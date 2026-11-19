package com.aethervpn.vpncore.softether

import com.aethervpn.vpncore.transport.SniBypassSocketFactory
import com.aethervpn.vpncore.transport.SniStrategy
import com.aethervpn.vpncore.transport.SocketProtector
import com.aethervpn.vpncore.transport.SstpTransport
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * An individual TCP/TLS channel to a SoftEther VPN Server.
 * Supports primary session negotiation (login), secondary channel joining (additional_connect),
 * and zero-allocation multi-frame TX batching for high throughput over high-RTT cellular/Wi-Fi links.
 */
class SoftEtherChannel(
    val channelId: Int,
    val host: String,
    val ipAddress: String,
    val port: Int,
    val isPrimary: Boolean,
    val sniStrategy: SniStrategy,
    val customSni: String?,
    val strictCert: Boolean,
    val socketProtector: SocketProtector?,
    val connectTimeoutMs: Int = 10000,
    val decoySeed: Int = channelId
) {
    companion object {
        private const val TX_RING_CAPACITY = 64
        private const val TX_SLOT_SIZE = 2048
        private const val MAX_BATCH_FRAMES = 16
        private const val MAX_BATCH_BYTES = 49152
        private const val HIGH_WATER_QUEUE = 48

        private val BROWSER_USER_AGENTS = arrayOf(
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"
        )

        /**
         * Encodes a batch of raw Ethernet frames into a SoftEther multi-frame binary block:
         * [int32 numFrames][int32 len0][frame0]...[int32 lenN-1][frameN-1]
         * Exposed internally for unit testing and reuse.
         */
        internal fun encodeMultiFrameBlock(
            txBuffer: ByteBuffer,
            frames: Array<ByteArray>,
            lengths: IntArray,
            indices: IntArray,
            count: Int
        ): Int {
            txBuffer.clear()
            txBuffer.putInt(count)
            for (i in 0 until count) {
                val idx = indices[i]
                val len = lengths[idx]
                txBuffer.putInt(len)
                txBuffer.put(frames[idx], 0, len)
            }
            txBuffer.flip()
            return txBuffer.limit()
        }
    }

    private var transport: SstpTransport? = null
    private var input: InputStream? = null
    private var output: OutputStream? = null

    val isConnected = AtomicBoolean(false)
    val txBytes = AtomicLong(0)
    val rxBytes = AtomicLong(0)
    val lastRxMs = AtomicLong(System.currentTimeMillis())
    val lastTxMs = AtomicLong(System.currentTimeMillis())
    val ewmaWriteUs = AtomicLong(400L)
    @Volatile
    var connectedAtMs: Long = System.currentTimeMillis()
        private set

    private val writeLock = Any()
    private val txBuffer = ByteBuffer.allocate(65536).apply { order(ByteOrder.BIG_ENDIAN) }
    private val rxFrameBuf = ByteArray(65536)

    // Lock-guarded pre-allocated TX ring buffer for zero-delay batching
    private val ringLock = Any()
    private val ringFrames = Array(TX_RING_CAPACITY) { ByteArray(TX_SLOT_SIZE) }
    private val ringLengths = IntArray(TX_RING_CAPACITY)
    private var ringHead = 0
    private var ringTail = 0
    private val ringCount = AtomicInteger(0)
    private val txSignal = Semaphore(0)
    private val writerStarted = AtomicBoolean(false)
    private var writerJob: Job? = null
    private val batchIndices = IntArray(MAX_BATCH_FRAMES)

    fun queueDepth(): Int = ringCount.get()

    fun isCongested(): Boolean = ringCount.get() >= HIGH_WATER_QUEUE || ewmaWriteUs.get() > 80_000L

    fun isHealthy(nowMs: Long = System.currentTimeMillis()): Boolean {
        if (!isConnected.get()) return false
        if (ewmaWriteUs.get() > 250_000L) return false
        // SoftEther servers commonly deliver all downlink RX on channel 0 while secondary channels carry TX.
        // Only check RX freshness on channels that actually received downlink traffic (or primary channel).
        if (isPrimary && rxBytes.get() > 0L) {
            return (nowMs - lastRxMs.get()) < 35_000L
        }
        return true
    }

    suspend fun connectAndHandshake(
        username: String,
        password: String,
        hubName: String,
        targetConnections: Int,
        existingSessionKey: ByteArray? = null
    ): SoftEtherSessionInfo = withContext(Dispatchers.IO) {
        val socketFactory = SniBypassSocketFactory(
            strategy = sniStrategy,
            customSni = customSni,
            strictCert = strictCert,
            socketProtector = socketProtector,
            decoySeed = decoySeed
        )

        val inetAddr = try {
            java.net.InetAddress.getByName(ipAddress)
        } catch (_: Exception) {
            java.net.InetAddress.getByName(host)
        }

        val t = socketFactory.createAndConnectTransport(
            host = host,
            ipAddress = inetAddr,
            port = port,
            timeoutMs = connectTimeoutMs
        )
        transport = t
        input = BufferedInputStream(t.inputStream, 524288) // 512 KB buffer for high-throughput streaming
        output = t.outputStream

        val inStream = input ?: throw IllegalStateException("Input stream unavailable")
        val outStream = output ?: throw IllegalStateException("Output stream unavailable")

        // 1. Send VPNCONNECT Handshake Signature
        val targetHost = customSni?.takeIf { it.isNotBlank() } ?: ipAddress.ifBlank { host }
        val watermarkHttp = buildHttpPost(
            target = SoftEtherConstants.HTTP_CONNECT_TARGET,
            host = targetHost,
            body = SoftEtherConstants.VPNCONNECT_BODY,
            contentType = "image/jpeg"
        )
        outStream.write(watermarkHttp)
        outStream.flush()

        val helloResponse = readHttpResponse(inStream)
        if (helloResponse.statusCode != 200) {
            throw IllegalStateException("SoftEther connect.cgi returned HTTP ${helloResponse.statusCode}")
        }
        val helloPack = SoftEtherPack.decode(helloResponse.body)

        val serverChallenge = helloPack.bytesProperties[SoftEtherConstants.SEP_RANDOM]
            ?: ByteArray(20) { it.toByte() }

        if (isPrimary) {
            // Primary Channel: Perform Login
            val loginPack = SoftEtherPack().apply {
                intProperties[SoftEtherConstants.SEP_BUILD] = SoftEtherConstants.COMPATIBLE_BUILD
                intProperties[SoftEtherConstants.SEP_VERSION] = SoftEtherConstants.COMPATIBLE_VERSION
                intProperties[SoftEtherConstants.SEP_CLIENT_BUILD] = SoftEtherConstants.COMPATIBLE_BUILD
                intProperties[SoftEtherConstants.SEP_CLIENT_VER] = SoftEtherConstants.COMPATIBLE_VERSION
                intProperties[SoftEtherConstants.SEP_CLIENT_ID] = 0
                intProperties[SoftEtherConstants.SEP_PROTOCOL] = 0
                intProperties[SoftEtherConstants.SEP_AUTH_TYPE] = 1 // Password Auth
                intProperties[SoftEtherConstants.SEP_MAX_CONNECTION] = targetConnections
                intProperties[SoftEtherConstants.SEP_HALF_CONNECTION] = 0

                stringProperties[SoftEtherConstants.SEP_CLIENT_STR] = "RadinVPN"
                stringProperties[SoftEtherConstants.SEP_CLIENT_OS_NAME] = "Android"
                stringProperties[SoftEtherConstants.SEP_METHOD] = SoftEtherConstants.METHOD_LOGIN
                stringProperties[SoftEtherConstants.SEP_USERNAME] = username
                stringProperties[SoftEtherConstants.SEP_HUB_NAME] = hubName

                booleanProperties[SoftEtherConstants.SEP_USE_ENCRYPT] = true
                booleanProperties[SoftEtherConstants.SEP_USE_COMPRESS] = false

                bytesProperties[SoftEtherConstants.SEP_UNIQUE_ID_CAMEL] = ByteArray(16).apply { SecureRandom().nextBytes(this) }
                bytesProperties[SoftEtherConstants.SEP_SECURE_PASSWORD] =
                    SoftEtherCrypto.calcSecurePassword(password, username, serverChallenge)
            }

            val loginBytes = loginPack.encode()
            val loginHttp = buildHttpPost(SoftEtherConstants.HTTP_VPN_TARGET, targetHost, loginBytes, "application/octet-stream")
            outStream.write(loginHttp)
            outStream.flush()

            val welcomeResponse = readHttpResponse(inStream)
            if (welcomeResponse.statusCode != 200) {
                throw IllegalStateException("SoftEther login returned HTTP ${welcomeResponse.statusCode}")
            }
            val welcomePack = SoftEtherPack.decode(welcomeResponse.body)

            val err = welcomePack.intProperties[SoftEtherConstants.SEP_ERROR]
            if (err != null && err != 0) {
                throw IllegalStateException("SoftEther login failed with server error code $err")
            }

            val sessionKey = welcomePack.bytesProperties[SoftEtherConstants.SEP_SESSION_KEY]
                ?: ByteArray(20).apply { SecureRandom().nextBytes(this) }
            val serverMaxConn = welcomePack.intProperties[SoftEtherConstants.SEP_MAX_CONNECTION] ?: targetConnections

            try { t.setSoTimeout(0) } catch (_: Exception) {}
            try { t.setTcpNoDelay(true) } catch (_: Exception) {}
            val now = System.currentTimeMillis()
            connectedAtMs = now
            lastRxMs.set(now)
            lastTxMs.set(now)
            isConnected.set(true)
            SoftEtherSessionInfo(sessionKey = sessionKey, maxConnections = serverMaxConn)
        } else {
            // Secondary Channel: Join existing session with additional_connect
            val sessionKey = existingSessionKey ?: throw IllegalArgumentException("Session key required for secondary channel")

            val addPack = SoftEtherPack().apply {
                stringProperties[SoftEtherConstants.SEP_METHOD] = SoftEtherConstants.METHOD_ADDITIONAL_CONNECT
                bytesProperties[SoftEtherConstants.SEP_SESSION_KEY] = sessionKey
                intProperties[SoftEtherConstants.SEP_BUILD] = SoftEtherConstants.COMPATIBLE_BUILD
                intProperties[SoftEtherConstants.SEP_VERSION] = SoftEtherConstants.COMPATIBLE_VERSION
            }

            val addBytes = addPack.encode()
            val addHttp = buildHttpPost(SoftEtherConstants.HTTP_VPN_TARGET, targetHost, addBytes, "application/octet-stream")
            outStream.write(addHttp)
            outStream.flush()

            val addResponse = readHttpResponse(inStream)
            if (addResponse.statusCode != 200) {
                throw IllegalStateException("SoftEther additional_connect returned HTTP ${addResponse.statusCode}")
            }

            try { t.setSoTimeout(0) } catch (_: Exception) {}
            try { t.setTcpNoDelay(true) } catch (_: Exception) {}
            val now = System.currentTimeMillis()
            connectedAtMs = now
            lastRxMs.set(now)
            lastTxMs.set(now)
            isConnected.set(true)
            SoftEtherSessionInfo(sessionKey = sessionKey, maxConnections = targetConnections)
        }
    }

    /**
     * Starts the dedicated non-blocking batch writer loop for this channel.
     * Drains queued frames from the pre-allocated ring buffer and writes up to 16 frames per flush.
     */
    fun startWriter(scope: CoroutineScope) {
        if (!writerStarted.compareAndSet(false, true)) return
        writerJob = scope.launch(Dispatchers.IO) {
            try {
                while (isActive && isConnected.get()) {
                    txSignal.acquire()
                    // Coalesce additional permits if burst arrived simultaneously
                    txSignal.drainPermits()
                    if (!isConnected.get()) break
                    drainAndFlushRing()
                }
            } catch (_: InterruptedException) {
            } catch (_: CancellationException) {
            } catch (e: Exception) {
                android.util.Log.e("SoftEtherChannel", "Channel $channelId writer failed: ${e.message}", e)
                close()
            }
        }
    }

    /**
     * Enqueues an IPv4 packet as an Ethernet frame into this channel's pre-allocated TX ring buffer.
     * Returns false immediately (non-blocking) if the ring is full or channel is disconnected,
     * allowing the caller to immediately spill over to another healthy TCP channel.
     */
    fun enqueueIpPacket(
        srcMac: ByteArray,
        dstMac: ByteArray,
        ipPacket: ByteArray,
        offset: Int,
        length: Int
    ): Boolean {
        if (!isConnected.get() || length <= 0 || 14 + length > TX_SLOT_SIZE) return false
        if (!writerStarted.get()) {
            return sendIpPacketAsFrame(srcMac, dstMac, ipPacket, offset, length)
        }
        val enqueued = synchronized(ringLock) {
            if (ringCount.get() >= TX_RING_CAPACITY) {
                false
            } else {
                val slotIdx = ringTail
                val buf = ringFrames[slotIdx]
                System.arraycopy(dstMac, 0, buf, 0, 6)
                System.arraycopy(srcMac, 0, buf, 6, 6)
                buf[12] = 0x08.toByte()
                buf[13] = 0x00.toByte()
                System.arraycopy(ipPacket, offset, buf, 14, length)
                ringLengths[slotIdx] = 14 + length
                ringTail = (slotIdx + 1) % TX_RING_CAPACITY
                ringCount.incrementAndGet()
                true
            }
        }
        if (enqueued) {
            txSignal.release()
        }
        return enqueued
    }

    private fun drainAndFlushRing() {
        val out = output ?: return
        while (isConnected.get()) {
            var count = 0
            var totalBatchBytes = 0
            synchronized(ringLock) {
                while (count < MAX_BATCH_FRAMES && ringCount.get() > 0) {
                    val idx = ringHead
                    val frameLen = ringLengths[idx]
                    if (count > 0 && totalBatchBytes + 4 + frameLen > MAX_BATCH_BYTES) {
                        break
                    }
                    batchIndices[count++] = idx
                    totalBatchBytes += 4 + frameLen
                    ringHead = (idx + 1) % TX_RING_CAPACITY
                    ringCount.decrementAndGet()
                }
            }
            if (count == 0) return

            synchronized(writeLock) {
                val startNs = System.nanoTime()
                try {
                    val limit = encodeMultiFrameBlock(txBuffer, ringFrames, ringLengths, batchIndices, count)
                    out.write(txBuffer.array(), 0, limit)
                    out.flush()
                    val elapsedUs = ((System.nanoTime() - startNs) / 1000L).coerceAtLeast(1L)
                    val prevEwma = ewmaWriteUs.get()
                    ewmaWriteUs.set((prevEwma * 7L + elapsedUs) / 8L)
                    lastTxMs.set(System.currentTimeMillis())
                    txBytes.addAndGet(limit.toLong())
                } catch (e: Exception) {
                    android.util.Log.e("SoftEtherChannel", "Channel $channelId batch write failed: ${e.message}", e)
                    isConnected.set(false)
                    close()
                    return
                }
            }
        }
    }

    /**
     * Transmit an IPv4 packet as an Ethernet frame directly into the tx buffer with zero allocations.
     * Encapsulates dstMac, srcMac, EtherType (0x0800), and payload in one contiguous write.
     */
    fun sendIpPacketAsFrame(
        srcMac: ByteArray,
        dstMac: ByteArray,
        ipPacket: ByteArray,
        offset: Int,
        length: Int
    ): Boolean {
        val out = output ?: return false
        if (!isConnected.get()) return false

        val frameLen = 14 + length
        return synchronized(writeLock) {
            val startNs = System.nanoTime()
            try {
                txBuffer.clear()
                txBuffer.putInt(1) // 1 frame
                txBuffer.putInt(frameLen)
                // Ethernet Header (14 bytes)
                txBuffer.put(dstMac, 0, 6)
                txBuffer.put(srcMac, 0, 6)
                txBuffer.put(0x08.toByte())
                txBuffer.put(0x00.toByte())
                // IP Payload
                txBuffer.put(ipPacket, offset, length)
                txBuffer.flip()

                out.write(txBuffer.array(), 0, txBuffer.limit())
                out.flush()
                val elapsedUs = ((System.nanoTime() - startNs) / 1000L).coerceAtLeast(1L)
                val prevEwma = ewmaWriteUs.get()
                ewmaWriteUs.set((prevEwma * 7L + elapsedUs) / 8L)
                lastTxMs.set(System.currentTimeMillis())
                txBytes.addAndGet(txBuffer.limit().toLong())
                true
            } catch (e: Exception) {
                android.util.Log.e("SoftEtherChannel", "Channel $channelId sendIpPacketAsFrame failed: ${e.message}", e)
                isConnected.set(false)
                close()
                false
            }
        }
    }

    /**
     * Transmit a single raw Ethernet frame over this channel (e.g. ARP or DHCP).
     * Returns true if frame was successfully written, or false if channel write failed / disconnected.
     */
    fun sendEthernetFrame(frame: ByteArray, offset: Int = 0, length: Int = frame.size): Boolean {
        val out = output ?: return false
        if (!isConnected.get()) return false

        return synchronized(writeLock) {
            try {
                txBuffer.clear()
                txBuffer.putInt(1) // 1 frame
                txBuffer.putInt(length)
                txBuffer.put(frame, offset, length)
                txBuffer.flip()

                out.write(txBuffer.array(), 0, txBuffer.limit())
                out.flush()
                lastTxMs.set(System.currentTimeMillis())
                txBytes.addAndGet(txBuffer.limit().toLong())
                true
            } catch (e: Exception) {
                android.util.Log.e("SoftEtherChannel", "Channel $channelId sendEthernetFrame failed: ${e.message}", e)
                isConnected.set(false)
                close()
                false
            }
        }
    }

    /**
     * Send Cedar keepalive probe (block count = 0).
     */
    fun sendKeepalive() {
        val out = output ?: return
        if (!isConnected.get()) return
        synchronized(writeLock) {
            try {
                txBuffer.clear()
                txBuffer.putInt(0)
                txBuffer.flip()
                out.write(txBuffer.array(), 0, txBuffer.limit())
                out.flush()
                lastTxMs.set(System.currentTimeMillis())
            } catch (e: Exception) {
                android.util.Log.e("SoftEtherChannel", "Channel $channelId sendKeepalive failed: ${e.message}", e)
                isConnected.set(false)
                close()
            }
        }
    }

    /**
     * Read loop that continuously reads Ethernet frames from the server into reusable buffer
     * and delivers them with zero allocations.
     */
    suspend fun readLoop(onFrameReceived: (buffer: ByteArray, offset: Int, length: Int) -> Unit) = withContext(Dispatchers.IO) {
        val inStream = input ?: return@withContext
        val headerBuf = ByteArray(4)

        try {
            while (isActive && isConnected.get()) {
                // Read 4 bytes: number of frames in block
                val numFramesOk = try {
                    readFully(inStream, headerBuf, 0, 4)
                } catch (_: java.net.SocketTimeoutException) {
                    continue
                }
                if (!numFramesOk) {
                    android.util.Log.w("SoftEtherChannel", "Channel $channelId readLoop EOF on numFrames")
                    break
                }
                lastRxMs.set(System.currentTimeMillis())
                val numFrames = (((headerBuf[0].toInt() and 0xFF) shl 24) or
                        ((headerBuf[1].toInt() and 0xFF) shl 16) or
                        ((headerBuf[2].toInt() and 0xFF) shl 8) or
                        (headerBuf[3].toInt() and 0xFF))

                if (numFrames <= 0 || numFrames > 256) {
                    // Invalid or keepalive probe
                    continue
                }

                for (i in 0 until numFrames) {
                    val frameLenOk = try {
                        readFully(inStream, headerBuf, 0, 4)
                    } catch (_: java.net.SocketTimeoutException) {
                        continue
                    }
                    if (!frameLenOk) {
                        android.util.Log.w("SoftEtherChannel", "Channel $channelId readLoop EOF on frameLen")
                        break
                    }
                    val frameLen = (((headerBuf[0].toInt() and 0xFF) shl 24) or
                            ((headerBuf[1].toInt() and 0xFF) shl 16) or
                            ((headerBuf[2].toInt() and 0xFF) shl 8) or
                            (headerBuf[3].toInt() and 0xFF))

                    if (frameLen in 14..65535) {
                        val frameReadOk = try {
                            readFully(inStream, rxFrameBuf, 0, frameLen)
                        } catch (_: java.net.SocketTimeoutException) {
                            continue
                        }
                        if (frameReadOk) {
                            rxBytes.addAndGet(frameLen.toLong())
                            lastRxMs.set(System.currentTimeMillis())
                            onFrameReceived(rxFrameBuf, 0, frameLen)
                        } else {
                            android.util.Log.w("SoftEtherChannel", "Channel $channelId readLoop EOF on frameData len=$frameLen")
                            break
                        }
                    }
                }
            }
        } catch (_: java.net.SocketTimeoutException) {
            // Socket timeout during idle - normal
        } catch (e: CancellationException) {
            // Normal shutdown
        } catch (e: Exception) {
            android.util.Log.e("SoftEtherChannel", "Channel $channelId readLoop exception: ${e.message}", e)
        } finally {
            close()
        }
    }

    private fun readFully(inStream: InputStream, target: ByteArray, offset: Int, length: Int): Boolean {
        var total = 0
        while (total < length) {
            val r = inStream.read(target, offset + total, length - total)
            if (r == -1) return false
            total += r
        }
        return true
    }

    private fun buildHttpPost(target: String, host: String, body: ByteArray, contentType: String): ByteArray {
        val ua = BROWSER_USER_AGENTS[(decoySeed.coerceAtLeast(0)) % BROWSER_USER_AGENTS.size]
        val headers = "POST $target HTTP/1.1\r\n" +
                "Host: $host\r\n" +
                "User-Agent: $ua\r\n" +
                "Accept: */*\r\n" +
                "Cache-Control: no-cache\r\n" +
                "Content-Type: $contentType\r\n" +
                "Content-Length: ${body.size}\r\n" +
                "Connection: Keep-Alive\r\n" +
                "Keep-Alive: ${SoftEtherConstants.HTTP_KEEP_ALIVE}\r\n\r\n"
        val headerBytes = headers.toByteArray(Charsets.US_ASCII)
        val full = ByteArray(headerBytes.size + body.size)
        System.arraycopy(headerBytes, 0, full, 0, headerBytes.size)
        System.arraycopy(body, 0, full, headerBytes.size, body.size)
        return full
    }

    private fun readHttpResponse(inStream: InputStream): HttpResponse {
        val headerBytes = mutableListOf<Byte>()

        while (true) {
            val b = inStream.read()
            if (b == -1) throw IllegalStateException("Unexpected EOF while reading HTTP header")
            headerBytes.add(b.toByte())
            val size = headerBytes.size
            if (size >= 4 &&
                headerBytes[size - 4] == '\r'.code.toByte() &&
                headerBytes[size - 3] == '\n'.code.toByte() &&
                headerBytes[size - 2] == '\r'.code.toByte() &&
                headerBytes[size - 1] == '\n'.code.toByte()
            ) {
                break
            }
        }

        val headerStr = String(headerBytes.toByteArray(), Charsets.US_ASCII)
        val lines = headerStr.split("\r\n")
        val statusLine = lines.firstOrNull().orEmpty()
        val statusCode = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 200

        var contentLength = 0
        for (line in lines) {
            if (line.startsWith("Content-Length:", ignoreCase = true)) {
                contentLength = line.substringAfter(":").trim().toIntOrNull() ?: 0
            }
        }

        val body = ByteArray(contentLength)
        if (contentLength > 0) {
            readFully(inStream, body, 0, contentLength)
        }

        return HttpResponse(statusCode, body)
    }

    fun close() {
        isConnected.set(false)
        txSignal.release()
        writerJob?.cancel()
        writerJob = null
        try { transport?.close() } catch (_: Exception) {}
        transport = null
        input = null
        output = null
    }

    private data class HttpResponse(val statusCode: Int, val body: ByteArray)
}

data class SoftEtherSessionInfo(
    val sessionKey: ByteArray,
    val maxConnections: Int
)
