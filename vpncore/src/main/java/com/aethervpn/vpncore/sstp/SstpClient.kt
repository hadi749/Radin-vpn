package com.aethervpn.vpncore.sstp

import com.aethervpn.vpncore.crypto.CryptoBinding
import com.aethervpn.vpncore.crypto.MsChapV2
import com.aethervpn.vpncore.ppp.ChapPacket
import com.aethervpn.vpncore.ppp.IpcpOption
import com.aethervpn.vpncore.ppp.IpcpPacket
import com.aethervpn.vpncore.ppp.LcpOption
import com.aethervpn.vpncore.ppp.LcpPacket
import com.aethervpn.vpncore.ppp.PppFrame
import com.aethervpn.vpncore.transport.SniBypassSocketFactory
import com.aethervpn.vpncore.transport.SniStrategy
import com.aethervpn.vpncore.transport.SocketProtector
import com.aethervpn.vpncore.transport.SstpTransport
import com.aethervpn.vpncore.transport.TunnelClient
import com.aethervpn.vpncore.tun.TunnelPackets
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

data class SstpConfig(
    val host: String,
    val ipAddress: InetAddress,
    val port: Int = 443,
    val username: String = "vpn",
    val password: String = "vpn",
    val mtu: Int = 1400,
    val keepaliveIntervalSec: Int = 20,
    val strictCert: Boolean = false,
    val sniStrategy: SniStrategy = SniStrategy.DIRECT_IP_NO_SNI,
    val customSni: String? = null,
    val connectTimeoutMs: Int = 10000
)

data class VpnParameters(
    val clientIp: String,
    val gatewayIp: String,
    val primaryDns: String,
    val secondaryDns: String,
    val mtu: Int
)

data class SstpTrafficSnapshot(
    val txPackets: Long,
    val rxUnicastPackets: Long,
    val lastAnyRxMs: Long,
    val lastUnicastIpRxMs: Long
)

interface SstpEventListener {
    fun onStateChanged(state: SstpState, message: String? = null)
    fun onParametersEstablished(params: VpnParameters)
    fun onDataPacketReceived(packet: ByteArray) {}
    fun onDataPacketReceived(packet: ByteArray, offset: Int, length: Int) {
        onDataPacketReceived(if (offset == 0 && length == packet.size) packet else packet.copyOfRange(offset, offset + length))
    }
    fun onBytesTransferred(txBytesDelta: Long, rxBytesDelta: Long)
    fun onError(t: Throwable)
    fun onLog(message: String) {}
}

enum class SstpState {
    DISCONNECTED,
    CONNECTING_TCP,
    TLS_HANDSHAKE,
    HTTP_HANDSHAKE,
    SSTP_CONNECTING,
    PPP_LCP,
    PPP_AUTH,
    PPP_IPCP,
    CONNECTED,
    DISCONNECTING
}

class SstpClient(
    private val config: SstpConfig,
    private val socketProtector: SocketProtector?,
    private val listener: SstpEventListener
) : TunnelClient {
    private val isRunning = AtomicBoolean(false)
    private var transport: SstpTransport? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null

    private var serverCert: X509Certificate? = null
    private var serverNonce: ByteArray? = null
    private var masterKey: ByteArray? = null
    private var hlak: ByteArray? = null
    private var useSha256Binding: Boolean = true

    private var clientIp = "10.0.0.2"
    private var gatewayIp = "10.0.0.1"
    private var primaryDns = "8.8.8.8"
    private var secondaryDns = "8.8.4.4"

    private val txFastHeader = ByteArray(8)
    private val txFastBuf = ByteArray(4096)
    private val rxHeaderBuf = ByteArray(4)
    private val rxFastPacketBuf = ByteArray(65536)

    // Pre-allocated TX coalescing ring buffer for batching burst packets into fewer TLS records
    private val txRingCapacity = 64
    private val txRingLock = Any()
    private val txRingPackets = Array(txRingCapacity) { ByteArray(4096) }
    private val txRingLengths = IntArray(txRingCapacity)
    private var txRingHead = 0
    private var txRingTail = 0
    private val txRingCount = AtomicInteger(0)
    private val txSignal = Semaphore(0)
    private val txBatchBuf = ByteArray(49152)
    private var txWriterJob: Job? = null

    private val txBytes = AtomicLong(0)
    private val rxBytes = AtomicLong(0)
    private val txPackets = AtomicLong(0)
    private val rxPackets = AtomicLong(0)
    private val rxUnicastPackets = AtomicLong(0)
    private val rxBroadcastDropped = AtomicLong(0)
    private val lastAnyRxMs = AtomicLong(0)
    private val lastAnyTxMs = AtomicLong(0)
    private val lastUnicastIpRxMs = AtomicLong(0)
    @Volatile
    private var probeInterceptor: ((ByteArray) -> Boolean)? = null
    @Volatile
    private var packetProbeInterceptor: ((ByteArray, Int, Int) -> Boolean)? = null

    private var echoJob: Job? = null

    override fun setProbeInterceptor(interceptor: ((ByteArray) -> Boolean)?) {
        probeInterceptor = interceptor
        if (interceptor == null) {
            packetProbeInterceptor = null
        } else {
            packetProbeInterceptor = { buf, off, len ->
                interceptor.invoke(buf.copyOfRange(off, off + len))
            }
        }
    }

    override fun setPacketProbeInterceptor(interceptor: ((ByteArray, Int, Int) -> Boolean)?) {
        packetProbeInterceptor = interceptor
        if (interceptor == null) {
            probeInterceptor = null
        }
    }

    override fun snapshotTraffic(): SstpTrafficSnapshot = SstpTrafficSnapshot(
        txPackets = txPackets.get(),
        rxUnicastPackets = rxUnicastPackets.get(),
        lastAnyRxMs = lastAnyRxMs.get(),
        lastUnicastIpRxMs = lastUnicastIpRxMs.get()
    )

    private fun logDebug(msg: String) {
        try {
            listener.onLog("SSTP: $msg")
        } catch (_: Exception) {}
    }

    suspend fun start(scope: CoroutineScope) = withContext(Dispatchers.IO) {
        if (!isRunning.compareAndSet(false, true)) return@withContext
        var wasConnected = false
        try {
            listener.onStateChanged(SstpState.CONNECTING_TCP, "Connecting to ${config.host}:${config.port}...")

            val socketFactory = SniBypassSocketFactory(
                strategy = config.sniStrategy,
                customSni = config.customSni,
                strictCert = config.strictCert,
                socketProtector = socketProtector,
                onCertificateCaptured = { cert ->
                    serverCert = cert
                },
                decoySeed = (System.nanoTime() and 0x7FFF).toInt()
            )

            listener.onStateChanged(SstpState.TLS_HANDSHAKE, "Performing TLS handshake...")
            val sstpTransport = socketFactory.createAndConnectTransport(
                host = config.host,
                ipAddress = config.ipAddress,
                port = config.port,
                timeoutMs = config.connectTimeoutMs
            )
            transport = sstpTransport
            val bis = BufferedInputStream(sstpTransport.inputStream, 524288) // 512 KB buffer for video streaming
            val nativeOs = sstpTransport.outputStream
            inputStream = bis
            outputStream = nativeOs

            // HTTP Handshake
            listener.onStateChanged(SstpState.HTTP_HANDSHAKE, "Sending SSTP HTTP duplex post...")
            performHttpHandshake(bis, nativeOs)

            // SSTP Call Connect Request
            listener.onStateChanged(SstpState.SSTP_CONNECTING, "Initiating SSTP connection...")
            sendSstpConnectRequest(nativeOs)

            // Read SSTP Call Connect Ack
            readSstpConnectAck(bis)

            // LCP Phase
            listener.onStateChanged(SstpState.PPP_LCP, "Negotiating PPP LCP...")
            negotiateLcp(bis, nativeOs)

            // Authentication Phase
            listener.onStateChanged(SstpState.PPP_AUTH, "Authenticating with MS-CHAPv2...")
            authenticateMsChap(bis, nativeOs)

            // SSTP Call Connected with Crypto Binding
            sendCallConnected(nativeOs)

            // IPCP Phase
            listener.onStateChanged(SstpState.PPP_IPCP, "Negotiating IPCP network settings...")
            negotiateIpcp(bis, nativeOs)

            val vpnParams = VpnParameters(
                clientIp = clientIp,
                gatewayIp = gatewayIp,
                primaryDns = primaryDns,
                secondaryDns = secondaryDns,
                mtu = config.mtu
            )
            listener.onParametersEstablished(vpnParams)
            listener.onStateChanged(SstpState.CONNECTED, "Connected ($clientIp)")
            wasConnected = true

            // Restore generous data-pump read timeout once handshake & PPP negotiation complete
            try {
                sstpTransport.setSoTimeout(maxOf(config.keepaliveIntervalSec * 3000, 30_000))
            } catch (_: Exception) {}

            // Start TX coalescing writer + Echo Keepalive job
            txWriterJob = scope.launch(Dispatchers.IO) {
                txBatchWriterLoop(nativeOs)
            }
            echoJob = scope.launch {
                keepaliveLoop(nativeOs)
            }

            // Enter Data Pump Loop
            dataPumpLoop(bis)

        } catch (e: Exception) {
            if (e !is CancellationException && isRunning.get()) {
                if (wasConnected) {
                    listener.onError(e)
                } else {
                    throw e
                }
            }
        } finally {
            close()
        }
    }

    private fun performHttpHandshake(input: InputStream, output: OutputStream) {
        val correlationId = UUID.randomUUID().toString().uppercase()
        val httpRequest = "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n" +
                "SSTPCORRELATIONID: {$correlationId}\r\n" +
                "Content-Length: 18446744073709551615\r\n" +
                "Host: ${config.host}\r\n" +
                "\r\n"

        val reqBytes = httpRequest.toByteArray(StandardCharsets.US_ASCII)
        output.write(reqBytes)
        output.flush()

        // Read HTTP response status line
        val responseLine = readLine(input)
        if (!responseLine.contains("200")) {
            throw IllegalStateException("SSTP HTTP handshake failed: $responseLine")
        }

        // Read remaining headers until blank line
        while (true) {
            val header = readLine(input)
            if (header.isEmpty()) break
        }
    }

    private fun readLine(input: InputStream): String {
        val sb = java.lang.StringBuilder()
        var prev = -1
        while (true) {
            val b = input.read()
            if (b == -1) throw IllegalStateException("EOF while reading HTTP response")
            if (b == '\n'.code && prev == '\r'.code) {
                return sb.substring(0, sb.length - 1)
            }
            sb.append(b.toChar())
            prev = b
        }
    }

    private fun sendSstpConnectRequest(output: OutputStream) {
        val req = SstpPacket.ControlPacket(
            messageType = SstpPacket.MSG_CALL_CONNECT_REQUEST,
            attributes = listOf(SstpAttribute.encapsulatedPpp())
        )
        val bytes = req.encode()
        output.write(bytes)
        output.flush()
    }

    private fun readSstpConnectAck(input: InputStream) {
        val packet = readNextSstpPacket(input)
        if (packet !is SstpPacket.ControlPacket || packet.messageType != SstpPacket.MSG_CALL_CONNECT_ACK) {
            throw IllegalStateException("Expected SSTP CALL_CONNECT_ACK, got $packet")
        }
        for (attr in packet.attributes) {
            if (attr.id == SstpAttribute.ATTRIB_CRYPTO_BINDING_REQ) {
                // Value layout: Reserved(3) + HashProtocolBitmask(1) + Nonce(32)
                if (attr.value.size >= 36) {
                    val hashMask = attr.value[3].toInt() and 0xFF
                    useSha256Binding = (hashMask and (CryptoBinding.CERT_HASH_PROTOCOL_SHA256.toInt() and 0xFF)) != 0 ||
                        (hashMask and (CryptoBinding.CERT_HASH_PROTOCOL_SHA1.toInt() and 0xFF)) == 0
                    val nonce = ByteArray(32)
                    System.arraycopy(attr.value, 4, nonce, 0, 32)
                    serverNonce = nonce
                    logDebug("CALL_CONNECT_ACK crypto binding req: hashMask=0x${hashMask.toString(16)} useSha256=$useSha256Binding")
                }
            }
        }
        if (serverNonce == null) {
            // Default 32-byte zeroes if not supplied
            serverNonce = ByteArray(32)
        }
    }

    private fun negotiateLcp(input: InputStream, output: OutputStream) {
        var activeOptions = listOf(LcpOption.mru(config.mtu))
        var nextReqId: Byte = 2
        val clientReq = LcpPacket(
            code = LcpPacket.CODE_CONFIGURE_REQUEST,
            identifier = 1,
            options = activeOptions
        )
        sendPacket(output, SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_LCP, clientReq.encode()).encode()).encode())
        logDebug("TX LCP Configure-Request id=1 mtu=${config.mtu}")

        var clientAcked = false
        var serverAcked = false

        while (!clientAcked || !serverAcked) {
            val pkt = readNextSstpPacket(input)
            if (pkt is SstpPacket.ControlPacket) {
                if (!handleControlPacket(pkt, output)) {
                    throw IllegalStateException("Server disconnected during LCP negotiation")
                }
                continue
            }
            if (pkt !is SstpPacket.DataPacket) continue
            val ppp = PppFrame.decode(pkt.payload)
            if (ppp.protocol != PppFrame.PROTO_LCP) continue
            val lcp = LcpPacket.decode(ppp.payload)
            logDebug("RX LCP(neg) code=${lcp.code} id=${lcp.identifier} opts=${lcp.options.size}")

            when (lcp.code) {
                LcpPacket.CODE_CONFIGURE_REQUEST -> {
                    val authOpt = lcp.options.firstOrNull { it.type == LcpOption.OPTION_AUTH_PROTOCOL }
                    if (authOpt != null && authOpt.value.size >= 2 && (authOpt.value[0].toInt() and 0xFF) == 0xC0 && (authOpt.value[1].toInt() and 0xFF) == 0x23) {
                        // NAK with MS-CHAPv2 so server uses MS-CHAPv2 required for SSTP Crypto Binding
                        val nak = LcpPacket(LcpPacket.CODE_CONFIGURE_NAK, lcp.identifier, listOf(LcpOption.authMsChapV2()))
                        sendPacket(output, SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_LCP, nak.encode()).encode()).encode())
                        logDebug("TX LCP Configure-Nak PAP->MS-CHAPv2 id=${lcp.identifier}")
                    } else {
                        val ack = LcpPacket(LcpPacket.CODE_CONFIGURE_ACK, lcp.identifier, lcp.options)
                        sendPacket(output, SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_LCP, ack.encode()).encode()).encode())
                        serverAcked = true
                    }
                }
                LcpPacket.CODE_CONFIGURE_ACK -> {
                    clientAcked = true
                }
                LcpPacket.CODE_CONFIGURE_NAK -> {
                    val byType = lcp.options.associateBy { it.type }
                    activeOptions = activeOptions.map { byType[it.type] ?: it }
                    val reqId = nextReqId++
                    val resend = LcpPacket(LcpPacket.CODE_CONFIGURE_REQUEST, reqId, activeOptions)
                    sendPacket(output, SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_LCP, resend.encode()).encode()).encode())
                }
                LcpPacket.CODE_CONFIGURE_REJECT -> {
                    val rejectedTypes = lcp.options.map { it.type }.toSet()
                    activeOptions = activeOptions.filter { it.type !in rejectedTypes }
                    val reqId = nextReqId++
                    val resend = LcpPacket(LcpPacket.CODE_CONFIGURE_REQUEST, reqId, activeOptions)
                    sendPacket(output, SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_LCP, resend.encode()).encode()).encode())
                }
                LcpPacket.CODE_ECHO_REQUEST -> {
                    sendLcpEchoReply(output, lcp)
                }
                LcpPacket.CODE_TERMINATE_REQUEST -> {
                    val ack = LcpPacket(LcpPacket.CODE_TERMINATE_ACK, lcp.identifier, rawData = lcp.rawData)
                    sendPacket(output, SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_LCP, ack.encode()).encode()).encode())
                    throw IllegalStateException("LCP terminated by server during LCP negotiation")
                }
            }
        }
    }

    private fun authenticateMsChap(input: InputStream, output: OutputStream) {
        var lastChapId: Byte? = null
        var lastChapRespBytes: ByteArray? = null

        while (true) {
            val pkt = readNextSstpPacket(input)
            if (pkt is SstpPacket.ControlPacket) {
                if (!handleControlPacket(pkt, output)) {
                    throw IllegalStateException("Server disconnected during MS-CHAPv2 authentication")
                }
                continue
            }
            if (pkt !is SstpPacket.DataPacket) continue
            val ppp = PppFrame.decode(pkt.payload)
            if (ppp.protocol == PppFrame.PROTO_LCP) {
                val lcp = LcpPacket.decode(ppp.payload)
                when (lcp.code) {
                    LcpPacket.CODE_ECHO_REQUEST -> sendLcpEchoReply(output, lcp)
                    LcpPacket.CODE_TERMINATE_REQUEST -> {
                        val ack = LcpPacket(LcpPacket.CODE_TERMINATE_ACK, lcp.identifier, rawData = lcp.rawData)
                        sendPacket(output, SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_LCP, ack.encode()).encode()).encode())
                        throw IllegalStateException("LCP terminated by server during MS-CHAPv2 authentication")
                    }
                }
                continue
            }
            if (ppp.protocol != PppFrame.PROTO_CHAP) continue

            val chap = ChapPacket.decode(ppp.payload)
            logDebug("RX CHAP code=${chap.code} id=${chap.identifier} len=${chap.data.size}")
            if (chap.code == ChapPacket.CODE_CHALLENGE) {
                if (lastChapId == chap.identifier && lastChapRespBytes != null) {
                    logDebug("Duplicate CHAP challenge id=${chap.identifier}, resending cached response")
                    sendPacket(output, lastChapRespBytes!!)
                    continue
                }
                if (chap.data.isEmpty()) throw IllegalStateException("Empty MS-CHAPv2 challenge")
                val valSize = chap.data[0].toInt() and 0xFF
                if (chap.data.size < 1 + valSize) {
                    throw IllegalStateException("Malformed MS-CHAPv2 challenge length: $valSize > ${chap.data.size - 1}")
                }
                val authChallenge = ByteArray(valSize)
                System.arraycopy(chap.data, 1, authChallenge, 0, valSize)

                val peerChallenge = MsChapV2.generatePeerChallenge()
                val ntResponse = MsChapV2.generateNtResponse(
                    authChallenge = authChallenge,
                    peerChallenge = peerChallenge,
                    userName = config.username,
                    password = config.password
                )

                // Derive keys for crypto binding (HLAK = ClientSendKey[16] || ClientRecvKey[16])
                val pwhash = MsChapV2.ntPasswordHash(config.password)
                val pwhashhash = MsChapV2.hashNtPasswordHash(pwhash)
                val mk = MsChapV2.getMasterKey(pwhashhash, ntResponse)
                masterKey = mk
                val clientSendKey = MsChapV2.getAsymmetricKey(mk, isSend = true)
                val clientRecvKey = MsChapV2.getAsymmetricKey(mk, isSend = false)
                hlak = ByteArray(32).also {
                    System.arraycopy(clientSendKey, 0, it, 0, 16)
                    System.arraycopy(clientRecvKey, 0, it, 16, 16)
                }

                val chapResp = ChapPacket.buildMsChapV2Response(
                    id = chap.identifier,
                    peerChallenge = peerChallenge,
                    ntResponse = ntResponse,
                    userName = config.username
                )
                val encodedResp = SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_CHAP, chapResp.encode()).encode()).encode()
                lastChapId = chap.identifier
                lastChapRespBytes = encodedResp
                sendPacket(output, encodedResp)
                logDebug("TX CHAP Response id=${chap.identifier}")
            } else if (chap.code == ChapPacket.CODE_SUCCESS) {
                logDebug("MS-CHAPv2 authentication succeeded")
                break
            } else if (chap.code == ChapPacket.CODE_FAILURE) {
                val msg = String(chap.data, StandardCharsets.US_ASCII)
                throw IllegalStateException("MS-CHAPv2 authentication rejected: $msg")
            }
        }
    }

    private fun sendCallConnected(output: OutputStream) {
        val cert = serverCert
        val sha256 = if (cert != null) CryptoBinding.computeCertHashSha256(cert.encoded) else ByteArray(32)
        val sha1 = if (cert != null) CryptoBinding.computeCertHashSha1(cert.encoded) else ByteArray(20)

        val cryptoBindingAttr = CryptoBinding.buildCryptoBindingAttribute(
            nonce = serverNonce ?: ByteArray(32),
            serverCertSha256 = sha256,
            serverCertSha1 = sha1,
            useSha256 = useSha256Binding
        )

        val callConnected = SstpPacket.ControlPacket(
            messageType = SstpPacket.MSG_CALL_CONNECTED,
            attributes = listOf(SstpAttribute(CryptoBinding.SSTP_ATTRIB_CRYPTO_BINDING, cryptoBindingAttr.copyOfRange(4, cryptoBindingAttr.size)))
        )
        val encoded = callConnected.encode()

        // CMAC sits after 8B SSTP header + 4B attr header + 4B(reserved+hashProto) + 32B nonce + 32B certHash = 80
        val cmKey = CryptoBinding.deriveCompoundMacKey(hlak ?: ByteArray(32), useSha256 = useSha256Binding)
        val cmacOffset = 8 + 4 + 4 + 32 + 32
        if (encoded.size >= cmacOffset + 32) {
            CryptoBinding.computeAndInsertCompoundMac(encoded, cmKey, cmacOffset, useSha256 = useSha256Binding)
        }
        val certPrefix = sha256.take(4).joinToString("") { "%02x".format(it) }
        logDebug("Sending CALL_CONNECTED useSha256=$useSha256Binding hlakReady=${hlak != null} certSha256=$certPrefix.. len=${encoded.size}")

        output.write(encoded)
        output.flush()
    }

    private fun negotiateIpcp(input: InputStream, output: OutputStream) {
        var reqIp: ByteArray? = ByteArray(4)
        var reqDns1: ByteArray? = ByteArray(4)
        var reqDns2: ByteArray? = null
        var nextReqId: Byte = 2

        fun buildIpcpOptions(): List<IpcpOption> = buildList {
            reqIp?.let { add(IpcpOption.ipAddress(it)) }
            reqDns1?.let { add(IpcpOption.primaryDns(it)) }
            reqDns2?.let { add(IpcpOption.secondaryDns(it)) }
        }

        val initialReq = IpcpPacket(
            code = IpcpPacket.CODE_CONFIGURE_REQUEST,
            identifier = 1,
            options = buildIpcpOptions()
        )
        sendPacket(output, SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_IPCP, initialReq.encode()).encode()).encode())
        logDebug("TX IPCP Configure-Request id=1")

        var clientAcked = false
        var serverAcked = false

        while (!clientAcked || !serverAcked) {
            val pkt = readNextSstpPacket(input)
            if (pkt is SstpPacket.ControlPacket) {
                if (!handleControlPacket(pkt, output)) {
                    throw IllegalStateException("Server disconnected during IPCP negotiation")
                }
                continue
            }
            if (pkt !is SstpPacket.DataPacket) continue
            val ppp = PppFrame.decode(pkt.payload)
            when (ppp.protocol) {
                PppFrame.PROTO_LCP -> {
                    val lcp = LcpPacket.decode(ppp.payload)
                    logDebug("RX LCP(ipcp) code=${lcp.code} id=${lcp.identifier}")
                    when (lcp.code) {
                        LcpPacket.CODE_ECHO_REQUEST -> sendLcpEchoReply(output, lcp)
                        LcpPacket.CODE_TERMINATE_REQUEST -> {
                            val ack = LcpPacket(LcpPacket.CODE_TERMINATE_ACK, lcp.identifier, rawData = lcp.rawData)
                            sendPacket(output, SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_LCP, ack.encode()).encode()).encode())
                            throw IllegalStateException("LCP terminated by server during IPCP negotiation")
                        }
                    }
                    continue
                }
                PppFrame.PROTO_CHAP, PppFrame.PROTO_PAP, PppFrame.PROTO_IP -> {
                    // Ignore delayed retransmitted auth challenges or early IP packets without rejecting auth!
                    logDebug("Ignoring non-IPCP PPP proto=0x${ppp.protocol.toInt().and(0xFFFF).toString(16)} during IPCP")
                    continue
                }
                !in setOf(PppFrame.PROTO_IPCP) -> {
                    logDebug("Rejecting unsupported PPP proto=0x${ppp.protocol.toInt().and(0xFFFF).toString(16)} during IPCP")
                    sendLcpProtocolReject(output, ppp.protocol, ppp.payload)
                    continue
                }
            }

            val ipcp = IpcpPacket.decode(ppp.payload)
            logDebug("RX IPCP code=${ipcp.code} id=${ipcp.identifier} opts=${ipcp.options.size}")
            when (ipcp.code) {
                IpcpPacket.CODE_CONFIGURE_REQUEST -> {
                    for (opt in ipcp.options) {
                        if (opt.type == IpcpOption.OPTION_IP_ADDRESS && opt.value.size == 4) {
                            gatewayIp = InetAddress.getByAddress(opt.value).hostAddress ?: "10.0.0.1"
                        }
                    }
                    val ack = IpcpPacket(IpcpPacket.CODE_CONFIGURE_ACK, ipcp.identifier, ipcp.options)
                    sendPacket(output, SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_IPCP, ack.encode()).encode()).encode())
                    logDebug("TX IPCP Configure-Ack id=${ipcp.identifier} gateway=$gatewayIp")
                    serverAcked = true
                }
                IpcpPacket.CODE_CONFIGURE_NAK -> {
                    val nakTypes = ipcp.options.map { it.type }.toSet()
                    if (IpcpOption.OPTION_PRIMARY_DNS !in nakTypes) reqDns1 = null
                    if (IpcpOption.OPTION_SECONDARY_DNS !in nakTypes) reqDns2 = null
                    for (opt in ipcp.options) {
                        if (opt.value.size != 4) continue
                        val addr = InetAddress.getByAddress(opt.value).hostAddress ?: continue
                        when (opt.type) {
                            IpcpOption.OPTION_IP_ADDRESS -> {
                                clientIp = addr
                                reqIp = opt.value.clone()
                            }
                            IpcpOption.OPTION_PRIMARY_DNS -> {
                                primaryDns = addr
                                reqDns1 = opt.value.clone()
                            }
                            IpcpOption.OPTION_SECONDARY_DNS -> {
                                secondaryDns = addr
                                reqDns2 = opt.value.clone()
                            }
                        }
                    }
                    val reqId = nextReqId++
                    val resend = IpcpPacket(IpcpPacket.CODE_CONFIGURE_REQUEST, reqId, buildIpcpOptions())
                    sendPacket(output, SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_IPCP, resend.encode()).encode()).encode())
                    logDebug("TX IPCP Configure-Request id=$reqId (ip=$clientIp dns=$primaryDns)")
                }
                IpcpPacket.CODE_CONFIGURE_REJECT -> {
                    val rejectedTypes = ipcp.options.map { it.type }.toSet()
                    logDebug("RX IPCP Configure-Reject id=${ipcp.identifier} types=$rejectedTypes")
                    if (IpcpOption.OPTION_IP_ADDRESS in rejectedTypes) {
                        throw IllegalStateException("Server rejected IP address allocation (no DHCP/IP pool on host)")
                    }
                    if (IpcpOption.OPTION_PRIMARY_DNS in rejectedTypes) reqDns1 = null
                    if (IpcpOption.OPTION_SECONDARY_DNS in rejectedTypes) reqDns2 = null
                    val remaining = buildIpcpOptions()
                    if (remaining.isEmpty()) {
                        clientAcked = true
                    } else {
                        val reqId = nextReqId++
                        val resend = IpcpPacket(IpcpPacket.CODE_CONFIGURE_REQUEST, reqId, remaining)
                        sendPacket(output, SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_IPCP, resend.encode()).encode()).encode())
                        logDebug("TX IPCP Configure-Request id=$reqId after reject")
                    }
                }
                IpcpPacket.CODE_CONFIGURE_ACK -> {
                    for (opt in ipcp.options) {
                        if (opt.value.size != 4) continue
                        val addr = InetAddress.getByAddress(opt.value).hostAddress ?: continue
                        when (opt.type) {
                            IpcpOption.OPTION_IP_ADDRESS -> clientIp = addr
                            IpcpOption.OPTION_PRIMARY_DNS -> primaryDns = addr
                            IpcpOption.OPTION_SECONDARY_DNS -> secondaryDns = addr
                        }
                    }
                    clientAcked = true
                }
            }
        }
    }

    private fun sendPacket(output: OutputStream, bytes: ByteArray) {
        synchronized(output) {
            output.write(bytes)
            output.flush()
        }
        lastAnyTxMs.set(System.currentTimeMillis())
    }

    private fun handleControlPacket(pkt: SstpPacket.ControlPacket, output: OutputStream): Boolean {
        logDebug("RX SSTP Control msgType=0x${pkt.messageType.toInt().and(0xFFFF).toString(16)} attrs=${pkt.attributes.size}")
        return when (pkt.messageType) {
            SstpPacket.MSG_ECHO_REQUEST -> {
                val echoResp = SstpPacket.ControlPacket(messageType = SstpPacket.MSG_ECHO_RESPONSE).encode()
                sendPacket(output, echoResp)
                true
            }
            SstpPacket.MSG_CALL_DISCONNECT, SstpPacket.MSG_CALL_ABORT -> false
            else -> true
        }
    }

    private fun sendLcpEchoReply(output: OutputStream, req: LcpPacket) {
        // RFC 1661 section 5.8: Magic-Number (our local magic = 0) + echoed data bytes after sender's magic
        val incoming = req.rawData ?: ByteArray(0)
        val extraLen = maxOf(0, incoming.size - 4)
        val replyData = ByteArray(4 + extraLen)
        if (extraLen > 0) {
            System.arraycopy(incoming, 4, replyData, 4, extraLen)
        }
        val reply = LcpPacket(
            code = LcpPacket.CODE_ECHO_REPLY,
            identifier = req.identifier,
            rawData = replyData
        )
        val sstpReply = SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_LCP, reply.encode()).encode())
        sendPacket(output, sstpReply.encode())
    }

    private fun sendLcpProtocolReject(output: OutputStream, protocol: Short, info: ByteArray) {
        val copyLen = minOf(info.size, maxOf(0, config.mtu - 16))
        val body = ByteArray(2 + copyLen)
        body[0] = ((protocol.toInt() ushr 8) and 0xFF).toByte()
        body[1] = (protocol.toInt() and 0xFF).toByte()
        if (copyLen > 0) {
            System.arraycopy(info, 0, body, 2, copyLen)
        }
        val reject = LcpPacket(
            code = LcpPacket.CODE_PROTOCOL_REJECT,
            identifier = 1,
            rawData = body
        )
        val sstpReject = SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_LCP, reject.encode()).encode())
        sendPacket(output, sstpReject.encode())
    }

    private suspend fun keepaliveLoop(output: OutputStream) {
        val sstpEcho = SstpPacket.ControlPacket(messageType = SstpPacket.MSG_ECHO_REQUEST).encode()
        var lcpId: Byte = 1
        val intervalMs = (config.keepaliveIntervalSec.coerceIn(15, 30)) * 1000L
        var missedWindows = 0
        lastAnyRxMs.compareAndSet(0L, System.currentTimeMillis())
        lastAnyTxMs.compareAndSet(0L, System.currentTimeMillis())

        while (isRunning.get()) {
            delay(intervalMs)
            if (!isRunning.get()) break
            val now = System.currentTimeMillis()
            val idleRxMs = now - lastAnyRxMs.get()
            val idleTxMs = now - lastAnyTxMs.get()

            // SoftEther servers typically do not echo back custom SSTP control or LCP Echo packets.
            // Do not close transport aggressively on idle RX; only close if transport has been
            // completely silent for over 90s AND multiple consecutive keepalive attempts failed.
            if (idleRxMs > 90_000L) {
                missedWindows++
                logDebug("Keepalive RX idle ${idleRxMs}ms (missed=$missedWindows, rxUni=${rxUnicastPackets.get()})")
                if (missedWindows >= 3) {
                    logDebug("Keepalive timeout after $missedWindows missed windows (${idleRxMs}ms idle); closing stalled transport")
                    try { transport?.close() } catch (_: Exception) {}
                    break
                }
            } else {
                missedWindows = 0
            }

            // Battery Optimization:
            // If user traffic was transmitted within the last 15 seconds, NAT state and baseband are warm.
            // Avoid waking cellular radio for redundant echo pinging while active data is flowing.
            if (idleTxMs < 15_000L) {
                continue
            }

            try {
                logDebug("Keepalive TX (idleTx=${idleTxMs}ms, idleRx=${idleRxMs}ms, txPkts=${txPackets.get()}, rxUni=${rxUnicastPackets.get()}, bcastDrop=${rxBroadcastDropped.get()})")
                // 1. Send SSTP Control Echo Request
                sendPacket(output, sstpEcho)
                // 2. Send PPP LCP Echo Request (SoftEther keepalive)
                val lcpEcho = LcpPacket(
                    code = LcpPacket.CODE_ECHO_REQUEST,
                    identifier = lcpId++,
                    rawData = byteArrayOf(0, 0, 0, 0, 0x41, 0x65, 0x74, 0x68) // Magic 0 + "Aeth"
                )
                val sstpLcpEcho = SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_LCP, lcpEcho.encode()).encode()).encode()
                sendPacket(output, sstpLcpEcho)
            } catch (e: Exception) {
                logDebug("Keepalive TX error: ${e.message}")
                break
            }
        }
    }

    private fun dataPumpLoop(input: InputStream) {
        try {
            // 1000ms read timeout ensures timely shutdown checks without aborting partial packets
            transport?.setSoTimeout(1000)
        } catch (_: Exception) {}

        val os = outputStream ?: return
        var exitReason = "loop_end"
        lastAnyRxMs.set(System.currentTimeMillis())

        while (isRunning.get()) {
            try {
                // Read 4-byte SSTP header into rxHeaderBuf
                readFully(input, rxHeaderBuf, 0, 4)
                lastAnyRxMs.set(System.currentTimeMillis())
                val isControl = (rxHeaderBuf[1].toInt() and 0x01) != 0
                val len = ((rxHeaderBuf[2].toInt() and 0x0F) shl 8) or (rxHeaderBuf[3].toInt() and 0xFF)
                if (len < 4) throw IllegalStateException("Invalid SSTP packet length: $len")

                if (!isControl && len <= rxFastPacketBuf.size) {
                    // Fast path for DATA packets: read directly into rxFastPacketBuf (Zero heap allocations)
                    rxFastPacketBuf[0] = rxHeaderBuf[0]
                    rxFastPacketBuf[1] = rxHeaderBuf[1]
                    rxFastPacketBuf[2] = rxHeaderBuf[2]
                    rxFastPacketBuf[3] = rxHeaderBuf[3]
                    readFully(input, rxFastPacketBuf, 4, len - 4)

                    // Standard uncompressed PPP IPv4 data frame (0xFF 0x03 0x00 0x21):
                    if (len >= 8 &&
                        rxFastPacketBuf[4] == 0xFF.toByte() &&
                        rxFastPacketBuf[5] == 0x03.toByte() &&
                        rxFastPacketBuf[6] == 0x00.toByte() &&
                        rxFastPacketBuf[7] == 0x21.toByte()
                    ) {
                        val ipOffset = 8
                        val ipLen = len - 8
                        val pktProbe = packetProbeInterceptor
                        if (pktProbe != null && pktProbe.invoke(rxFastPacketBuf, ipOffset, ipLen)) {
                            rxUnicastPackets.incrementAndGet()
                            lastUnicastIpRxMs.set(System.currentTimeMillis())
                            continue
                        }
                        if (TunnelPackets.isBroadcastOrMulticastIpv4(rxFastPacketBuf, ipOffset, ipLen)) {
                            rxBroadcastDropped.incrementAndGet()
                            continue
                        }
                        rxPackets.incrementAndGet()
                        rxUnicastPackets.incrementAndGet()
                        lastUnicastIpRxMs.set(System.currentTimeMillis())
                        rxBytes.addAndGet(ipLen.toLong())
                        listener.onBytesTransferred(0, ipLen.toLong())
                        listener.onDataPacketReceived(rxFastPacketBuf, ipOffset, ipLen)
                        continue
                    }

                    // Compressed PPP protocol (0xFF 0x03 0x21):
                    if (len >= 7 &&
                        rxFastPacketBuf[4] == 0xFF.toByte() &&
                        rxFastPacketBuf[5] == 0x03.toByte() &&
                        rxFastPacketBuf[6] == 0x21.toByte()
                    ) {
                        val ipOffset = 7
                        val ipLen = len - 7
                        val pktProbe = packetProbeInterceptor
                        if (pktProbe != null && pktProbe.invoke(rxFastPacketBuf, ipOffset, ipLen)) {
                            rxUnicastPackets.incrementAndGet()
                            lastUnicastIpRxMs.set(System.currentTimeMillis())
                            continue
                        }
                        if (!TunnelPackets.isBroadcastOrMulticastIpv4(rxFastPacketBuf, ipOffset, ipLen)) {
                            rxPackets.incrementAndGet()
                            rxUnicastPackets.incrementAndGet()
                            lastUnicastIpRxMs.set(System.currentTimeMillis())
                            rxBytes.addAndGet(ipLen.toLong())
                            listener.onBytesTransferred(0, ipLen.toLong())
                            listener.onDataPacketReceived(rxFastPacketBuf, ipOffset, ipLen)
                            continue
                        }
                    }

                    // Fallback to SstpPacket.decode for non-IPv4 data packets (LCP, IPCP, etc.)
                    val full = rxFastPacketBuf.copyOf(len)
                    val pkt = SstpPacket.decode(full)
                    val proceed = handleDecodedPacket(pkt, os)
                    if (!proceed) {
                        exitReason = "Terminated by packet handler"
                        break
                    }
                    continue
                }

                // Fallback for ControlPacket or oversized frame
                val full = ByteArray(len)
                System.arraycopy(rxHeaderBuf, 0, full, 0, 4)
                readFully(input, full, 4, len - 4)
                val pkt = SstpPacket.decode(full)
                val proceed = handleDecodedPacket(pkt, os)
                if (!proceed) {
                    exitReason = "Terminated by control packet handler"
                    break
                }
            } catch (e: CancellationException) {
                exitReason = "Cancelled"
                break
            } catch (e: Exception) {
                exitReason = "Exception: ${e.message}"
                if (isRunning.get()) {
                    listener.onError(e)
                }
                break
            }
        }
        logDebug("dataPumpLoop exited: $exitReason (txPkts=${txPackets.get()}, rxPkts=${rxPackets.get()}, txB=${txBytes.get()}, rxB=${rxBytes.get()})")
        if (isRunning.get() && !exitReason.startsWith("Exception") && exitReason != "Cancelled") {
            listener.onError(IllegalStateException("Disconnected by server ($exitReason)"))
        }
    }

    private fun handleDecodedPacket(pkt: SstpPacket, os: OutputStream): Boolean {
        if (pkt is SstpPacket.DataPacket) {
            val ppp = PppFrame.decode(pkt.payload)
            when (ppp.protocol) {
                PppFrame.PROTO_IP -> {
                    val pktProbe = packetProbeInterceptor
                    if (pktProbe != null && pktProbe.invoke(ppp.payload, 0, ppp.payload.size)) {
                        rxUnicastPackets.incrementAndGet()
                        lastUnicastIpRxMs.set(System.currentTimeMillis())
                        return true
                    }
                    if (TunnelPackets.isBroadcastOrMulticastIpv4(ppp.payload)) {
                        rxBroadcastDropped.incrementAndGet()
                        return true
                    }
                    rxPackets.incrementAndGet()
                    rxUnicastPackets.incrementAndGet()
                    lastUnicastIpRxMs.set(System.currentTimeMillis())
                    rxBytes.addAndGet(ppp.payload.size.toLong())
                    listener.onBytesTransferred(0, ppp.payload.size.toLong())
                    listener.onDataPacketReceived(ppp.payload)
                }
                PppFrame.PROTO_LCP -> {
                    val lcp = LcpPacket.decode(ppp.payload)
                    when (lcp.code) {
                        LcpPacket.CODE_ECHO_REQUEST -> sendLcpEchoReply(os, lcp)
                        LcpPacket.CODE_ECHO_REPLY -> { /* counted via lastAnyRxMs */ }
                        LcpPacket.CODE_TERMINATE_REQUEST -> {
                            logDebug("RX LCP Terminate-Request id=${lcp.identifier}")
                            val ack = LcpPacket(
                                code = LcpPacket.CODE_TERMINATE_ACK,
                                identifier = lcp.identifier,
                                rawData = lcp.rawData
                            )
                            sendPacket(os, SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_LCP, ack.encode()).encode()).encode())
                            return false
                        }
                        else -> logDebug("RX LCP code=${lcp.code} id=${lcp.identifier}")
                    }
                }
                PppFrame.PROTO_IPCP -> {
                    val ipcp = IpcpPacket.decode(ppp.payload)
                    if (ipcp.code == IpcpPacket.CODE_CONFIGURE_REQUEST) {
                        val ack = IpcpPacket(IpcpPacket.CODE_CONFIGURE_ACK, ipcp.identifier, ipcp.options)
                        sendPacket(os, SstpPacket.DataPacket(PppFrame(PppFrame.PROTO_IPCP, ack.encode()).encode()).encode())
                    } else {
                        logDebug("Ignoring post-connect IPCP code=${ipcp.code}")
                    }
                }
                PppFrame.PROTO_CHAP, PppFrame.PROTO_PAP -> {
                    logDebug("Ignoring late auth PPP proto=0x${ppp.protocol.toInt().and(0xFFFF).toString(16)}")
                }
                PppFrame.PROTO_IPV6CP, PppFrame.PROTO_IPV6 -> {
                    logDebug("RX IPv6/IPv6CP proto=0x${ppp.protocol.toInt().and(0xFFFF).toString(16)}, sending Protocol-Reject")
                    sendLcpProtocolReject(os, ppp.protocol, ppp.payload)
                }
                else -> {
                    logDebug("RX unknown PPP proto=0x${ppp.protocol.toInt().and(0xFFFF).toString(16)}, sending Protocol-Reject")
                    sendLcpProtocolReject(os, ppp.protocol, ppp.payload)
                }
            }
            return true
        } else if (pkt is SstpPacket.ControlPacket) {
            return handleControlPacket(pkt, os)
        }
        return true
    }

    /**
     * Sends an IPv4 packet through the tunnel (encapsulated into PPP -> SSTP data packet).
     * Enqueues into a pre-allocated ring buffer for batched TLS writes, with direct fallback under saturation.
     */
    override fun sendIpPacket(packet: ByteArray, length: Int) {
        if (!isRunning.get() || length <= 0 || length > 4087) return
        val totalLen = 8 + length
        val enqueued = synchronized(txRingLock) {
            if (txRingCount.get() >= txRingCapacity) {
                false
            } else {
                val idx = txRingTail
                val buf = txRingPackets[idx]
                buf[0] = SstpPacket.VERSION_1_0
                buf[1] = SstpPacket.FLAG_DATA
                buf[2] = ((totalLen ushr 8) and 0x0F).toByte()
                buf[3] = (totalLen and 0xFF).toByte()
                buf[4] = 0xFF.toByte()
                buf[5] = 0x03.toByte()
                buf[6] = 0x00
                buf[7] = 0x21
                System.arraycopy(packet, 0, buf, 8, length)
                txRingLengths[idx] = totalLen
                txRingTail = (idx + 1) % txRingCapacity
                txRingCount.incrementAndGet()
                true
            }
        }
        if (enqueued) {
            txSignal.release()
            lastAnyTxMs.set(System.currentTimeMillis())
            txPackets.incrementAndGet()
            txBytes.addAndGet(length.toLong())
            listener.onBytesTransferred(length.toLong(), 0)
            return
        }

        // Fallback direct write when burst ring is saturated (natural TCP backpressure)
        val os = outputStream ?: return
        synchronized(os) {
            txFastBuf[0] = SstpPacket.VERSION_1_0
            txFastBuf[1] = SstpPacket.FLAG_DATA
            txFastBuf[2] = ((totalLen ushr 8) and 0x0F).toByte()
            txFastBuf[3] = (totalLen and 0xFF).toByte()
            txFastBuf[4] = 0xFF.toByte()
            txFastBuf[5] = 0x03.toByte()
            txFastBuf[6] = 0x00
            txFastBuf[7] = 0x21
            System.arraycopy(packet, 0, txFastBuf, 8, length)
            os.write(txFastBuf, 0, totalLen)
            os.flush()
        }
        lastAnyTxMs.set(System.currentTimeMillis())
        txPackets.incrementAndGet()
        txBytes.addAndGet(length.toLong())
        listener.onBytesTransferred(length.toLong(), 0)
    }

    private fun txBatchWriterLoop(os: OutputStream) {
        try {
            while (isRunning.get()) {
                txSignal.acquire()
                txSignal.drainPermits()
                if (!isRunning.get()) break

                while (isRunning.get()) {
                    var offset = 0
                    var count = 0
                    synchronized(txRingLock) {
                        while (count < 12 && txRingCount.get() > 0) {
                            val idx = txRingHead
                            val pktLen = txRingLengths[idx]
                            if (offset + pktLen > txBatchBuf.size) break
                            System.arraycopy(txRingPackets[idx], 0, txBatchBuf, offset, pktLen)
                            offset += pktLen
                            count++
                            txRingHead = (idx + 1) % txRingCapacity
                            txRingCount.decrementAndGet()
                        }
                    }
                    if (offset == 0) break
                    synchronized(os) {
                        os.write(txBatchBuf, 0, offset)
                        os.flush()
                    }
                    lastAnyTxMs.set(System.currentTimeMillis())
                }
            }
        } catch (_: InterruptedException) {
        } catch (_: CancellationException) {
        } catch (e: Exception) {
            if (isRunning.get()) {
                logDebug("txBatchWriterLoop error: ${e.message}")
            }
        }
    }

    private fun readFully(input: InputStream, buf: ByteArray, offset: Int, length: Int) {
        var readTotal = 0
        while (readTotal < length) {
            if (!isRunning.get()) throw CancellationException("SSTP client closed")
            try {
                val count = input.read(buf, offset + readTotal, length - readTotal)
                if (count == -1) throw IllegalStateException("Connection closed by server")
                readTotal += count
            } catch (_: java.net.SocketTimeoutException) {
                // Retry read cleanly without losing partial header/body bytes
                continue
            }
        }
    }

    private fun readNextSstpPacket(input: InputStream): SstpPacket {
        readFully(input, rxHeaderBuf, 0, 4)
        val len = ((rxHeaderBuf[2].toInt() and 0x0F) shl 8) or (rxHeaderBuf[3].toInt() and 0xFF)
        if (len < 4) throw IllegalStateException("Invalid SSTP packet length: $len")

        val full = ByteArray(len)
        System.arraycopy(rxHeaderBuf, 0, full, 0, 4)
        if (len > 4) {
            readFully(input, full, 4, len - 4)
        }
        return SstpPacket.decode(full)
    }

    override fun close() {
        if (isRunning.compareAndSet(true, false)) {
            txSignal.release()
            txWriterJob?.cancel()
            echoJob?.cancel()
            listener.onStateChanged(SstpState.DISCONNECTING, "Disconnecting...")
            try {
                outputStream?.let { os ->
                    val disconnect = SstpPacket.ControlPacket(messageType = SstpPacket.MSG_CALL_DISCONNECT).encode()
                    synchronized(os) {
                        os.write(disconnect)
                        os.flush()
                    }
                }
            } catch (_: Exception) {}
            try { transport?.close() } catch (_: Exception) {}
            listener.onStateChanged(SstpState.DISCONNECTED, "Disconnected")
        }
    }
}

