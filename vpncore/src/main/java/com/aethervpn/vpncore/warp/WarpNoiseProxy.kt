package com.aethervpn.vpncore.warp

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

enum class WarpNoiseMode(val label: String) {
    QUIC_MIMIC("QUIC-v1 Noise"),
    RANDOM_JUNK("AmneziaWG Junk"),
    DNS_MIMIC("DNS-UDP Noise")
}

data class WarpRaceWinner(
    val endpoint: CleanEndpoint,
    val noiseMode: WarpNoiseMode,
    val handshakeRttMs: Long
)

/**
 * Local loopback UDP obfuscation & parallel handshake-racing relay for Cloudflare WARP.
 *
 * Bridges standard `wireguard-go` (`GoBackend`) pointing at `127.0.0.1:<localPort>` to
 * Cloudflare WARP Anycast endpoints while defeating Iran's UDP/WireGuard DPI:
 * 1. Injects Cloudflare's 3-byte `client_id` (`reserved`) into outbound WireGuard headers
 *    (`[1..3]`) to enable ECMP session pinning AND break the `01 00 00 00` / `04 00 00 00`
 *    DPI signature, while zeroing `[1..3]` on inbound packets for `wireguard-go`.
 * 2. Sends multi-mode pre-handshake UDP noise bursts (QUIC v1 Initial mimicry, AmneziaWG-style
 *    random junk datagrams, or DNS-like UDP probes) before Handshake Initiation and periodic rekeys.
 * 3. Races the real 148-byte WireGuard Handshake Initiation across up to 18 diverse Cloudflare
 *    `(IP, UDP Port)` endpoints simultaneously and locks onto the first node that returns a
 *    genuine 92-byte WireGuard Handshake Response (`type == 2`).
 * 4. Confirms end-to-end cryptographic tunnel readiness once `wireguard-go` validates the
 *    response and emits encrypted Transport Data (`type == 4`).
 */
class WarpNoiseProxy(
    private val reservedBytes: ByteArray?,
    private val candidatesProvider: () -> List<CleanEndpoint>,
    private val onLog: (String) -> Unit = {}
) {
    companion object {
        const val WG_TYPE_HANDSHAKE_INIT = 1
        const val WG_TYPE_HANDSHAKE_RESPONSE = 2
        const val WG_TYPE_COOKIE_REPLY = 3
        const val WG_TYPE_TRANSPORT_DATA = 4

        const val WG_HANDSHAKE_INIT_LEN = 148
        const val WG_HANDSHAKE_RESPONSE_LEN = 92
        private const val MAX_UDP_PACKET = 4096
        private const val RACE_TIMEOUT_MS = 2800

        /**
         * Stamps Cloudflare WARP's 3-byte `client_id` into WireGuard header bytes `[1..3]`.
         * Preserves WireGuard `mac1` (Cloudflare's edge reads `[1..3]` for ECMP routing and
         * zeroes it before verifying `mac1`).
         */
        fun applyOutboundReserved(packet: ByteArray, length: Int, reserved: ByteArray?) {
            if (reserved == null || reserved.size < 3 || length < 32) return
            val type = packet[0].toInt() and 0xFF
            if (type in WG_TYPE_HANDSHAKE_INIT..WG_TYPE_TRANSPORT_DATA) {
                packet[1] = reserved[0]
                packet[2] = reserved[1]
                packet[3] = reserved[2]
            }
        }

        /**
         * Zeroes WireGuard header bytes `[1..3]` on inbound packets from Cloudflare so
         * vanilla `wireguard-go` accepts them cleanly.
         */
        fun stripInboundReserved(packet: ByteArray, length: Int) {
            if (length < 32) return
            val type = packet[0].toInt() and 0xFF
            if (type in WG_TYPE_HANDSHAKE_INIT..WG_TYPE_TRANSPORT_DATA) {
                packet[1] = 0
                packet[2] = 0
                packet[3] = 0
            }
        }

        /**
         * Generates a burst of pre-handshake decoy UDP datagrams tailored to the given [mode].
         * Guaranteed never to start with WireGuard message types `0x01..0x04` so Cloudflare's
         * edge silently drops them without disrupting the subsequent handshake.
         */
        fun generateNoiseBurst(mode: WarpNoiseMode, rng: SecureRandom = SecureRandom()): List<ByteArray> {
            return when (mode) {
                WarpNoiseMode.QUIC_MIMIC -> {
                    val count = 3 + rng.nextInt(3) // 3..5 QUIC-like Initial datagrams
                    List(count) { idx ->
                        val len = if (idx == 0) 88 + rng.nextInt(48) else 44 + rng.nextInt(72)
                        val buf = ByteArray(len)
                        rng.nextBytes(buf)
                        // QUIC v1 Long Header Initial: 0xC0..0xCF, Version = 0x00000001
                        buf[0] = (0xC0 or (rng.nextInt(16) and 0x0F)).toByte()
                        buf[1] = 0x00
                        buf[2] = 0x00
                        buf[3] = 0x00
                        buf[4] = 0x01
                        buf[5] = 0x08 // DCID len = 8
                        buf[14] = 0x08 // SCID len = 8
                        buf
                    }
                }
                WarpNoiseMode.RANDOM_JUNK -> {
                    val count = 4 + rng.nextInt(3) // 4..6 random junk packets (AmneziaWG jc)
                    List(count) {
                        val len = 36 + rng.nextInt(84) // 36..119 bytes
                        val buf = ByteArray(len)
                        rng.nextBytes(buf)
                        if ((buf[0].toInt() and 0xFF) in 0..4) {
                            buf[0] = (0x50 + rng.nextInt(0x80)).toByte()
                        }
                        buf
                    }
                }
                WarpNoiseMode.DNS_MIMIC -> {
                    val count = 3 + rng.nextInt(2) // 3..4 DNS-query-like UDP packets
                    List(count) {
                        val len = 42 + rng.nextInt(28)
                        val buf = ByteArray(len)
                        rng.nextBytes(buf)
                        // Avoid 0x01..0x04 in byte 0; set standard DNS recursion-desired flags
                        buf[0] = (0x20 + rng.nextInt(0xB0)).toByte()
                        buf[2] = 0x01
                        buf[3] = 0x00
                        buf[4] = 0x00
                        buf[5] = 0x01 // QDCOUNT = 1
                        buf[6] = 0x00
                        buf[7] = 0x00
                        buf[8] = 0x00
                        buf[9] = 0x00
                        buf[10] = 0x00
                        buf[11] = 0x00
                        buf
                    }
                }
            }
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val rng = SecureRandom()
    private val running = AtomicBoolean(false)
    private val racingInProgress = AtomicBoolean(false)

    private var localSocket: DatagramSocket? = null
    @Volatile
    private var wgLocalAddr: InetSocketAddress? = null

    private val activeUpstreamSocket = AtomicReference<DatagramSocket?>(null)
    private val activeEndpointRef = AtomicReference<WarpRaceWinner?>(null)
    private val activeRaceSockets = ConcurrentHashMap.newKeySet<DatagramSocket>()

    private var localReaderJob: Job? = null
    private var upstreamReaderJob: Job? = null

    private val winnerDeferred = AtomicReference(CompletableDeferred<WarpRaceWinner>())
    private val transportReadyDeferred = AtomicReference(CompletableDeferred<WarpRaceWinner>())

    val handshakeResponsesReceived = AtomicInteger(0)
    val transportTxPackets = AtomicLong(0)
    val transportRxPackets = AtomicLong(0)

    val localPort: Int
        get() = localSocket?.localPort ?: 0

    val activeWinner: WarpRaceWinner?
        get() = activeEndpointRef.get()

    fun start(): Int {
        if (!running.compareAndSet(false, true)) return localPort
        val sock = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        runCatching {
            sock.receiveBufferSize = 2 * 1024 * 1024
            sock.sendBufferSize = 2 * 1024 * 1024
        }
        localSocket = sock

        localReaderJob = scope.launch(Dispatchers.IO) {
            localToUpstreamLoop(sock)
        }
        return sock.localPort
    }

    /**
     * Suspends until a Cloudflare endpoint completes a real 92-byte WireGuard Handshake Response
     * AND `wireguard-go` validates it and emits encrypted Transport Data (`type == 4`).
     * Falls back to accepting the verified Handshake Response if no data packet arrives yet.
     */
    suspend fun awaitVerifiedTransportReady(timeoutMs: Long = 5200L): WarpRaceWinner? {
        val transportWinner = withTimeoutOrNull(timeoutMs) {
            transportReadyDeferred.get().await()
        }
        if (transportWinner != null) return transportWinner
        val handshakeWinner = activeEndpointRef.get()
        if (handshakeWinner != null && handshakeResponsesReceived.get() > 0) {
            return handshakeWinner
        }
        return null
    }

    /**
     * Triggers a hot mid-session endpoint migration on the next WireGuard handshake initiation
     * without tearing down Android's `VpnService` / `GoBackend` interface.
     */
    fun triggerHotRescan() {
        onLog("WARP NoiseProxy: unlocking current endpoint for hot UDP rescan...")
        val oldSock = activeUpstreamSocket.getAndSet(null)
        activeEndpointRef.set(null)
        upstreamReaderJob?.cancel()
        upstreamReaderJob = null
        try { oldSock?.close() } catch (_: Exception) {}
        winnerDeferred.set(CompletableDeferred())
        transportReadyDeferred.set(CompletableDeferred())
    }

    private fun localToUpstreamLoop(localSock: DatagramSocket) {
        val buf = ByteArray(MAX_UDP_PACKET)
        val pkt = DatagramPacket(buf, buf.size)
        var lastRekeyNoiseMs = 0L

        while (running.get() && !localSock.isClosed) {
            try {
                pkt.setData(buf, 0, buf.size)
                localSock.receive(pkt)
                val len = pkt.length
                if (len <= 0) continue

                wgLocalAddr = InetSocketAddress(pkt.address, pkt.port)
                val msgType = buf[0].toInt() and 0xFF
                val currentSock = activeUpstreamSocket.get()
                val currentWinner = activeEndpointRef.get()

                if (msgType == WG_TYPE_HANDSHAKE_INIT && len == WG_HANDSHAKE_INIT_LEN) {
                    val initCopy = buf.copyOf(len)
                    applyOutboundReserved(initCopy, initCopy.size, reservedBytes)

                    if (currentSock == null || currentWinner == null) {
                        // Launch parallel multi-endpoint real-UDP race with anti-DPI noise bursts
                        if (racingInProgress.compareAndSet(false, true)) {
                            scope.launch(Dispatchers.IO) {
                                try {
                                    raceHandshakeAcrossCandidates(initCopy)
                                } finally {
                                    racingInProgress.set(false)
                                }
                            }
                        }
                    } else {
                        // Periodic WireGuard rekey (~120s): prepend 2 lightweight noise packets
                        val now = System.currentTimeMillis()
                        if (now - lastRekeyNoiseMs > 5000L) {
                            lastRekeyNoiseMs = now
                            sendNoiseOnSocket(currentSock, currentWinner.endpoint, currentWinner.noiseMode, maxPackets = 2)
                        }
                        sendRawUdp(currentSock, initCopy, initCopy.size, currentWinner.endpoint)
                    }
                } else if (currentSock != null && currentWinner != null) {
                    if (msgType == WG_TYPE_TRANSPORT_DATA) {
                        transportTxPackets.incrementAndGet()
                        val w = activeEndpointRef.get()
                        if (w != null && handshakeResponsesReceived.get() > 0) {
                            transportReadyDeferred.get().complete(w)
                        }
                    }
                    applyOutboundReserved(buf, len, reservedBytes)
                    sendRawUdp(currentSock, buf, len, currentWinner.endpoint)
                }
            } catch (_: Exception) {
                if (!running.get()) break
            }
        }
    }

    private fun raceHandshakeAcrossCandidates(patchedHandshakeInit: ByteArray) {
        val candidates = candidatesProvider()
        if (candidates.isEmpty()) return

        val winnerChosen = AtomicBoolean(false)
        val modes = WarpNoiseMode.entries
        val jobs = ArrayList<Job>(candidates.size)

        onLog("WARP NoiseProxy: racing real UDP handshake across ${candidates.size} Cloudflare endpoints with QUIC/Junk noise...")

        for ((idx, candidate) in candidates.withIndex()) {
            val mode = modes[idx % modes.size]
            val job = scope.launch(Dispatchers.IO) {
                var probeSock: DatagramSocket? = null
                try {
                    val sock = DatagramSocket()
                    probeSock = sock
                    activeRaceSockets.add(sock)
                    runCatching {
                        sock.receiveBufferSize = 2 * 1024 * 1024
                        sock.sendBufferSize = 2 * 1024 * 1024
                    }
                    sock.soTimeout = 750

                    val targetAddr = InetAddress.getByName(candidate.ip)
                    val targetSockAddr = InetSocketAddress(targetAddr, candidate.port)

                    // 1. Send Anti-DPI Noise Burst
                    val noisePackets = generateNoiseBurst(mode, rng)
                    for ((nIdx, noise) in noisePackets.withIndex()) {
                        if (!running.get() || winnerChosen.get()) return@launch
                        sock.send(DatagramPacket(noise, noise.size, targetSockAddr))
                        if (nIdx < noisePackets.lastIndex) {
                            Thread.sleep(6L + rng.nextInt(14).toLong())
                        }
                    }

                    if (!running.get() || winnerChosen.get()) return@launch

                    // 2. Send real 148-byte reserved-patched WireGuard Handshake Initiation (up to 3 fast tries)
                    val startedAt = System.currentTimeMillis()
                    val rxBuf = ByteArray(MAX_UDP_PACKET)
                    val rxPkt = DatagramPacket(rxBuf, rxBuf.size)
                    val deadline = startedAt + RACE_TIMEOUT_MS

                    var attempt = 0
                    while (running.get() && !winnerChosen.get() && System.currentTimeMillis() < deadline) {
                        if (attempt == 0 || attempt == 1) {
                            sock.send(DatagramPacket(patchedHandshakeInit, patchedHandshakeInit.size, targetSockAddr))
                        }
                        attempt++
                        try {
                            rxPkt.setData(rxBuf, 0, rxBuf.size)
                            sock.receive(rxPkt)
                            val rLen = rxPkt.length
                            val rType = if (rLen > 0) rxBuf[0].toInt() and 0xFF else 0
                            if (rType == WG_TYPE_HANDSHAKE_RESPONSE && rLen == WG_HANDSHAKE_RESPONSE_LEN) {
                                val rtt = (System.currentTimeMillis() - startedAt).coerceAtLeast(1L)
                                if (winnerChosen.compareAndSet(false, true)) {
                                    activeRaceSockets.remove(sock)
                                    sock.soTimeout = 0
                                    val winner = WarpRaceWinner(
                                        endpoint = candidate.copy(pingMs = rtt),
                                        noiseMode = mode,
                                        handshakeRttMs = rtt
                                    )
                                    lockWinner(sock, winner, rxBuf.copyOf(rLen))
                                    closeRemainingRaceSockets(exclude = sock)
                                    return@launch
                                } else {
                                    return@launch
                                }
                            }
                        } catch (_: SocketTimeoutException) {
                            // Retry initiation on timeout within race deadline
                        }
                    }
                } catch (_: Exception) {
                    // Candidate endpoint or port blocked/unreachable
                } finally {
                    val s = probeSock
                    if (s != null && activeUpstreamSocket.get() !== s) {
                        activeRaceSockets.remove(s)
                        try { s.close() } catch (_: Exception) {}
                    }
                }
            }
            jobs.add(job)
        }

        // Wait until winner is picked or race deadline expires
        val raceDeadline = System.currentTimeMillis() + RACE_TIMEOUT_MS + 400L
        while (running.get() && !winnerChosen.get() && System.currentTimeMillis() < raceDeadline) {
            try { Thread.sleep(40) } catch (_: InterruptedException) { break }
        }
        if (!winnerChosen.get()) {
            closeRemainingRaceSockets(exclude = null)
        }
    }

    private fun lockWinner(
        winningSocket: DatagramSocket,
        winner: WarpRaceWinner,
        firstResponsePacket: ByteArray
    ) {
        val prev = activeUpstreamSocket.getAndSet(winningSocket)
        if (prev != null && prev !== winningSocket) {
            try { prev.close() } catch (_: Exception) {}
        }
        activeEndpointRef.set(winner)
        handshakeResponsesReceived.incrementAndGet()
        onLog("⚡ WARP UDP Winner: ${winner.endpoint.ip}:${winner.endpoint.port} (${winner.handshakeRttMs}ms, ${winner.noiseMode.label})")

        // Forward winning 92-byte Handshake Response immediately to wireguard-go
        forwardInboundToWireGuard(firstResponsePacket, firstResponsePacket.size)
        winnerDeferred.get().complete(winner)

        upstreamReaderJob?.cancel()
        upstreamReaderJob = scope.launch(Dispatchers.IO) {
            upstreamToLocalLoop(winningSocket)
        }
    }

    private fun upstreamToLocalLoop(upstreamSock: DatagramSocket) {
        val buf = ByteArray(MAX_UDP_PACKET)
        val pkt = DatagramPacket(buf, buf.size)
        while (running.get() && !upstreamSock.isClosed && activeUpstreamSocket.get() === upstreamSock) {
            try {
                pkt.setData(buf, 0, buf.size)
                upstreamSock.receive(pkt)
                val len = pkt.length
                if (len < 32) continue
                val type = buf[0].toInt() and 0xFF
                if (type !in WG_TYPE_HANDSHAKE_INIT..WG_TYPE_TRANSPORT_DATA) continue

                if (type == WG_TYPE_HANDSHAKE_RESPONSE && len == WG_HANDSHAKE_RESPONSE_LEN) {
                    handshakeResponsesReceived.incrementAndGet()
                } else if (type == WG_TYPE_TRANSPORT_DATA) {
                    transportRxPackets.incrementAndGet()
                    activeEndpointRef.get()?.let { transportReadyDeferred.get().complete(it) }
                }
                forwardInboundToWireGuard(buf, len)
            } catch (_: Exception) {
                if (!running.get() || activeUpstreamSocket.get() !== upstreamSock) break
            }
        }
    }

    private fun forwardInboundToWireGuard(buf: ByteArray, length: Int) {
        val localSock = localSocket ?: return
        val dest = wgLocalAddr ?: return
        stripInboundReserved(buf, length)
        try {
            localSock.send(DatagramPacket(buf, length, dest))
        } catch (_: Exception) {}
    }

    private fun sendNoiseOnSocket(
        sock: DatagramSocket,
        endpoint: CleanEndpoint,
        mode: WarpNoiseMode,
        maxPackets: Int = 3
    ) {
        try {
            val dest = InetSocketAddress(InetAddress.getByName(endpoint.ip), endpoint.port)
            val packets = generateNoiseBurst(mode, rng).take(maxPackets)
            for (p in packets) {
                sock.send(DatagramPacket(p, p.size, dest))
            }
        } catch (_: Exception) {}
    }

    private fun sendRawUdp(sock: DatagramSocket, buf: ByteArray, len: Int, endpoint: CleanEndpoint) {
        try {
            val dest = InetSocketAddress(InetAddress.getByName(endpoint.ip), endpoint.port)
            sock.send(DatagramPacket(buf, len, dest))
        } catch (_: Exception) {}
    }

    private fun closeRemainingRaceSockets(exclude: DatagramSocket?) {
        val iter = activeRaceSockets.iterator()
        while (iter.hasNext()) {
            val s = iter.next()
            iter.remove()
            if (s !== exclude) {
                try { s.close() } catch (_: Exception) {}
            }
        }
    }

    fun close() {
        if (!running.compareAndSet(true, false)) return
        closeRemainingRaceSockets(exclude = null)
        val up = activeUpstreamSocket.getAndSet(null)
        try { up?.close() } catch (_: Exception) {}
        try { localSocket?.close() } catch (_: Exception) {}
        localSocket = null
        localReaderJob?.cancel()
        upstreamReaderJob?.cancel()
        scope.cancel()
    }
}
