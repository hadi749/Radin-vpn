package com.aethervpn.vpncore.softether

import com.aethervpn.vpncore.sstp.SstpTrafficSnapshot
import com.aethervpn.vpncore.transport.SniStrategy
import com.aethervpn.vpncore.transport.SocketProtector
import com.aethervpn.vpncore.transport.TunnelClient
import java.io.IOException
import java.net.InetAddress
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

enum class SoftEtherState {
    DISCONNECTED,
    CONNECTING_PRIMARY,
    AUTHENTICATING,
    ESTABLISHING_CHANNELS,
    NEGOTIATING_DHCP,
    CONNECTED,
    DISCONNECTING
}

data class SoftEtherConfig(
    val host: String,
    val ipAddress: String,
    val port: Int = 443,
    val username: String = "vpn",
    val password: String = "vpn",
    val hubName: String = "VPNGATE",
    val targetConnections: Int = 2,
    val sniStrategy: SniStrategy = SniStrategy.AUTO_SMART,
    val customSni: String? = null,
    val strictCert: Boolean = false,
    val connectTimeoutMs: Int = 10000,
    val mtu: Int = 1400
)

data class SoftEtherVpnParameters(
    val clientIp: String,
    val netmask: String,
    val gateway: String,
    val dnsServers: List<String>,
    val mtu: Int = 1400,
    val activeChannels: Int = 1
)

interface SoftEtherEventListener {
    fun onStateChanged(state: SoftEtherState, message: String)
    fun onConnected(params: SoftEtherVpnParameters)
    fun onDisconnected(reason: String)
    fun onError(e: Exception)
    fun onIpPacketReceived(packet: ByteArray, offset: Int, length: Int)
    fun onIpPacketReceived(packet: ByteArray, length: Int) {
        onIpPacketReceived(packet, 0, length)
    }
    fun onBytesTransferred(txBytesDelta: Long, rxBytesDelta: Long) {}
    fun onLog(message: String) {}
}

/**
 * SoftEther VPN Native Protocol Client with Multi-Connection TCP channel bonding.
 */
class SoftEtherClient(
    private val config: SoftEtherConfig,
    private val socketProtector: SocketProtector?,
    private val listener: SoftEtherEventListener
) : TunnelClient {
    private var isRunning = AtomicBoolean(false)
    private var clientJob: Job? = null
    @Volatile
    private var probeInterceptor: ((ByteArray) -> Boolean)? = null
    @Volatile
    private var packetProbeInterceptor: ((ByteArray, Int, Int) -> Boolean)? = null
    private val decoySeedSeq = AtomicInteger(0)

    private val channels = CopyOnWriteArrayList<SoftEtherChannel>()
    @Volatile
    private var activeChannelsArray: Array<SoftEtherChannel> = emptyArray()
    private val txChannelIndex = AtomicInteger(0)

    val clientMac: ByteArray = SoftEtherFrame.generateClientMac()
    @Volatile
    private var gatewayMac: ByteArray = SoftEtherFrame.BROADCAST_MAC
    @Volatile
    private var myGatewayIpBytes: ByteArray? = null
    @Volatile
    private var myClientIpBytes: ByteArray? = null

    private var sessionKey: ByteArray? = null
    private var acquiredDhcp: SoftEtherDhcp.DhcpConfig? = null

    private var pendingDhcpXid: Int = 0
    private var dhcpChannel: Channel<Pair<Byte, SoftEtherDhcp.DhcpOffer>>? = null

    val totalTxBytes = AtomicLong(0)
    val totalRxBytes = AtomicLong(0)
    val txPackets = AtomicLong(0)
    val rxPackets = AtomicLong(0)
    val lastAnyRxMs = AtomicLong(System.currentTimeMillis())
    val lastUnicastIpRxMs = AtomicLong(System.currentTimeMillis())

    companion object {
        /**
         * Selects the starting channel index preserving per-flow TCP ordering when the hashed channel
         * is healthy & uncongested, and transparently failing over to the least-congested channel otherwise.
         */
        internal fun selectPreferredChannelIndex(
            channels: Array<SoftEtherChannel>,
            flowHash: Int,
            rrCursor: Int,
            nowMs: Long
        ): Int {
            val count = channels.size
            if (count <= 1) return 0
            val baseIdx = if (flowHash != 0) (flowHash and 0x7FFFFFFF) % count else (rrCursor and 0x7FFFFFFF) % count
            val preferred = channels[baseIdx]
            if (preferred.isHealthy(nowMs) && !preferred.isCongested()) {
                return baseIdx
            }
            var bestIdx = baseIdx
            var bestScore = Long.MAX_VALUE
            for (i in 0 until count) {
                val idx = (baseIdx + i) % count
                val ch = channels[idx]
                if (!ch.isConnected.get()) continue
                val penalty = if (ch.isHealthy(nowMs)) 0L else 10_000_000L
                val score = penalty + (ch.queueDepth().toLong() * 25_000L) + ch.ewmaWriteUs.get()
                if (score < bestScore) {
                    bestScore = score
                    bestIdx = idx
                }
            }
            return bestIdx
        }
    }

    private fun updateActiveChannels() {
        activeChannelsArray = channels.filter { it.isConnected.get() }.toTypedArray()
    }

    override fun setProbeInterceptor(interceptor: ((ByteArray) -> Boolean)?) {
        this.probeInterceptor = interceptor
        if (interceptor == null) {
            this.packetProbeInterceptor = null
        } else {
            this.packetProbeInterceptor = { buf, off, len ->
                interceptor.invoke(buf.copyOfRange(off, off + len))
            }
        }
    }

    override fun setPacketProbeInterceptor(interceptor: ((ByteArray, Int, Int) -> Boolean)?) {
        this.packetProbeInterceptor = interceptor
        if (interceptor == null) {
            this.probeInterceptor = null
        }
    }

    override fun snapshotTraffic(): SstpTrafficSnapshot = SstpTrafficSnapshot(
        txPackets = txPackets.get(),
        rxUnicastPackets = rxPackets.get(),
        lastAnyRxMs = lastAnyRxMs.get(),
        lastUnicastIpRxMs = lastUnicastIpRxMs.get()
    )

    suspend fun start(scope: CoroutineScope) = withContext(Dispatchers.IO) {
        if (!isRunning.compareAndSet(false, true)) return@withContext
        var wasConnected = false
        try {
            listener.onStateChanged(SoftEtherState.CONNECTING_PRIMARY, "Connecting primary channel to ${config.host}:${config.port}...")

            // 1. Establish Primary Channel (Channel 0)
            val primaryChannel = SoftEtherChannel(
                channelId = 0,
                host = config.host,
                ipAddress = config.ipAddress,
                port = config.port,
                isPrimary = true,
                sniStrategy = config.sniStrategy,
                customSni = config.customSni,
                strictCert = config.strictCert,
                socketProtector = socketProtector,
                connectTimeoutMs = config.connectTimeoutMs,
                decoySeed = decoySeedSeq.getAndIncrement()
            )

            listener.onStateChanged(SoftEtherState.AUTHENTICATING, "Authenticating with Virtual Hub '${config.hubName}'...")
            val sessionInfo = primaryChannel.connectAndHandshake(
                username = config.username,
                password = config.password,
                hubName = config.hubName,
                targetConnections = config.targetConnections
            )

            sessionKey = sessionInfo.sessionKey
            channels.add(primaryChannel)
            primaryChannel.startWriter(scope)
            updateActiveChannels()

            // Start reading on primary channel
            scope.launch(Dispatchers.IO) {
                primaryChannel.readLoop { buffer, offset, length -> handleIncomingEthernetFrame(buffer, offset, length) }
            }

            // 2. Establish Secondary Channels (Multi-TCP bonding) in Parallel
            val effectiveTarget = minOf(config.targetConnections, sessionInfo.maxConnections)
                .coerceIn(1, SoftEtherConstants.MAX_SUPPORTED_CONNECTIONS)

            if (effectiveTarget > 1) {
                listener.onStateChanged(
                    SoftEtherState.ESTABLISHING_CHANNELS,
                    "Multiplexing tunnel over $effectiveTarget parallel TCP connections..."
                )

                coroutineScope {
                    (1 until effectiveTarget).map { id ->
                        async(Dispatchers.IO) {
                            if (!scope.isActive || !isRunning.get()) return@async
                            try {
                                val ch = SoftEtherChannel(
                                    channelId = id,
                                    host = config.host,
                                    ipAddress = config.ipAddress,
                                    port = config.port,
                                    isPrimary = false,
                                    sniStrategy = config.sniStrategy,
                                    customSni = config.customSni,
                                    strictCert = config.strictCert,
                                    socketProtector = socketProtector,
                                    connectTimeoutMs = config.connectTimeoutMs,
                                    decoySeed = decoySeedSeq.getAndIncrement()
                                )
                                ch.connectAndHandshake(
                                    username = config.username,
                                    password = config.password,
                                    hubName = config.hubName,
                                    targetConnections = effectiveTarget,
                                    existingSessionKey = sessionKey
                                )
                                channels.add(ch)
                                ch.startWriter(scope)
                                updateActiveChannels()

                                scope.launch(Dispatchers.IO) {
                                    ch.readLoop { buffer, offset, length -> handleIncomingEthernetFrame(buffer, offset, length) }
                                }
                            } catch (_: Exception) {
                                // If an additional channel fails, continue with established channels
                            }
                        }
                    }.awaitAll()
                }
            }

            // 3. Negotiate Virtual DHCP
            listener.onStateChanged(SoftEtherState.NEGOTIATING_DHCP, "Negotiating IP configuration with Virtual NAT...")
            val dhcpConfig = negotiateDhcp()
            acquiredDhcp = dhcpConfig

            val vpnParams = SoftEtherVpnParameters(
                clientIp = dhcpConfig.clientIp,
                netmask = dhcpConfig.netmask,
                gateway = dhcpConfig.gateway,
                dnsServers = dhcpConfig.dnsServers,
                mtu = config.mtu,
                activeChannels = channels.count { it.isConnected.get() }
            )

            // Actively discover Gateway MAC via ARP
            sendArpDiscovery(dhcpConfig.gateway, dhcpConfig.clientIp)

            listener.onStateChanged(
                SoftEtherState.CONNECTED,
                "Connected via SoftEther Native Protocol (${vpnParams.activeChannels} TCP channels active)"
            )
            listener.onConnected(vpnParams)
            wasConnected = true

            // 4. Supervision loop
            while (scope.isActive && isRunning.get()) {
                delay(2000)
                val now = System.currentTimeMillis()
                cleanupDeadChannels(now)
                val currentChannels = activeChannelsArray
                if (currentChannels.isEmpty()) {
                    throw IOException("All SoftEther channels disconnected")
                }
                ensureChannelsCount(scope, effectiveTarget)
                for (ch in currentChannels) {
                    if (now - ch.lastTxMs.get() >= 10_000L) {
                        ch.sendKeepalive()
                    }
                }
                if (gatewayMac.contentEquals(SoftEtherFrame.BROADCAST_MAC)) {
                    val assigned = acquiredDhcp
                    if (assigned != null) {
                        sendArpDiscovery(assigned.gateway, assigned.clientIp)
                    }
                }
            }
        } catch (e: CancellationException) {
            listener.onDisconnected("Cancelled")
            throw e
        } catch (e: Exception) {
            if (wasConnected) {
                listener.onError(e)
            } else {
                throw e
            }
        } finally {
            close()
        }
    }

    private suspend fun negotiateDhcp(): SoftEtherDhcp.DhcpConfig = withContext(Dispatchers.IO) {
        val xid = SecureRandom().nextInt()
        pendingDhcpXid = xid
        val ch = Channel<Pair<Byte, SoftEtherDhcp.DhcpOffer>>(capacity = 8)
        dhcpChannel = ch

        try {
            var offer: SoftEtherDhcp.DhcpOffer? = null
            for (attempt in 1..2) {
                val discoverFrame = SoftEtherDhcp.buildDiscoverFrame(clientMac, xid)
                sendFrameBroadcast(discoverFrame)

                offer = withTimeoutOrNull(2500L) {
                    while (true) {
                        val (msgType, offerData) = ch.receive()
                        if (msgType == SoftEtherDhcp.DHCP_OFFER) {
                            return@withTimeoutOrNull offerData
                        }
                    }
                    null
                }
                if (offer != null) break
            }

            if (offer != null) {
                gatewayMac = offer.serverMac
                val requestFrame = SoftEtherDhcp.buildRequestFrame(
                    clientMac = clientMac,
                    xid = xid,
                    requestedIp = offer.offeredIp,
                    serverIp = offer.serverIp,
                    serverMac = offer.serverMac
                )
                sendFrameBroadcast(requestFrame)

                val ack = withTimeoutOrNull(2500L) {
                    while (true) {
                        val (msgType, ackData) = ch.receive()
                        if (msgType == SoftEtherDhcp.DHCP_ACK) {
                            return@withTimeoutOrNull ackData
                        }
                    }
                    null
                }

                if (ack != null) {
                    gatewayMac = ack.serverMac
                    val clientIpStr = InetAddress.getByAddress(ack.offeredIp).hostAddress ?: "192.168.30.15"
                    myGatewayIpBytes = try { InetAddress.getByName(ack.gateway).address } catch (_: Exception) { null }
                    myClientIpBytes = ack.offeredIp
                    val dns = ack.dnsServers.ifEmpty { listOf("8.8.8.8", "8.8.4.4") }
                    val conf = SoftEtherDhcp.DhcpConfig(
                        clientIp = clientIpStr,
                        netmask = ack.netmask,
                        gateway = ack.gateway,
                        dnsServers = dns,
                        serverMac = ack.serverMac
                    )
                    listener.onLog("SoftEther DHCP success: IP=$clientIpStr, Gateway=${ack.gateway}, DNS=$dns")
                    return@withContext conf
                }
            }
        } catch (e: Exception) {
            listener.onLog("SoftEther DHCP notice: ${e.message ?: "timeout"}")
        } finally {
            pendingDhcpXid = 0
            dhcpChannel = null
        }

        // Fallback: Virtual NAT standard configuration
        val fallback = SoftEtherDhcp.defaultFallbackConfig(clientMac)
        gatewayMac = SoftEtherFrame.BROADCAST_MAC
        myGatewayIpBytes = try { InetAddress.getByName(fallback.gateway).address } catch (_: Exception) { null }
        myClientIpBytes = try { InetAddress.getByName(fallback.clientIp).address } catch (_: Exception) { null }
        listener.onLog("SoftEther using Virtual NAT configuration: IP=${fallback.clientIp}, Gateway=${fallback.gateway}")
        sendArpDiscovery(fallback.gateway, fallback.clientIp)
        fallback
    }

    private fun handleIncomingEthernetFrame(frame: ByteArray, offset: Int, length: Int) {
        totalRxBytes.addAndGet(length.toLong())

        // Drop unicast frames intended for other clients on the virtual switch
        if (!SoftEtherFrame.isMatchingDestinationMac(frame, offset, clientMac)) {
            return
        }

        if (length < SoftEtherFrame.ETHERNET_HEADER_SIZE) return

        val etherType = (((frame[offset + 12].toInt() and 0xFF) shl 8) or (frame[offset + 13].toInt() and 0xFF)).toShort()

        // Check for ARP packet (EtherType 0x0806)
        if (etherType == SoftEtherFrame.ETHER_TYPE_ARP) {
            if (length >= 42) {
                handleArpPacket(frame, offset, length)
            }
            return
        }

        // Check for DHCP packet during negotiation
        if (pendingDhcpXid != 0 && length >= 282 && etherType == SoftEtherFrame.ETHER_TYPE_IPV4) {
            val frameCopy = frame.copyOfRange(offset, offset + length)
            val resp = SoftEtherDhcp.parseDhcpResponse(frameCopy, length, pendingDhcpXid)
            if (resp != null) {
                dhcpChannel?.trySend(resp)
                return
            }
        }

        // Check if it's an IPv4 packet (0x0800)
        if (etherType == SoftEtherFrame.ETHER_TYPE_IPV4) {
            // Learn Gateway MAC from incoming traffic if currently using broadcast
            if (gatewayMac.contentEquals(SoftEtherFrame.BROADCAST_MAC) && length >= 14) {
                val srcMac = ByteArray(6)
                System.arraycopy(frame, offset + 6, srcMac, 0, 6)
                if (!srcMac.contentEquals(clientMac)) {
                    gatewayMac = srcMac
                    val macStr = srcMac.joinToString(":") { "%02X".format(it) }
                    listener.onLog("Learned Gateway MAC from traffic: $macStr")
                }
            }

            val actualLen = SoftEtherFrame.getIpv4PayloadLength(frame, offset, length)
            if (actualLen >= 20) {
                rxPackets.incrementAndGet()
                val now = System.currentTimeMillis()
                lastAnyRxMs.set(now)
                lastUnicastIpRxMs.set(now)

                val ipOffset = offset + SoftEtherFrame.ETHERNET_HEADER_SIZE
                val pktProbe = packetProbeInterceptor
                if (pktProbe != null && pktProbe.invoke(frame, ipOffset, actualLen)) {
                    return
                }

                listener.onIpPacketReceived(frame, ipOffset, actualLen)
                listener.onBytesTransferred(0, actualLen.toLong())
            }
        }
    }

    private fun handleArpPacket(frame: ByteArray, offset: Int, length: Int) {
        if (length < 42) return
        val hwType = ((frame[offset + 14].toInt() and 0xFF) shl 8) or (frame[offset + 15].toInt() and 0xFF)
        val protoType = ((frame[offset + 16].toInt() and 0xFF) shl 8) or (frame[offset + 17].toInt() and 0xFF)
        val opcode = ((frame[offset + 20].toInt() and 0xFF) shl 8) or (frame[offset + 21].toInt() and 0xFF)
        if (hwType != 1 || protoType != 0x0800) return

        val senderMac = ByteArray(6)
        System.arraycopy(frame, offset + 22, senderMac, 0, 6)
        val senderIp = ByteArray(4)
        System.arraycopy(frame, offset + 28, senderIp, 0, 4)

        val gBytes = myGatewayIpBytes
        val cBytes = myClientIpBytes

        // 1. Learn/update Gateway MAC ONLY if sender IP is our Gateway IP
        if (gBytes != null && senderIp.contentEquals(gBytes)) {
            val oldMac = gatewayMac
            gatewayMac = senderMac
            if (!oldMac.contentEquals(senderMac)) {
                val macStr = senderMac.joinToString(":") { "%02X".format(it) }
                val currentGateway = acquiredDhcp?.gateway ?: "Gateway"
                listener.onLog("Learned Gateway MAC for $currentGateway: $macStr")
            }
        }

        // 2. Reply to ARP Request ONLY if the target IP is OUR assigned IP
        if (opcode == 1 && cBytes != null) {
            val targetIp = ByteArray(4)
            System.arraycopy(frame, offset + 38, targetIp, 0, 4)

            if (targetIp.contentEquals(cBytes)) {
                val reply = ByteArray(60) // Pad to 60 bytes minimum Ethernet frame
                // Ethernet header: Dst MAC (senderMac), Src MAC (clientMac), EtherType (0x0806)
                System.arraycopy(senderMac, 0, reply, 0, 6)
                System.arraycopy(clientMac, 0, reply, 6, 6)
                reply[12] = 0x08.toByte()
                reply[13] = 0x06.toByte()

                // ARP header: hwType=1, proto=0x0800, hwSize=6, protoSize=4, opcode=2 (Reply)
                reply[14] = 0x00; reply[15] = 0x01
                reply[16] = 0x08; reply[17] = 0x00
                reply[18] = 0x06; reply[19] = 0x04
                reply[20] = 0x00; reply[21] = 0x02

                // Sender MAC: clientMac
                System.arraycopy(clientMac, 0, reply, 22, 6)
                // Sender IP: cBytes
                System.arraycopy(cBytes, 0, reply, 28, 4)

                // Target MAC: senderMac
                System.arraycopy(senderMac, 0, reply, 32, 6)
                // Target IP: senderIp
                System.arraycopy(senderIp, 0, reply, 38, 4)

                sendFrameBroadcast(reply)
            }
        }
    }

    private fun sendArpDiscovery(gatewayIpStr: String, clientIpStr: String) {
        try {
            val gatewayIp = InetAddress.getByName(gatewayIpStr).address
            val clientIp = InetAddress.getByName(clientIpStr).address
            val req = buildArpRequest(clientMac, clientIp, gatewayIp)
            sendFrameBroadcast(req)
        } catch (_: Exception) {}
    }

    private fun buildArpRequest(srcMac: ByteArray, srcIp: ByteArray, targetIp: ByteArray): ByteArray {
        val frame = ByteArray(60) // Standard 60-byte minimum Ethernet frame (padded with zeros)
        // Dst MAC: Broadcast FF:FF:FF:FF:FF:FF
        for (i in 0 until 6) frame[i] = 0xFF.toByte()
        // Src MAC: srcMac
        System.arraycopy(srcMac, 0, frame, 6, 6)
        // EtherType: 0x0806 (ARP)
        frame[12] = 0x08.toByte()
        frame[13] = 0x06.toByte()
        // Hardware type: Ethernet (1)
        frame[14] = 0x00; frame[15] = 0x01
        // Protocol type: IPv4 (0x0800)
        frame[16] = 0x08; frame[17] = 0x00
        // HLEN: 6, PLEN: 4
        frame[18] = 0x06; frame[19] = 0x04
        // Opcode: 1 (Request)
        frame[20] = 0x00; frame[21] = 0x01
        // Sender MAC: srcMac
        System.arraycopy(srcMac, 0, frame, 22, 6)
        // Sender IP: srcIp
        System.arraycopy(srcIp, 0, frame, 28, 4)
        // Target MAC: 00:00:00:00:00:00
        for (i in 32 until 38) frame[i] = 0x00
        // Target IP: targetIp
        System.arraycopy(targetIp, 0, frame, 38, 4)
        return frame
    }

    /**
     * Send an IP packet received from Android TUN interface.
     * Enqueues into a pre-allocated ring buffer for batched multi-frame writes,
     * failing over automatically to healthy uncongested TCP channels.
     */
    override fun sendIpPacket(packet: ByteArray, length: Int) {
        if (!isRunning.get() || length <= 0) return
        try {
            val currentChannels = activeChannelsArray
            val count = currentChannels.size
            if (count == 0) return

            val now = System.currentTimeMillis()
            val flowHash = SoftEtherFrame.computeFlowHash(packet, 0, length)
            val startIdx = selectPreferredChannelIndex(
                channels = currentChannels,
                flowHash = flowHash,
                rrCursor = if (flowHash == 0) txChannelIndex.getAndIncrement() else 0,
                nowMs = now
            )
            for (i in 0 until count) {
                val ch = currentChannels[(startIdx + i) % count]
                if (ch.enqueueIpPacket(clientMac, gatewayMac, packet, 0, length)) {
                    txPackets.incrementAndGet()
                    totalTxBytes.addAndGet(length.toLong())
                    listener.onBytesTransferred(length.toLong(), 0)
                    return
                }
            }
        } catch (_: Exception) {
            // Channel failure or socket reset - do not crash TUN reader loop
        }
    }

    private fun sendFrameBroadcast(frame: ByteArray) {
        val currentChannels = activeChannelsArray
        for (ch in currentChannels) {
            if (ch.sendEthernetFrame(frame)) {
                return
            }
        }
    }

    private fun cleanupDeadChannels(nowMs: Long = System.currentTimeMillis()) {
        val staleOrDead = channels.filter { ch ->
            !ch.isConnected.get() ||
                (!ch.isPrimary && ch.txBytes.get() > 8192L && (nowMs - ch.lastRxMs.get()) > 25_000L && channels.size > 1)
        }
        if (staleOrDead.isNotEmpty()) {
            for (ch in staleOrDead) {
                if (ch.isConnected.get()) {
                    listener.onLog("Recycling stalled secondary TCP channel ${ch.channelId}")
                }
                ch.close()
                channels.remove(ch)
            }
            updateActiveChannels()
        }
    }

    private fun ensureChannelsCount(scope: CoroutineScope, target: Int) {
        val key = sessionKey ?: return
        val currentCount = channels.count { it.isConnected.get() }
        val needed = target - currentCount
        if (needed > 0 && isRunning.get()) {
            for (i in 0 until minOf(needed, 2)) {
                scope.launch(Dispatchers.IO) {
                    try {
                        val nextId = decoySeedSeq.getAndIncrement() + 1
                        val ch = SoftEtherChannel(
                            channelId = nextId,
                            host = config.host,
                            ipAddress = config.ipAddress,
                            port = config.port,
                            isPrimary = false,
                            sniStrategy = config.sniStrategy,
                            customSni = config.customSni,
                            strictCert = config.strictCert,
                            socketProtector = socketProtector,
                            connectTimeoutMs = config.connectTimeoutMs,
                            decoySeed = nextId
                        )
                        ch.connectAndHandshake(
                            username = config.username,
                            password = config.password,
                            hubName = config.hubName,
                            targetConnections = target,
                            existingSessionKey = key
                        )
                        channels.add(ch)
                        ch.startWriter(scope)
                        updateActiveChannels()
                        listener.onLog("Channel $nextId reconnected (fast-reconnect within 2s cycle)")
                        ch.readLoop { buffer, offset, length -> handleIncomingEthernetFrame(buffer, offset, length) }
                    } catch (_: Exception) {}
                }
            }
        }
    }

    override fun close() {
        if (!isRunning.compareAndSet(true, false)) return
        clientJob?.cancel()
        for (ch in channels) {
            ch.close()
        }
        channels.clear()
        activeChannelsArray = emptyArray()
        listener.onStateChanged(SoftEtherState.DISCONNECTED, "Disconnected")
    }
}
