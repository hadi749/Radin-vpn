package com.aethervpn.vpncore.warp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class WarpNoiseProxyTest {

    @Test
    fun warpAccountDecodesClientIdReservedBytesAndRoundTripsJson() {
        // Base64 "AQID" -> [0x01, 0x02, 0x03]; "3q2+" -> [0xDE, 0xAD, 0xBE]
        val account = WarpAccount(
            id = "acc-123",
            privateKey = "priv-key",
            publicKey = "pub-key",
            token = "tok-xyz",
            assignedIpv4 = "172.16.0.2",
            assignedIpv6 = "2606:4700:110:8000::2",
            clientId = "3q2+"
        )

        val reserved = account.reservedBytes()
        assertNotNull(reserved)
        assertArrayEquals(byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte()), reserved)

        val restored = WarpAccount.fromJson(account.toJson())
        assertNotNull(restored)
        assertEquals("3q2+", restored!!.clientId)
        assertArrayEquals(reserved, restored.reservedBytes())

        val noClientId = account.copy(clientId = null)
        assertNull(noClientId.reservedBytes())
    }

    @Test
    fun applyAndStripReservedModifyOnlyWireGuardHeaders() {
        val reserved = byteArrayOf(0x11, 0x22, 0x33)

        for (type in 1..4) {
            val pkt = ByteArray(48)
            pkt[0] = type.toByte()
            WarpNoiseProxy.applyOutboundReserved(pkt, pkt.size, reserved)
            assertEquals(0x11.toByte(), pkt[1])
            assertEquals(0x22.toByte(), pkt[2])
            assertEquals(0x33.toByte(), pkt[3])

            WarpNoiseProxy.stripInboundReserved(pkt, pkt.size)
            assertEquals(0.toByte(), pkt[1])
            assertEquals(0.toByte(), pkt[2])
            assertEquals(0.toByte(), pkt[3])
        }

        // Non-WireGuard packet (e.g., QUIC 0xC3) must remain untouched
        val nonWg = ByteArray(48)
        nonWg[0] = 0xC3.toByte()
        nonWg[1] = 0x55
        WarpNoiseProxy.applyOutboundReserved(nonWg, nonWg.size, reserved)
        assertEquals(0x55.toByte(), nonWg[1])
    }

    @Test
    fun noiseBurstNeverStartsWithWireGuardMessageTypes() {
        for (mode in WarpNoiseMode.entries) {
            repeat(10) {
                val burst = WarpNoiseProxy.generateNoiseBurst(mode)
                assertTrue("Expected non-empty burst for $mode", burst.size >= 3)
                for (pkt in burst) {
                    assertTrue(pkt.size >= 36)
                    val b0 = pkt[0].toInt() and 0xFF
                    assertFalse("Byte 0 ($b0) must not collide with WireGuard types 1..4", b0 in 1..4)
                    if (mode == WarpNoiseMode.QUIC_MIMIC) {
                        assertEquals(0xC0, b0 and 0xF0)
                        assertEquals(0x00, pkt[1].toInt() and 0xFF)
                        assertEquals(0x00, pkt[2].toInt() and 0xFF)
                        assertEquals(0x00, pkt[3].toInt() and 0xFF)
                        assertEquals(0x01, pkt[4].toInt() and 0xFF)
                    }
                }
            }
        }
    }

    @Test
    fun buildDiverseUdpCandidatesPrioritizesPreferredAndSpreadsPorts() {
        val preferred = CleanEndpoint("162.159.192.5", 4500, 32L)
        val candidates = CloudflareCleanIpScanner.buildDiverseUdpCandidates(
            preferredEndpoint = preferred,
            targetPort = 2408,
            count = 18
        )
        assertEquals(18, candidates.size)
        assertEquals("162.159.192.5", candidates.first().ip)
        assertEquals(4500, candidates.first().port)
        assertTrue(candidates.map { it.port }.toSet().size >= 10)
        assertTrue(candidates.all { it.ip.startsWith("162.159.") || it.ip.startsWith("188.114.") })
    }

    @Test
    fun loopbackRaceStampsReservedSendsNoiseAndVerifiesTransport() = runBlocking {
        val reserved = byteArrayOf(0x2A, 0x3B, 0x4C)
        val noiseBeforeInit = AtomicInteger(0)
        val sawStampedInit = AtomicBoolean(false)
        val serverReady = CountDownLatch(1)

        // Mock silent/blocked endpoint + mock responsive Cloudflare endpoint on loopback
        val deadServer = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        val liveServer = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        liveServer.soTimeout = 4000

        val responderThread = Thread {
            serverReady.countDown()
            val buf = ByteArray(2048)
            val pkt = DatagramPacket(buf, buf.size)
            while (!liveServer.isClosed) {
                try {
                    pkt.setData(buf, 0, buf.size)
                    liveServer.receive(pkt)
                    val len = pkt.length
                    val type = buf[0].toInt() and 0xFF
                    if (type == WarpNoiseProxy.WG_TYPE_HANDSHAKE_INIT && len == WarpNoiseProxy.WG_HANDSHAKE_INIT_LEN) {
                        if (buf[1] == reserved[0] && buf[2] == reserved[1] && buf[3] == reserved[2]) {
                            sawStampedInit.set(true)
                        }
                        val resp = ByteArray(WarpNoiseProxy.WG_HANDSHAKE_RESPONSE_LEN)
                        resp[0] = WarpNoiseProxy.WG_TYPE_HANDSHAKE_RESPONSE.toByte()
                        resp[1] = reserved[0]
                        resp[2] = reserved[1]
                        resp[3] = reserved[2]
                        liveServer.send(DatagramPacket(resp, resp.size, pkt.socketAddress))
                        break
                    } else if (type !in 1..4) {
                        noiseBeforeInit.incrementAndGet()
                    }
                } catch (_: Exception) {
                    break
                }
            }
        }
        responderThread.start()
        assertTrue(serverReady.await(2, TimeUnit.SECONDS))

        val proxy = WarpNoiseProxy(
            reservedBytes = reserved,
            candidatesProvider = {
                listOf(
                    CleanEndpoint("127.0.0.1", deadServer.localPort, 1L),
                    CleanEndpoint("127.0.0.1", liveServer.localPort, 1L)
                )
            }
        )

        val wgClient = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        wgClient.soTimeout = 4000

        try {
            val localPort = proxy.start()
            val proxyAddr = InetSocketAddress(InetAddress.getByName("127.0.0.1"), localPort)

            // 1. Send WireGuard Handshake Initiation (type == 1, 148 bytes, zero reserved)
            val initPkt = ByteArray(WarpNoiseProxy.WG_HANDSHAKE_INIT_LEN)
            initPkt[0] = WarpNoiseProxy.WG_TYPE_HANDSHAKE_INIT.toByte()
            wgClient.send(DatagramPacket(initPkt, initPkt.size, proxyAddr))

            // 2. Receive 92-byte Handshake Response from proxy with [1..3] stripped back to 0
            val rxBuf = ByteArray(512)
            val rxPkt = DatagramPacket(rxBuf, rxBuf.size)
            wgClient.receive(rxPkt)
            assertEquals(WarpNoiseProxy.WG_HANDSHAKE_RESPONSE_LEN, rxPkt.length)
            assertEquals(WarpNoiseProxy.WG_TYPE_HANDSHAKE_RESPONSE, rxBuf[0].toInt() and 0xFF)
            assertEquals(0.toByte(), rxBuf[1])
            assertEquals(0.toByte(), rxBuf[2])
            assertEquals(0.toByte(), rxBuf[3])

            // 3. Emit WireGuard Transport Data (type == 4) to confirm cryptographic verification
            val dataPkt = ByteArray(32)
            dataPkt[0] = WarpNoiseProxy.WG_TYPE_TRANSPORT_DATA.toByte()
            wgClient.send(DatagramPacket(dataPkt, dataPkt.size, proxyAddr))

            val winner = proxy.awaitVerifiedTransportReady(timeoutMs = 3000L)
            assertNotNull("Expected verified WARP race winner", winner)
            assertEquals(liveServer.localPort, winner!!.endpoint.port)
            assertTrue("Expected noise datagrams before handshake init", noiseBeforeInit.get() >= 3)
            assertTrue("Expected 3-byte client_id reserved header on handshake init", sawStampedInit.get())
        } finally {
            proxy.close()
            wgClient.close()
            liveServer.close()
            deadServer.close()
            responderThread.join(1000)
        }
    }
}
