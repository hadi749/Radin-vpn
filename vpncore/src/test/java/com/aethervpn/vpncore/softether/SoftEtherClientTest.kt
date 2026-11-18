package com.aethervpn.vpncore.softether

import com.aethervpn.vpncore.transport.SniStrategy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SoftEtherClientTest {

    @Test
    fun testConfigDefaults() {
        val config = SoftEtherConfig(
            host = "vpn123.opengw.net",
            ipAddress = "1.2.3.4",
            port = 443
        )

        assertEquals("vpn123.opengw.net", config.host)
        assertEquals("1.2.3.4", config.ipAddress)
        assertEquals(443, config.port)
        assertEquals("vpn", config.username)
        assertEquals("vpn", config.password)
        assertEquals("VPNGATE", config.hubName)
        assertEquals(2, config.targetConnections)
        assertEquals(SniStrategy.AUTO_SMART, config.sniStrategy)
        assertFalse(config.strictCert)
    }

    @Test
    fun testVpnParametersConstruction() {
        val params = SoftEtherVpnParameters(
            clientIp = "192.168.30.15",
            netmask = "255.255.255.0",
            gateway = "192.168.30.1",
            dnsServers = listOf("8.8.8.8", "8.8.4.4"),
            mtu = 1400,
            activeChannels = 8
        )

        assertEquals("192.168.30.15", params.clientIp)
        assertEquals(8, params.activeChannels)
        assertEquals(1400, params.mtu)
        assertEquals(2, params.dnsServers.size)
    }

    @Test
    fun testClientInstantiation() {
        val config = SoftEtherConfig(
            host = "test.opengw.net",
            ipAddress = "1.2.3.4",
            port = 443,
            targetConnections = 4
        )

        val client = SoftEtherClient(
            config = config,
            socketProtector = null,
            listener = object : SoftEtherEventListener {
                override fun onStateChanged(state: SoftEtherState, message: String) {}
                override fun onConnected(params: SoftEtherVpnParameters) {}
                override fun onDisconnected(reason: String) {}
                override fun onError(e: Exception) {}
                override fun onIpPacketReceived(packet: ByteArray, offset: Int, length: Int) {}
            }
        )

        assertNotNull(client.clientMac)
        assertEquals(6, client.clientMac.size)
        assertEquals(0x00.toByte(), client.clientMac[0])
        assertEquals(0xAC.toByte(), client.clientMac[1])

        val snap = client.snapshotTraffic()
        assertEquals(0L, snap.txPackets)
        assertEquals(0L, snap.rxUnicastPackets)
        assertTrue(snap.lastAnyRxMs > 0L)

        client.setProbeInterceptor { true }
        client.close()
    }

    @Test
    fun testMultiFrameBlockEncodingPacksMultipleFrames() {
        val buf = java.nio.ByteBuffer.allocate(1024).order(java.nio.ByteOrder.BIG_ENDIAN)
        val frames = arrayOf(
            byteArrayOf(1, 2, 3, 4),
            byteArrayOf(5, 6, 7, 8, 9, 10)
        )
        val lengths = intArrayOf(4, 6)
        val indices = intArrayOf(0, 1)

        val totalLen = SoftEtherChannel.encodeMultiFrameBlock(buf, frames, lengths, indices, 2)
        // Expected: 4 (numFrames) + 4 (len0) + 4 + 4 (len1) + 6 = 22
        assertEquals(22, totalLen)
        assertEquals(2, buf.getInt())
        assertEquals(4, buf.getInt())
        val out0 = ByteArray(4).apply { buf.get(this) }
        assertTrue(out0.contentEquals(frames[0]))
        assertEquals(6, buf.getInt())
        val out1 = ByteArray(6).apply { buf.get(this) }
        assertTrue(out1.contentEquals(frames[1]))
    }

    @Test
    fun testSelectPreferredChannelFailsOverFromUnhealthyChannel() {
        val now = System.currentTimeMillis()
        val ch0 = SoftEtherChannel(0, "h", "1.2.3.4", 443, true, SniStrategy.AUTO_SMART, null, false, null)
        val ch1 = SoftEtherChannel(1, "h", "1.2.3.4", 443, false, SniStrategy.AUTO_SMART, null, false, null)
        // Only ch1 is marked connected
        ch1.isConnected.set(true)
        ch1.lastRxMs.set(now)

        val chosen = SoftEtherClient.selectPreferredChannelIndex(
            channels = arrayOf(ch0, ch1),
            flowHash = 0, // baseIdx = 0 (unhealthy ch0)
            rrCursor = 0,
            nowMs = now
        )
        assertEquals(1, chosen)
    }
}
