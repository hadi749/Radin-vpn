package com.aethervpn.vpncore.transport

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class TlsClientHelloInspectorTest {

    private fun buildSyntheticClientHello(sniHost: String, paddingExtBytes: Int = 90): ByteArray {
        val hostBytes = sniHost.toByteArray(Charsets.US_ASCII)

        // Build extensions: first a large padding extension so SNI sits past byte 120, then server_name
        val extOut = ByteArrayOutputStream()
        // Extension 0x0015 (padding)
        extOut.write(0x00); extOut.write(0x15)
        extOut.write((paddingExtBytes ushr 8) and 0xFF); extOut.write(paddingExtBytes and 0xFF)
        extOut.write(ByteArray(paddingExtBytes))

        // Extension 0x0000 (server_name)
        val sniEntryLen = 1 + 2 + hostBytes.size
        val sniExtLen = 2 + sniEntryLen
        extOut.write(0x00); extOut.write(0x00)
        extOut.write((sniExtLen ushr 8) and 0xFF); extOut.write(sniExtLen and 0xFF)
        extOut.write((sniEntryLen ushr 8) and 0xFF); extOut.write(sniEntryLen and 0xFF)
        extOut.write(0x00) // host_name
        extOut.write((hostBytes.size ushr 8) and 0xFF); extOut.write(hostBytes.size and 0xFF)
        extOut.write(hostBytes)

        val extBytes = extOut.toByteArray()

        val bodyOut = ByteArrayOutputStream()
        // Legacy version TLS 1.2 + 32-byte random
        bodyOut.write(0x03); bodyOut.write(0x03)
        bodyOut.write(ByteArray(32) { 0x42 })
        // Empty session ID
        bodyOut.write(0x00)
        // Cipher suites (2 suites = 4 bytes)
        bodyOut.write(0x00); bodyOut.write(0x04)
        bodyOut.write(0x13); bodyOut.write(0x01)
        bodyOut.write(0x13); bodyOut.write(0x02)
        // Compression methods (1 null)
        bodyOut.write(0x01); bodyOut.write(0x00)
        // Extensions total length
        bodyOut.write((extBytes.size ushr 8) and 0xFF); bodyOut.write(extBytes.size and 0xFF)
        bodyOut.write(extBytes)

        val body = bodyOut.toByteArray()
        val hsOut = ByteArrayOutputStream()
        hsOut.write(0x01) // ClientHello
        hsOut.write((body.size ushr 16) and 0xFF)
        hsOut.write((body.size ushr 8) and 0xFF)
        hsOut.write(body.size and 0xFF)
        hsOut.write(body)

        val hs = hsOut.toByteArray()
        val recOut = ByteArrayOutputStream()
        recOut.write(0x16) // Handshake
        recOut.write(0x03); recOut.write(0x01)
        recOut.write((hs.size ushr 8) and 0xFF); recOut.write(hs.size and 0xFF)
        recOut.write(hs)
        return recOut.toByteArray()
    }

    @Test
    fun findSniRangeLocatesHostnameBeyondFixedOffsetAndSplitsAcrossMidpoint() {
        val host = "vpngate.secret-mirror.org"
        val packet = buildSyntheticClientHello(host, paddingExtBytes = 100)

        val sni = TlsClientHelloInspector.findSniRange(packet)
        assertNotNull(sni)
        sni!!
        assertTrue(sni.hostStart > 120)
        assertEquals(host, String(packet, sni.hostStart, sni.hostLength, Charsets.US_ASCII))

        val slices = TlsClientHelloInspector.computeTcpSplitSlices(packet, chunkSize = 24)
        assertTrue(slices.size >= 4)
        // A slice boundary must land directly on sni.hostMidpoint
        assertTrue(slices.any { it.last + 1 == sni.hostMidpoint })
        assertTrue(slices.any { it.first == sni.hostMidpoint })

        // Reassembling all slices reproduces exact original packet
        val rebuilt = ByteArrayOutputStream()
        for (range in slices) {
            rebuilt.write(packet, range.first, range.last - range.first + 1)
        }
        assertArrayEquals(packet, rebuilt.toByteArray())
    }

    @Test
    fun splitTlsRecordPreservesExactHandshakePayloadAcrossMultipleValidRecords() {
        val packet = buildSyntheticClientHello("telegram-edge.example.net", paddingExtBytes = 80)
        val originalPayloadLen = ((packet[3].toInt() and 0xFF) shl 8) or (packet[4].toInt() and 0xFF)
        val originalPayload = packet.copyOfRange(5, 5 + originalPayloadLen)

        val records = TlsClientHelloInspector.splitTlsRecord(packet, maxPayloadPerRecord = 36)
        assertTrue(records.size >= 3)

        val reassembledPayload = ByteArrayOutputStream()
        for (rec in records) {
            assertEquals(0x16, rec[0].toInt() and 0xFF)
            assertEquals(0x03, rec[1].toInt() and 0xFF)
            val recLen = ((rec[3].toInt() and 0xFF) shl 8) or (rec[4].toInt() and 0xFF)
            assertEquals(rec.size - 5, recLen)
            reassembledPayload.write(rec, 5, recLen)
        }
        assertArrayEquals(originalPayload, reassembledPayload.toByteArray())
    }

    @Test
    fun computeDesyncSlicesIsolatesTwoByteTlsHeaderAndCutsSniMidpoint() {
        val host = "filter-test.opengw.net"
        val packet = buildSyntheticClientHello(host, paddingExtBytes = 84)
        val sni = TlsClientHelloInspector.findSniRange(packet)!!

        val slices = TlsClientHelloInspector.computeDesyncSlices(packet)
        assertTrue(slices.size >= 4)
        assertEquals(0..1, slices.first())
        assertTrue(slices.any { it.last + 1 == sni.hostMidpoint })
        assertTrue(slices.any { it.first == sni.hostMidpoint })

        val rebuilt = ByteArrayOutputStream()
        for (range in slices) {
            rebuilt.write(packet, range.first, range.last - range.first + 1)
        }
        assertArrayEquals(packet, rebuilt.toByteArray())
    }

    @Test
    fun surgicalSniSplitEmitsCompactRecordsWithoutOverFragmenting() {
        val host = "compact-bypass.opengw.net"
        val packet = buildSyntheticClientHello(host, paddingExtBytes = 140)
        val originalPayloadLen = ((packet[3].toInt() and 0xFF) shl 8) or (packet[4].toInt() and 0xFF)
        val originalPayload = packet.copyOfRange(5, 5 + originalPayloadLen)

        val records = TlsClientHelloInspector.splitTlsRecord(
            packet = packet,
            maxPayloadPerRecord = 64,
            surgicalSniOnly = true
        )
        assertTrue("Expected compact 2..3 records, got ${records.size}", records.size in 2..3)

        val reassembledPayload = ByteArrayOutputStream()
        for (rec in records) {
            val recLen = ((rec[3].toInt() and 0xFF) shl 8) or (rec[4].toInt() and 0xFF)
            reassembledPayload.write(rec, 5, recLen)
        }
        assertArrayEquals(originalPayload, reassembledPayload.toByteArray())
    }

    @Test
    fun computeMicroDesyncSlicesChopsHeaderAndSniEveryTwoBytes() {
        val host = "micro-desync.opengw.net"
        val packet = buildSyntheticClientHello(host, paddingExtBytes = 84)
        val sni = TlsClientHelloInspector.findSniRange(packet)!!

        val slices = TlsClientHelloInspector.computeMicroDesyncSlices(packet)
        assertTrue(slices.size >= 10)
        assertEquals(0..1, slices[0])
        assertEquals(2..4, slices[1])
        // Every slice touching the hostname itself must be <= 2 bytes wide (except pre-SNI / post-SNI chunks)
        val sniSlices = slices.filter { it.first >= sni.hostStart && it.last < sni.hostEnd }
        assertTrue(sniSlices.isNotEmpty())
        assertTrue(sniSlices.all { (it.last - it.first + 1) <= 2 })

        val rebuilt = ByteArrayOutputStream()
        for (range in slices) {
            rebuilt.write(packet, range.first, range.last - range.first + 1)
        }
        assertArrayEquals(packet, rebuilt.toByteArray())
    }

    @Test
    fun computeSplit1SlicesIsolatesFirstByteAndCutsSniBoundaries() {
        val host = "zapret-split1.opengw.net"
        val packet = buildSyntheticClientHello(host, paddingExtBytes = 84)
        val sni = TlsClientHelloInspector.findSniRange(packet)!!

        val slices = TlsClientHelloInspector.computeSplit1Slices(packet)
        assertTrue(slices.size >= 4)
        // First slice MUST be exactly 1 byte: 0..0 containing 0x16
        assertEquals(0..0, slices[0])
        assertEquals(0x16, packet[slices[0].first].toInt() and 0xFF)
        // Second slice MUST be 4 bytes: 1..4 containing TLS version and record length
        assertEquals(1..4, slices[1])

        // Verify SNI midpoint cut exists
        assertTrue(slices.any { it.first == sni.hostMidpoint || it.last + 1 == sni.hostMidpoint })

        val rebuilt = ByteArrayOutputStream()
        for (range in slices) {
            rebuilt.write(packet, range.first, range.last - range.first + 1)
        }
        assertArrayEquals(packet, rebuilt.toByteArray())
    }

    @Test
    fun adaptiveHybridSlicesIsolateRecordAndSniAndVaryBySeed() {
        val host = "hybrid-desync.opengw.net"
        val packet = buildSyntheticClientHello(host, paddingExtBytes = 84)
        val sni = TlsClientHelloInspector.findSniRange(packet)!!

        val slices0 = TlsClientHelloInspector.computeAdaptiveHybridSlices(packet, cutSeed = 0)
        val slices20 = TlsClientHelloInspector.computeAdaptiveHybridSlices(packet, cutSeed = 20)
        assertTrue(slices0.size >= 5)
        // Reassembly for both seeds must match original ClientHello byte-for-byte
        for (slices in listOf(slices0, slices20)) {
            assertEquals(0..0, slices[0])
            assertEquals(1..2, slices[1])
            assertEquals(3..4, slices[2])
            val rebuilt = ByteArrayOutputStream()
            for (range in slices) {
                rebuilt.write(packet, range.first, range.last - range.first + 1)
            }
            assertArrayEquals(packet, rebuilt.toByteArray())
            assertTrue(slices.any { it.first in (sni.hostStart + 1) until sni.hostEnd })
        }
        assertTrue("Different cutSeeds should shift interior SNI split offset", slices0 != slices20)
    }
}

