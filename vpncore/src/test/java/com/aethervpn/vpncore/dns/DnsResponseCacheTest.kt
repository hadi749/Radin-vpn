package com.aethervpn.vpncore.dns

import com.aethervpn.vpncore.tun.TunnelPackets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.concurrent.atomic.AtomicLong

class DnsResponseCacheTest {

    private fun fakeResponse(txIdHi: Byte, txIdLo: Byte, domainLabel: String, rcode: Int = 0, ttlSec: Int = 45): ByteArray {
        return byteArrayOf(
            txIdHi, txIdLo,
            0x81.toByte(), (0x80 or (rcode and 0x0F)).toByte(),
            0x00, 0x01,
            0x00, if (rcode == 0) 0x01 else 0x00,
            0x00, 0x00, 0x00, 0x00,
            domainLabel.length.toByte()
        ) + domainLabel.toByteArray() + byteArrayOf(
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0x00,
            0x00, 0x01, 0x00, 0x01,
            0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01,
            ((ttlSec ushr 24) and 0xFF).toByte(),
            ((ttlSec ushr 16) and 0xFF).toByte(),
            ((ttlSec ushr 8) and 0xFF).toByte(),
            (ttlSec and 0xFF).toByte(),
            0x00, 0x04,
            104, 16, 1, 2
        )
    }

    @Test
    fun testCacheRewritesTxIdIsolatesRouteBucketsAndRespectsTtl() {
        val nowMs = AtomicLong(1_000_000L)
        val cache = DnsResponseCache(maxEntries = 16, minTtlSec = 15, maxTtlSec = 300, clockMs = { nowMs.get() })

        val q1 = TunnelPackets.buildDnsARecordQuery("example.com", 0x1122)
        val r1 = fakeResponse(0x11, 0x22, "example", ttlSec = 45)
        cache.put(q1, r1, routeBucket = 2)

        // Different txId + same routeBucket hits and patches txId
        val q2 = TunnelPackets.buildDnsARecordQuery("EXAMPLE.COM", 0x9988)
        val hit = cache.get(q2, routeBucket = 2)
        assertNotNull(hit)
        hit!!
        assertEquals(0x99.toByte(), hit[0])
        assertEquals(0x88.toByte(), hit[1])
        assertArrayEquals(r1.copyOfRange(2, r1.size), hit.copyOfRange(2, hit.size))

        // Different routeBucket misses (direct vs tunnel isolation)
        assertNull(cache.get(q2, routeBucket = 1))

        // After 46 seconds (past 45s TTL), entry expires
        nowMs.addAndGet(46_000L)
        assertNull(cache.get(q2, routeBucket = 2))

        val stats = cache.snapshotStats()
        assertEquals(1L, stats.hits)
        assertEquals(2L, stats.misses)
        assertEquals(33, stats.hitRatePercent)
    }

    @Test
    fun testCacheSkipsErrorsAndEvictsOldestOverCapacity() {
        val nowMs = AtomicLong(1_000L)
        val cache = DnsResponseCache(maxEntries = 2, clockMs = { nowMs.get() })

        val qErr = TunnelPackets.buildDnsARecordQuery("bad.com", 0x0101)
        val errResp = fakeResponse(0x01, 0x01, "bad", rcode = 3) // NXDOMAIN
        cache.put(qErr, errResp, routeBucket = 2)
        assertNull(cache.get(qErr, routeBucket = 2))

        val qA = TunnelPackets.buildDnsARecordQuery("aaa.com", 0x0001)
        val qB = TunnelPackets.buildDnsARecordQuery("bbb.com", 0x0002)
        val qC = TunnelPackets.buildDnsARecordQuery("ccc.com", 0x0003)

        cache.put(qA, fakeResponse(0x00, 0x01, "aaa"), routeBucket = 1)
        cache.put(qB, fakeResponse(0x00, 0x02, "bbb"), routeBucket = 1)
        // Touch qA so qB becomes least-recently-used
        assertNotNull(cache.get(qA, routeBucket = 1))

        cache.put(qC, fakeResponse(0x00, 0x03, "ccc"), routeBucket = 1)
        assertNotNull(cache.get(qA, routeBucket = 1))
        assertNull(cache.get(qB, routeBucket = 1))
        assertNotNull(cache.get(qC, routeBucket = 1))
    }

    @Test
    fun testStaleWhileRevalidateReturnsStaleWithinGraceAndEvictsAfterGrace() {
        val nowMs = AtomicLong(10_000L)
        val cache = DnsResponseCache(maxEntries = 8, minTtlSec = 15, maxTtlSec = 60, clockMs = { nowMs.get() })
        val q = TunnelPackets.buildDnsARecordQuery("telegram.com", 0x1234)
        cache.put(q, fakeResponse(0x12, 0x34, "telegram", ttlSec = 20), routeBucket = 2)

        val fresh = cache.getWithStale(q, routeBucket = 2, maxStaleGraceMs = 30_000L)
        assertNotNull(fresh)
        org.junit.Assert.assertFalse(fresh!!.isStale)

        // Advance past 20s TTL but within 30s grace period
        nowMs.addAndGet(25_000L)
        val stale = cache.getWithStale(q, routeBucket = 2, maxStaleGraceMs = 30_000L)
        assertNotNull(stale)
        org.junit.Assert.assertTrue(stale!!.isStale)

        // Advance past TTL + grace (20s + 30s = 50s) -> evicted
        nowMs.addAndGet(30_000L)
        assertNull(cache.getWithStale(q, routeBucket = 2, maxStaleGraceMs = 30_000L))
    }
}

