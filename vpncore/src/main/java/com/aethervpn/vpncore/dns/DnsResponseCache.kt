package com.aethervpn.vpncore.dns

import com.aethervpn.vpncore.tun.DnsQueryKey
import com.aethervpn.vpncore.tun.TunnelPackets

data class DnsCacheStats(
    val hits: Long,
    val misses: Long,
    val entries: Int
) {
    val hitRatePercent: Int
        get() {
            val total = hits + misses
            return if (total <= 0L) 0 else ((hits * 100L) / total).toInt().coerceIn(0, 100)
        }
}

/**
 * Thread-safe bounded LRU+TTL cache for wire-format DNS responses partitioned by route bucket
 * (e.g., direct domestic ISP DNS vs encrypted tunnel DNS).
 */
class DnsResponseCache(
    private val maxEntries: Int = 256,
    private val minTtlSec: Long = 15L,
    private val maxTtlSec: Long = 300L,
    private val clockMs: () -> Long = { System.currentTimeMillis() }
) {
    private data class CacheKey(
        val query: DnsQueryKey,
        val routeBucket: Int
    )

    private data class CacheEntry(
        val wireResponse: ByteArray,
        val expiresAtMs: Long
    )

    private val entries = object : LinkedHashMap<CacheKey, CacheEntry>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<CacheKey, CacheEntry>?): Boolean {
            return size > maxEntries
        }
    }
    private val lock = Any()
    private var hitCount = 0L
    private var missCount = 0L

    data class CacheLookupResult(
        val wireResponse: ByteArray,
        val isStale: Boolean
    )

    fun get(queryPayload: ByteArray, routeBucket: Int): ByteArray? {
        val res = getWithStale(queryPayload, routeBucket, maxStaleGraceMs = 0L) ?: return null
        return if (res.isStale) null else res.wireResponse
    }

    fun getWithStale(
        queryPayload: ByteArray,
        routeBucket: Int,
        maxStaleGraceMs: Long = 300_000L
    ): CacheLookupResult? {
        if (queryPayload.size < 18) return null
        val qKey = TunnelPackets.extractDnsQueryKey(queryPayload) ?: return null
        val key = CacheKey(qKey, routeBucket)
        val now = clockMs()

        var stale = false
        val cached = synchronized(lock) {
            val entry = entries[key]
            if (entry == null) {
                missCount++
                return null
            }
            if (now >= entry.expiresAtMs) {
                if (maxStaleGraceMs > 0L && now < entry.expiresAtMs + maxStaleGraceMs) {
                    stale = true
                } else {
                    entries.remove(key)
                    missCount++
                    return null
                }
            }
            hitCount++
            entry.wireResponse.clone()
        }
        if (cached.size < 12) return null
        // Rewrite transaction ID so the cached payload matches the caller's request
        cached[0] = queryPayload[0]
        cached[1] = queryPayload[1]
        return CacheLookupResult(cached, stale)
    }

    fun put(queryPayload: ByteArray, responsePayload: ByteArray, routeBucket: Int) {
        if (queryPayload.size < 18 || responsePayload.size < 12) return
        val ttlSec = TunnelPackets.extractDnsMinTtlSec(responsePayload) ?: return
        val qKey = TunnelPackets.extractDnsQueryKey(queryPayload) ?: return
        val clampedTtlSec = ttlSec.toLong().coerceIn(minTtlSec, maxTtlSec)
        val entry = CacheEntry(
            wireResponse = responsePayload.clone(),
            expiresAtMs = clockMs() + clampedTtlSec * 1000L
        )
        synchronized(lock) {
            entries[CacheKey(qKey, routeBucket)] = entry
        }
    }

    fun snapshotStats(): DnsCacheStats = synchronized(lock) {
        DnsCacheStats(hits = hitCount, misses = missCount, entries = entries.size)
    }

    fun clear() {
        synchronized(lock) {
            entries.clear()
            hitCount = 0L
            missCount = 0L
        }
    }
}

