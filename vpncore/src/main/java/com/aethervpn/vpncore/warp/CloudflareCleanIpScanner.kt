package com.aethervpn.vpncore.warp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.math.abs

data class CleanEndpoint(
    val ip: String,
    val port: Int,
    val pingMs: Long
)

object CloudflareCleanIpScanner {

    // Curated high-yield Anycast prefixes known to work across restricted cellular/fixed networks
    val CANDIDATE_IPS = listOf(
        // 188.114.96.0/24 - 188.114.99.0/24
        "188.114.97.1", "188.114.96.1", "188.114.98.1", "188.114.99.1",
        "188.114.97.2", "188.114.96.2", "188.114.98.2", "188.114.99.2",
        "188.114.97.10", "188.114.96.10", "188.114.98.10", "188.114.99.10",
        "188.114.97.66", "188.114.98.66", "188.114.96.66", "188.114.99.66",
        "188.114.97.120", "188.114.98.120", "188.114.96.120", "188.114.99.120",
        "188.114.97.150", "188.114.98.150", "188.114.96.150", "188.114.99.150",
        "188.114.97.200", "188.114.98.200", "188.114.96.200", "188.114.99.200",
        // 162.159.192.0/24 - 162.159.195.0/24 (Cloudflare WARP / Engage endpoints)
        "162.159.192.1", "162.159.193.1", "162.159.195.1",
        "162.159.192.2", "162.159.193.2", "162.159.195.2",
        "162.159.192.10", "162.159.193.10", "162.159.195.10",
        "162.159.192.66", "162.159.193.66", "162.159.195.66",
        "162.159.192.120", "162.159.193.120", "162.159.195.120",
        "162.159.192.150", "162.159.193.150", "162.159.195.150",
        "162.159.192.200", "162.159.193.200", "162.159.195.200",
        // 172.64.0.0/16 Anycast nodes
        "172.64.155.1", "172.64.156.1", "172.64.157.1", "172.64.158.1",
        "172.64.155.2", "172.64.156.2", "172.64.157.2", "172.64.158.2",
        // 104.16.0.0 - 104.28.0.0 edge
        "104.16.132.229", "104.16.133.229", "104.19.154.25", "104.20.154.25"
    )

    // Curated WARP WireGuard UDP & mimicry ports
    val CANDIDATE_PORTS = listOf(2408, 500, 1701, 4500, 443, 854, 880, 989, 990, 8080)

    suspend fun findBestCleanEndpoint(
        targetPort: Int = 2408,
        timeoutMs: Int = 850,
        sampleSize: Int = 18
    ): CleanEndpoint? = withContext(Dispatchers.IO) {
        val candidates = findTopCleanEndpoints(
            targetPort = targetPort,
            timeoutMs = timeoutMs,
            sampleSize = sampleSize,
            maxResults = 1
        )
        candidates.firstOrNull()
    }

    /**
     * Probes candidate Cloudflare Anycast IPs with dual-sample RTT + jitter scoring and returns
     * the top [maxResults] clean endpoints paired with diverse fallback ports for resilient rotation.
     */
    suspend fun findTopCleanEndpoints(
        targetPort: Int = 2408,
        timeoutMs: Int = 800,
        sampleSize: Int = 28,
        maxResults: Int = 6
    ): List<CleanEndpoint> = withContext(Dispatchers.IO) {
        val shuffledIps = CANDIDATE_IPS.shuffled().take(sampleSize)
        val validScored = coroutineScope {
            val jobs = shuffledIps.map { ip ->
                async {
                    probeEndpointStable(ip, 443, timeoutMs)
                }
            }
            jobs.awaitAll()
                .filterNotNull()
                .sortedBy { it.score }
        }

        if (validScored.isEmpty()) return@withContext emptyList()

        val portPool = listOf(
            targetPort,
            if (targetPort != 500) 500 else 1701,
            if (targetPort != 1701) 1701 else 2408,
            if (targetPort != 4500) 4500 else 854,
            if (targetPort != 443) 443 else 880,
            854
        )

        validScored.take(maxResults).mapIndexed { idx, res ->
            val assignedPort = portPool[idx % portPool.size]
            CleanEndpoint(ip = res.ip, port = assignedPort, pingMs = res.avgPingMs)
        }
    }

    private data class ScoredEndpoint(
        val ip: String,
        val avgPingMs: Long,
        val score: Long
    )

    private fun probeEndpointStable(ip: String, port: Int, timeoutMs: Int): ScoredEndpoint? {
        val rtt1 = singleTcpProbe(ip, port, timeoutMs) ?: return null
        val rtt2 = singleTcpProbe(ip, port, timeoutMs) ?: return ScoredEndpoint(
            ip = ip,
            avgPingMs = rtt1,
            score = rtt1 + 250L // single-success jitter/loss penalty
        )
        val avg = (rtt1 + rtt2) / 2L
        val jitter = abs(rtt1 - rtt2)
        return ScoredEndpoint(ip = ip, avgPingMs = avg, score = avg + jitter)
    }

    private fun singleTcpProbe(ip: String, port: Int, timeoutMs: Int): Long? {
        val start = System.currentTimeMillis()
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress(ip, port), timeoutMs)
                (System.currentTimeMillis() - start).coerceAtLeast(1L)
            }
        } catch (_: Exception) {
            null
        }
    }
}
