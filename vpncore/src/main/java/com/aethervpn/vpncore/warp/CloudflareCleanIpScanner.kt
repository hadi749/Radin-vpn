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

    // Curated Cloudflare WARP WireGuard Anycast prefixes (162.159.192.0/22 & 188.114.96.0/22)
    // verified to serve WARP UDP across diverse Iranian ISPs (MCI, Irancell, Rightel, TCI, Shatel).
    val CANDIDATE_IPS = listOf(
        // 162.159.192.0/24 - 162.159.195.0/24 (Primary WARP Engage Anycast)
        "162.159.192.1", "162.159.192.2", "162.159.192.3", "162.159.192.10",
        "162.159.192.66", "162.159.192.120", "162.159.192.150", "162.159.192.200",
        "162.159.193.1", "162.159.193.2", "162.159.193.5", "162.159.193.10",
        "162.159.193.66", "162.159.193.120", "162.159.193.150", "162.159.193.200",
        "162.159.195.1", "162.159.195.2", "162.159.195.10", "162.159.195.66",
        "162.159.195.120", "162.159.195.150", "162.159.195.200",
        // 188.114.96.0/24 - 188.114.99.0/24 (European/ME Anycast Edge)
        "188.114.96.1", "188.114.96.2", "188.114.96.10", "188.114.96.66",
        "188.114.96.120", "188.114.96.150", "188.114.96.200",
        "188.114.97.1", "188.114.97.2", "188.114.97.10", "188.114.97.66",
        "188.114.97.120", "188.114.97.150", "188.114.97.200",
        "188.114.98.1", "188.114.98.2", "188.114.98.10", "188.114.98.66",
        "188.114.98.120", "188.114.98.150", "188.114.98.200",
        "188.114.99.1", "188.114.99.2", "188.114.99.10", "188.114.99.66",
        "188.114.99.120", "188.114.99.150", "188.114.99.200"
    )

    // Full list of official Cloudflare WARP WireGuard listening UDP ports (bypasses port-2408 blocks)
    val CANDIDATE_PORTS = listOf(
        2408, 500, 1701, 4500, 854, 859, 864, 878, 880, 890, 891, 894,
        903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988,
        1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506,
        3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152,
        7156, 7281, 7559, 8319, 8742, 8854, 8886
    )

    /**
     * Builds a maximally diverse list of Cloudflare Anycast (IP, UDP Port) pairs spanning
     * all 7 WARP /24 subnets and non-standard UDP ports for instant parallel real-UDP
     * WireGuard handshake racing (no slow TCP:443 pre-scan needed).
     */
    fun buildDiverseUdpCandidates(
        preferredEndpoint: CleanEndpoint? = null,
        targetPort: Int = 2408,
        count: Int = 18
    ): List<CleanEndpoint> {
        val result = LinkedHashMap<String, CleanEndpoint>(count)
        if (preferredEndpoint != null && preferredEndpoint.ip.isNotBlank() && preferredEndpoint.port in 1..65535) {
            result["${preferredEndpoint.ip}:${preferredEndpoint.port}"] = preferredEndpoint
        }

        // Group candidate IPs by /24 subnet and shuffle within each subnet for breadth
        val subnetGroups = CANDIDATE_IPS
            .groupBy { ip -> ip.substringBeforeLast('.') }
            .values
            .map { it.shuffled() }
            .shuffled()

        // Prioritize a blend of high-success non-standard ports + classic ports
        val prioritizedPorts = buildList {
            if (targetPort in CANDIDATE_PORTS) add(targetPort)
            addAll(listOf(854, 878, 880, 908, 987, 1018, 1701, 2371, 4500, 500, 4198, 7156, 8854, 8886, 2408))
            addAll(CANDIDATE_PORTS.shuffled())
        }.distinct()

        var round = 0
        var portCursor = 0
        while (result.size < count && round < 8) {
            for (group in subnetGroups) {
                if (result.size >= count) break
                val ip = group.getOrNull(round) ?: continue
                val port = prioritizedPorts[portCursor % prioritizedPorts.size]
                portCursor++
                result.putIfAbsent("$ip:$port", CleanEndpoint(ip = ip, port = port, pingMs = 0L))
            }
            round++
        }
        return result.values.toList()
    }

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
            if (targetPort != 854) 854 else 878,
            if (targetPort != 1701) 1701 else 987,
            if (targetPort != 4500) 4500 else 2371,
            if (targetPort != 500) 500 else 8854,
            7156
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
