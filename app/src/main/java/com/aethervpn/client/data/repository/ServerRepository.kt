package com.aethervpn.client.data.repository

import android.content.Context
import com.aethervpn.client.data.local.VpnServerDao
import com.aethervpn.client.data.model.VpnServer
import com.aethervpn.client.data.source.VpnGateCsvParser
import com.aethervpn.client.data.datastore.PreferencesManager
import com.aethervpn.client.data.routing.IranRoutingRules
import com.aethervpn.vpncore.dns.DnsOverTlsClient
import com.aethervpn.vpncore.dns.DnsResolver
import com.aethervpn.vpncore.transport.SniBypassSocketFactory
import com.aethervpn.vpncore.transport.SniStrategy
import com.aethervpn.vpncore.transport.SstpTransport
import com.aethervpn.vpncore.tun.TunnelPackets
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.SequenceInputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ServerRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val vpnServerDao: VpnServerDao,
    private val okHttpClient: OkHttpClient
) {
    private val initMutex = Mutex()
    private val preferencesManager: PreferencesManager by lazy { PreferencesManager(context) }

    val allServers: Flow<List<VpnServer>> = vpnServerDao.getAllServers()
    val favoriteServers: Flow<List<VpnServer>> = vpnServerDao.getFavorites()
    val customServers: Flow<List<VpnServer>> = vpnServerDao.getCustomServers()

    suspend fun ensureInitialized(force: Boolean = false): Int = withContext(Dispatchers.IO) {
        initMutex.withLock {
            val currentCount = vpnServerDao.getServerCount()
            val staleSeed = if (currentCount > 0 && !force) {
                vpnServerDao.getServerByHost(LEGACY_STALE_SEED_HOST)?.score == LEGACY_STALE_SEED_SCORE
            } else {
                false
            }
            val missingRomania = if (currentCount > 0 && !force) {
                vpnServerDao.getServerByHost("opengw") == null
            } else false
            val oldSmallSeed = currentCount in 1..39
            if (currentCount == 0 || force || staleSeed || missingRomania || oldSmallSeed) {
                if (force || staleSeed || missingRomania || oldSmallSeed) {
                    vpnServerDao.clearVpnGateServers()
                }
                val loaded = loadBundledFallback()
                val reason = when {
                    staleSeed -> "Migrated stale bundled seed"
                    missingRomania -> "Updated catalog with European seed"
                    oldSmallSeed -> "Upgraded bundled server catalog"
                    else -> "Prepopulated"
                }
                com.aethervpn.client.service.VpnStateHolder.log("$reason $loaded servers from bundled cache.")
                loaded
            } else {
                currentCount
            }
        }
    }

    private suspend fun loadBundledFallback(): Int = withContext(Dispatchers.IO) {
        try {
            context.assets.open("vpngate_fallback.csv").use { stream ->
                val parsed = VpnGateCsvParser.parse(stream)
                if (parsed.isNotEmpty()) {
                    vpnServerDao.insertAll(parsed)
                    return@withContext parsed.size
                }
            }
        } catch (e: Exception) {
            com.aethervpn.client.service.VpnStateHolder.log("Error loading fallback: ${e.message}")
        }
        0
    }

    suspend fun refreshServers(mirrorUrl: String = PreferencesManager.DEFAULT_MIRROR_URLS): Result<Int> = withContext(Dispatchers.IO) {
        try {
            ensureInitialized()
            val isDisconnected = com.aethervpn.client.service.VpnStateHolder.state.value.status ==
                com.aethervpn.client.service.VpnStatus.DISCONNECTED
            if (isDisconnected) {
                com.aethervpn.client.service.VpnStateHolder.updateLiveStatus("درحال دریافت سرورها...")
            }
            val preferredBypass = runCatching {
                preferencesManager.settingsFlow.first().lastMirrorBypassStrategy
            }.getOrDefault("")
            var csvBytes: ByteArray? = null
            val urls = mirrorUrl.split("\n", ";", ",").map { it.trim() }.filter { it.isNotBlank() }

            for (url in urls) {
                try {
                    com.aethervpn.client.service.VpnStateHolder.log("Fetching server list from $url...")
                    val request = Request.Builder().url(url).build()
                    val response = okHttpClient.newCall(request).execute()
                    if (response.isSuccessful) {
                        val body = response.body?.bytes()
                        if (body != null && isValidVpnGateCsv(body)) {
                            csvBytes = body
                            com.aethervpn.client.service.VpnStateHolder.log("Server list fetched from $url (${body.size} bytes).")
                            break
                        } else if (body != null) {
                            com.aethervpn.client.service.VpnStateHolder.log("Mirror $url returned non-CSV payload (filtered/block page); trying next.")
                        }
                    } else {
                        com.aethervpn.client.service.VpnStateHolder.log("Mirror $url returned HTTP ${response.code}")
                    }
                } catch (e: Exception) {
                    com.aethervpn.client.service.VpnStateHolder.log("Mirror $url direct fetch unavailable (${e.message}); trying SNI bypass...")
                }

                // Fallback to SNI-bypass / raw transport for blocked mirrors
                val bypassResult = fetchUrlWithSniBypass(url, preferredStrategyKey = preferredBypass)
                if (bypassResult != null && isValidVpnGateCsv(bypassResult.body)) {
                    csvBytes = bypassResult.body
                    if (bypassResult.strategyKey.isNotBlank() && bypassResult.strategyKey != preferredBypass) {
                        runCatching { preferencesManager.updateLastMirrorBypassStrategy(bypassResult.strategyKey) }
                    }
                    com.aethervpn.client.service.VpnStateHolder.log(
                        "Server list fetched via SNI bypass (${bypassResult.strategyKey}, ${bypassResult.body.size} bytes)."
                    )
                    break
                }
            }

            // Preserve existing cache if already populated; otherwise fall back to bundled snapshot
            if (csvBytes == null) {
                val existingCount = vpnServerDao.getServerCount()
                if (existingCount > 0) {
                    com.aethervpn.client.service.VpnStateHolder.log("All network mirrors failed. Keeping $existingCount cached servers.")
                    if (isDisconnected) {
                        com.aethervpn.client.service.VpnStateHolder.updateLiveStatus("$existingCount سرور دریافت شد • آماده اتصال")
                    }
                    return@withContext Result.success(existingCount)
                }
                com.aethervpn.client.service.VpnStateHolder.log("All network mirrors failed. Using bundled server cache.")
                val loaded = loadBundledFallback()
                if (isDisconnected) {
                    com.aethervpn.client.service.VpnStateHolder.updateLiveStatus("$loaded سرور دریافت شد • آماده اتصال")
                }
                return@withContext Result.success(loaded)
            }

            val parsed = VpnGateCsvParser.parse(ByteArrayInputStream(csvBytes))
            if (parsed.isNotEmpty()) {
                val existingByHost = vpnServerDao.getAllServers().first().associateBy { it.hostName }
                val verified = filterSstpReadyServers(parsed)
                val baseList = buildRefreshedServerPool(parsed, verified)
                if (verified.isNotEmpty()) {
                    com.aethervpn.client.service.VpnStateHolder.log(
                        "Verified ${verified.size} active SSTP servers (out of ${minOf(parsed.size, MAX_PROBE_CANDIDATES)} tested); catalog size ${baseList.size}."
                    )
                } else {
                    com.aethervpn.client.service.VpnStateHolder.log(
                        "SSTP readiness probe returned 0 reachable hosts; keeping ${baseList.size} prioritized servers."
                    )
                }
                val toStore = baseList.map { fresh ->
                    val prev = existingByHost[fresh.hostName]
                    if (prev != null) {
                        fresh.copy(
                            isFavorite = prev.isFavorite,
                            successCount = prev.successCount,
                            failureCount = prev.failureCount,
                            cooldownUntil = prev.cooldownUntil,
                            lastVerifiedAt = prev.lastVerifiedAt,
                            ping = if (fresh.ping >= 0) fresh.ping else prev.ping
                        )
                    } else {
                        fresh
                    }
                }
                vpnServerDao.clearVpnGateServers()
                vpnServerDao.insertAll(toStore)
                if (isDisconnected) {
                    com.aethervpn.client.service.VpnStateHolder.updateLiveStatus("${toStore.size} سرور دریافت شد • آماده اتصال")
                }
                Result.success(toStore.size)
            } else {
                val existingCount = vpnServerDao.getServerCount()
                if (existingCount == 0) loadBundledFallback()
                Result.success(vpnServerDao.getServerCount())
            }
        } catch (e: Exception) {
            com.aethervpn.client.service.VpnStateHolder.log("Refresh error: ${e.message}")
            Result.failure(e)
        }
    }

    suspend fun testServerPing(server: VpnServer): Int = withContext(Dispatchers.IO) {
        val candidatePorts = if (server.isCustom) {
            listOf(server.customPort)
        } else {
            listOf(443, server.customPort, 992, 5555)
                .filter { it in 1..65535 && it != 1723 && it != 500 && it != 4500 }
                .distinct()
        }

        for (port in candidatePorts) {
            val start = System.currentTimeMillis()
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(server.ip, port), 2500)
                    val ping = (System.currentTimeMillis() - start).toInt().coerceAtLeast(1)
                    vpnServerDao.updatePing(server.hostName, ping)
                    if (port != server.customPort) {
                        vpnServerDao.updatePort(server.hostName, port)
                        com.aethervpn.client.service.VpnStateHolder.log(
                            "Discovered working port $port for ${server.countryLong.ifBlank { server.hostName }}"
                        )
                    }
                    com.aethervpn.client.service.VpnStateHolder.log(
                        "Ping to ${server.countryLong.ifBlank { server.hostName }} ($port): ${ping}ms"
                    )
                    return@withContext ping
                }
            } catch (_: Exception) {
                // Try next candidate port
            }
        }
        vpnServerDao.updatePing(server.hostName, -1)
        com.aethervpn.client.service.VpnStateHolder.log(
            "Ping to ${server.countryLong.ifBlank { server.hostName }} failed"
        )
        -1
    }

    suspend fun testBatchPings(
        maxServers: Int = 20,
        onProgress: (Int, Int) -> Unit = { _, _ -> }
    ): Unit = withContext(Dispatchers.IO) {
        val servers = vpnServerDao.getAllServers().first().take(maxServers)
        if (servers.isEmpty()) return@withContext

        val semaphore = Semaphore(6)
        val completedCount = AtomicInteger(0)
        val total = servers.size

        coroutineScope {
            val jobs = servers.map { server ->
                async {
                    semaphore.withPermit {
                        testServerPing(server)
                        val done = completedCount.incrementAndGet()
                        onProgress(done, total)
                    }
                }
            }
            jobs.awaitAll()
        }
    }

    suspend fun toggleFavorite(server: VpnServer) {
        vpnServerDao.setFavorite(server.hostName, !server.isFavorite)
    }

    suspend fun addCustomServer(server: VpnServer) {
        saveCustomServer(server)
    }

    suspend fun saveCustomServer(server: VpnServer, previousHostName: String? = null) = withContext(Dispatchers.IO) {
        val oldKey = previousHostName?.trim()?.takeIf { it.isNotEmpty() && it != server.hostName }
        val existing = vpnServerDao.getServerByHost(previousHostName ?: server.hostName)
        if (oldKey != null) {
            vpnServerDao.deleteByHost(oldKey)
        }
        vpnServerDao.insert(
            server.copy(
                isCustom = true,
                isFavorite = existing?.isFavorite ?: server.isFavorite
            )
        )
    }

    suspend fun refreshIranCidrs(sourceUrl: String = IranRoutingRules.DEFAULT_RIPE_IR_URL): Result<Int> =
        withContext(Dispatchers.IO) {
            try {
                val preferredBypass = runCatching {
                    preferencesManager.settingsFlow.first().lastMirrorBypassStrategy
                }.getOrDefault("")
                val bodyBytes = try {
                    val req = Request.Builder().url(sourceUrl).build()
                    okHttpClient.newCall(req).execute().use { resp ->
                        if (resp.isSuccessful) resp.body?.bytes() else null
                    }
                } catch (_: Exception) {
                    null
                } ?: fetchUrlWithSniBypass(sourceUrl, preferredStrategyKey = preferredBypass)?.body

                if (bodyBytes == null || bodyBytes.isEmpty()) {
                    return@withContext Result.failure(IllegalStateException("Unable to reach Iran CIDR source"))
                }
                val updatedCount = IranRoutingRules.saveRemoteIranCidrs(context, String(bodyBytes, Charsets.UTF_8))
                com.aethervpn.client.service.VpnStateHolder.log("Updated Iran CIDR routing table ($updatedCount prefixes).")
                Result.success(updatedCount)
            } catch (e: Exception) {
                com.aethervpn.client.service.VpnStateHolder.log("Iran CIDR update error: ${e.message}")
                Result.failure(e)
            }
        }

    suspend fun deleteServer(server: VpnServer) {
        vpnServerDao.deleteByHost(server.hostName)
    }

    suspend fun recordServerSuccess(hostName: String) = withContext(Dispatchers.IO) {
        vpnServerDao.recordSuccess(hostName, System.currentTimeMillis())
    }

    suspend fun recordServerFailure(hostName: String, cooldownMs: Long = DEFAULT_COOLDOWN_MS) = withContext(Dispatchers.IO) {
        vpnServerDao.recordFailure(hostName, System.currentTimeMillis() + cooldownMs)
    }

    suspend fun clearServerCooldowns() = withContext(Dispatchers.IO) {
        vpnServerDao.clearCooldowns()
    }

    suspend fun getOrderedFailoverCandidates(excludeHosts: Set<String> = emptySet()): List<VpnServer> = withContext(Dispatchers.IO) {
        val candidates = vpnServerDao.getAllServers().first()
            .filter {
                !it.isCustom &&
                    !isCensoredCountry(it.countryShort) &&
                    it.hostName !in excludeHosts &&
                    it.ip !in excludeHosts
            }
        smartSortServers(candidates, System.currentTimeMillis())
    }

    suspend fun getBestServer(excludeHosts: Set<String> = emptySet()): VpnServer? =
        getOrderedFailoverCandidates(excludeHosts).firstOrNull()

    internal suspend fun filterSstpReadyServers(
        servers: List<VpnServer>,
        probeFn: suspend (VpnServer) -> VpnServer? = ::probeSstpReady
    ): List<VpnServer> = coroutineScope {
        val selected = selectProbeCandidates(servers, MAX_PROBE_CANDIDATES)
        val semaphore = Semaphore(PROBE_CONCURRENCY)
        val results = selected.map { server ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    probeFn(server)
                }
            }
        }.awaitAll().filterNotNull()
        smartSortServers(results, System.currentTimeMillis())
    }

    private fun probeSstpReady(server: VpnServer): VpnServer? {
        val ipAddr = try {
            InetAddress.getByName(server.ip)
        } catch (_: Exception) {
            return null
        }
        val probeStrategies = listOf(
            SniStrategy.ADAPTIVE_HYBRID_DESYNC to 1,
            SniStrategy.ZAPRET_SPLIT1_DESYNC to 1,
            SniStrategy.TLS_HEADER_DESYNC to 2,
            SniStrategy.MULTI_CHUNK_FRAGMENTATION to 16,
            SniStrategy.DIRECT_IP_NO_SNI to 3
        )
        for ((strategy, splitPos) in probeStrategies) {
            var transport: SstpTransport? = null
            val startedAt = System.currentTimeMillis()
            try {
                transport = SniBypassSocketFactory(
                    strategy = strategy,
                    splitPosition = splitPos,
                    splitDelayMs = 5,
                    strictCert = false
                ).createAndConnectTransport(
                    host = server.hostName.ifBlank { server.ip },
                    ipAddress = ipAddr,
                    port = server.customPort,
                    timeoutMs = PROBE_TIMEOUT_MS
                )
                transport.setSoTimeout(PROBE_TIMEOUT_MS)
                val req = buildString {
                    append("SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n")
                    append("Host: ${server.ip}:${server.customPort}\r\n")
                    append("SSTPCORRELATIONID: {${UUID.randomUUID()}}\r\n")
                    append("Content-Length: 18446744073709551615\r\n")
                    append("\r\n")
                }.toByteArray(Charsets.US_ASCII)
                transport.outputStream.write(req)
                transport.outputStream.flush()

                val buf = ByteArray(128)
                val n = transport.inputStream.read(buf)
                if (n > 0) {
                    val statusLine = String(buf, 0, n, Charsets.US_ASCII)
                    if (statusLine.startsWith("HTTP/1.1 200") || statusLine.startsWith("HTTP/1.0 200")) {
                        val rttMs = (System.currentTimeMillis() - startedAt).toInt().coerceAtLeast(1)
                        return server.copy(ping = rttMs)
                    }
                }
            } catch (_: Exception) {
                // Retry with next desync/fragmentation strategy if DPI reset or injected block page
            } finally {
                try { transport?.close() } catch (_: Exception) {}
            }
        }
        return null
    }

    private fun fetchUrlWithSniBypass(
        urlString: String,
        preferredStrategyKey: String = "",
        redirectsRemaining: Int = 3
    ): BypassFetchResult? {
        val url = try {
            URL(urlString)
        } catch (_: Exception) {
            return null
        }
        val isHttps = url.protocol.equals("https", ignoreCase = true)
        val isHttp = url.protocol.equals("http", ignoreCase = true)
        if (!isHttps && !isHttp) return null

        val host = url.host
        val port = if (url.port != -1) url.port else if (isHttps) 443 else 80
        val path = url.file.ifBlank { "/" }
        val hostHeader = if ((isHttps && port == 443) || (isHttp && port == 80)) host else "$host:$port"
        val reqBytes = buildString {
            append("GET $path HTTP/1.1\r\n")
            append("Host: $hostHeader\r\n")
            append("User-Agent: RadinVPN/1.5\r\n")
            append("Accept: */*\r\n")
            append("Accept-Encoding: identity\r\n")
            append("Connection: close\r\n")
            append("\r\n")
        }.toByteArray(Charsets.US_ASCII)

        val addr = resolvePublicHostAddress(host) ?: return null

        if (isHttp) {
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(addr, port), BYPASS_CONNECT_TIMEOUT_MS)
                    socket.soTimeout = BYPASS_READ_TIMEOUT_MS
                    val out = socket.getOutputStream()
                    val split = minOf(8, reqBytes.size)
                    out.write(reqBytes, 0, split)
                    out.flush()
                    if (reqBytes.size > split) {
                        out.write(reqBytes, split, reqBytes.size - split)
                        out.flush()
                    }
                    val resp = parseHttpResponse(socket.getInputStream()) ?: return null
                    if (resp.statusCode in 300..399 && !resp.location.isNullOrBlank() && redirectsRemaining > 0) {
                        return fetchUrlWithSniBypass(
                            URL(url, resp.location).toString(),
                            preferredStrategyKey = preferredStrategyKey,
                            redirectsRemaining = redirectsRemaining - 1
                        )
                    }
                    if (resp.statusCode in 200..299 && resp.body.isNotEmpty()) {
                        return BypassFetchResult(HTTP_SPLIT_BYPASS_KEY, resp.body)
                    }
                }
            } catch (_: Exception) {}
            return null
        }

        val candidates = buildOrderedBypassCandidates(preferredStrategyKey)
        for (candidate in candidates) {
            var transport: SstpTransport? = null
            try {
                transport = SniBypassSocketFactory(
                    strategy = candidate.strategy,
                    splitPosition = candidate.splitPosition,
                    splitDelayMs = 10,
                    strictCert = false
                ).createAndConnectTransport(
                    host = host,
                    ipAddress = addr,
                    port = port,
                    timeoutMs = BYPASS_CONNECT_TIMEOUT_MS
                )
                transport.setSoTimeout(BYPASS_READ_TIMEOUT_MS)
                transport.outputStream.write(reqBytes)
                transport.outputStream.flush()

                val resp = parseHttpResponse(transport.inputStream) ?: continue
                if (resp.statusCode in 300..399 && !resp.location.isNullOrBlank() && redirectsRemaining > 0) {
                    val nextUrl = URL(url, resp.location).toString()
                    try { transport.close() } catch (_: Exception) {}
                    transport = null
                    return fetchUrlWithSniBypass(
                        nextUrl,
                        preferredStrategyKey = candidate.key,
                        redirectsRemaining = redirectsRemaining - 1
                    )
                }
                if (resp.statusCode in 200..299 && resp.body.isNotEmpty()) {
                    return BypassFetchResult(candidate.key, resp.body)
                }
            } catch (_: Exception) {
                // Try next SNI strategy
            } finally {
                try { transport?.close() } catch (_: Exception) {}
            }
        }
        return null
    }

    internal data class BypassFetchResult(
        val strategyKey: String,
        val body: ByteArray
    )

    internal data class MirrorBypassCandidate(
        val key: String,
        val strategy: SniStrategy,
        val splitPosition: Int
    )

    internal data class HttpRawResponse(
        val statusCode: Int,
        val location: String?,
        val body: ByteArray
    )

    companion object {
        private const val LEGACY_STALE_SEED_HOST = "vg062133035.opengw.net"
        private const val LEGACY_STALE_SEED_SCORE = 9999999L
        private const val MAX_PROBE_CANDIDATES = 110
        private const val PROBE_CONCURRENCY = 20
        private const val PROBE_TIMEOUT_MS = 2500
        internal const val TARGET_MIN_SERVERS = 36
        private const val BYPASS_CONNECT_TIMEOUT_MS = 4000
        private const val BYPASS_READ_TIMEOUT_MS = 8000
        private const val HTTP_SPLIT_BYPASS_KEY = "HTTP_SPLIT"
        internal const val DEFAULT_COOLDOWN_MS = 20 * 60 * 1000L

        internal val EUROPEAN_COUNTRY_CODES = setOf(
            "RO", "DE", "NL", "FR", "GB", "UK", "IT", "ES", "PL", "SE", "FI", "NO", "DK",
            "CH", "AT", "BE", "CZ", "HU", "BG", "GR", "PT", "IE", "UA", "MD", "RS", "HR",
            "SK", "SI", "LT", "LV", "EE", "LU", "IS", "TR"
        )

        internal val CENSORED_COUNTRY_CODES = setOf("RU", "IR", "CN", "BY", "SY", "CU", "KP")

        internal fun isEuropeanServer(countryShort: String): Boolean =
            countryShort.trim().uppercase() in EUROPEAN_COUNTRY_CODES

        internal fun isLowLatencyRegion(countryShort: String): Boolean {
            val code = countryShort.trim().uppercase()
            return code in EUROPEAN_COUNTRY_CODES || code == "AE" || code == "TR"
        }

        internal fun isCensoredCountry(countryShort: String): Boolean =
            countryShort.trim().uppercase() in CENSORED_COUNTRY_CODES

        internal fun isRestrictedAcademicSubnet(ip: String): Boolean =
            ip.startsWith("219.100.37.")

        fun isValidVpnGateCsv(data: ByteArray): Boolean {
            if (data.size < 50) return false
            val sample = String(data, 0, minOf(data.size, 1024), Charsets.UTF_8)
            return sample.contains("*vpn_servers") || sample.contains("#HostName", ignoreCase = true)
        }

        internal fun selectProbeCandidates(
            servers: List<VpnServer>,
            limit: Int = MAX_PROBE_CANDIDATES
        ): List<VpnServer> {
            if (servers.size <= limit) {
                return servers.sortedWith(
                    compareBy<VpnServer> { !isEuropeanServer(it.countryShort) }
                        .thenByDescending { it.score }
                )
            }

            val chosen = LinkedHashMap<String, VpnServer>(limit)

            // Reserve European / nearby low-latency servers first so they are always tested
            val european = servers
                .filter { isEuropeanServer(it.countryShort) }
                .sortedByDescending { it.score }
            for (server in european) {
                if (chosen.size >= limit) break
                chosen[server.hostName] = server
            }

            // Ensure non-European country diversity (US, KR, SG, JP, etc.), filtering high-censorship exit nodes
            val byNonEuCountry = servers
                .filter { !isEuropeanServer(it.countryShort) && !isCensoredCountry(it.countryShort) }
                .groupBy { it.countryShort.ifBlank { it.countryLong }.ifBlank { "UNK" }.uppercase() }
                .values
                .map { it.sortedByDescending { s -> s.score } }
                .sortedByDescending { it.firstOrNull()?.score ?: 0L }

            for (slot in 0 until 3) {
                for (countryList in byNonEuCountry) {
                    if (chosen.size >= limit) break
                    val candidate = countryList.getOrNull(slot) ?: continue
                    chosen.putIfAbsent(candidate.hostName, candidate)
                }
            }

            if (chosen.size < limit) {
                for (server in servers.sortedByDescending { it.score }) {
                    if (chosen.size >= limit) break
                    chosen.putIfAbsent(server.hostName, server)
                }
            }
            return chosen.values.toList()
        }

        internal fun buildRefreshedServerPool(
            parsed: List<VpnServer>,
            verified: List<VpnServer>,
            targetMinServers: Int = TARGET_MIN_SERVERS
        ): List<VpnServer> {
            if (verified.size >= targetMinServers || parsed.size <= verified.size) {
                return verified.ifEmpty {
                    parsed
                        .sortedWith(compareBy<VpnServer> { !isEuropeanServer(it.countryShort) }.thenByDescending { it.score })
                        .take(maxOf(targetMinServers, 40))
                }
            }
            val result = LinkedHashMap<String, VpnServer>(targetMinServers)
            verified.forEach { result[it.hostName] = it }

            val remaining = parsed
                .filter { it.hostName !in result }
                .sortedWith(
                    compareBy<VpnServer> { !isEuropeanServer(it.countryShort) }
                        .thenByDescending { it.score }
                )

            // Top up with remaining European servers then diverse countries (ping=-1 keeps verified hosts ahead)
            val diverseBackfill = selectProbeCandidates(remaining, (targetMinServers - result.size).coerceAtLeast(0))
            for (server in diverseBackfill) {
                if (result.size >= targetMinServers) break
                result.putIfAbsent(server.hostName, server.copy(ping = -1))
            }
            return result.values.toList()
        }

        internal fun subnet24(ip: String): String {
            val parts = ip.split('.')
            return if (parts.size == 4) "${parts[0]}.${parts[1]}.${parts[2]}" else ip
        }

        internal fun resolveEffectiveMtu(
            configuredMtu: Int,
            physicalMtu: Int,
            isCellular: Boolean
        ): Int {
            return when {
                physicalMtu in 576..1399 -> {
                    val physicalCap = (physicalMtu - 84).coerceAtLeast(1200)
                    minOf(configuredMtu, physicalCap)
                }
                isCellular && physicalMtu <= 0 -> minOf(configuredMtu, 1280)
                else -> configuredMtu
            }
        }

        internal fun selectNextCandidate(
            servers: List<VpnServer>,
            excludedHosts: Set<String> = emptySet(),
            deprioritizedSubnets: Set<String> = emptySet(),
            nowMs: Long = System.currentTimeMillis()
        ): VpnServer? {
            val pool = servers.filter {
                !it.isCustom &&
                    !isCensoredCountry(it.countryShort) &&
                    it.hostName !in excludedHosts &&
                    it.ip !in excludedHosts
            }
            val sorted = smartSortServers(pool, nowMs)
            return sorted.firstOrNull { subnet24(it.ip) !in deprioritizedSubnets && !isRestrictedAcademicSubnet(it.ip) }
                ?: sorted.firstOrNull()
        }

        internal fun selectRaceCandidates(
            servers: List<VpnServer>,
            primary: VpnServer? = null,
            excludedHosts: Set<String> = emptySet(),
            deprioritizedSubnets: Set<String> = emptySet(),
            maxCandidates: Int = 3,
            nowMs: Long = System.currentTimeMillis()
        ): List<VpnServer> {
            val pool = servers.filter {
                !it.isCustom &&
                    !isCensoredCountry(it.countryShort) &&
                    it.hostName !in excludedHosts &&
                    it.ip !in excludedHosts &&
                    it.cooldownUntil <= nowMs
            }
            val sorted = smartSortServers(pool, nowMs)
            val (freshSubnets, failedSubnets) = sorted.partition {
                subnet24(it.ip) !in deprioritizedSubnets && !isRestrictedAcademicSubnet(it.ip)
            }
            val ordered = freshSubnets + failedSubnets
            val chosen = LinkedHashMap<String, VpnServer>(maxCandidates)
            val seenSubnets = HashSet<String>()
            val seenCountries = HashSet<String>()

            if (primary != null &&
                primary.hostName !in excludedHosts &&
                primary.ip !in excludedHosts &&
                !isCensoredCountry(primary.countryShort) &&
                !isRestrictedAcademicSubnet(primary.ip) &&
                subnet24(primary.ip) !in deprioritizedSubnets
            ) {
                chosen[primary.hostName] = primary
                seenSubnets.add(subnet24(primary.ip))
                seenCountries.add(primary.countryShort.uppercase())
            }

            // Pass 1: maximize both country and /24 subnet diversity across racers
            for (server in ordered) {
                if (chosen.size >= maxCandidates) break
                if (server.hostName in chosen) continue
                val country = server.countryShort.uppercase()
                val subnet = subnet24(server.ip)
                if (country !in seenCountries && subnet !in seenSubnets) {
                    chosen[server.hostName] = server
                    seenCountries.add(country)
                    seenSubnets.add(subnet)
                }
            }

            // Pass 2: maximize /24 subnet diversity
            for (server in ordered) {
                if (chosen.size >= maxCandidates) break
                if (server.hostName in chosen) continue
                val subnet = subnet24(server.ip)
                if (subnet !in seenSubnets) {
                    chosen[server.hostName] = server
                    seenSubnets.add(subnet)
                }
            }

            // Pass 3: fill remaining slots by smart score
            for (server in ordered) {
                if (chosen.size >= maxCandidates) break
                chosen.putIfAbsent(server.hostName, server)
            }
            return chosen.values.toList()
        }

        private fun healthTier(server: VpnServer): Int = when {
            server.successCount > server.failureCount && server.lastVerifiedAt > 0L -> 0
            server.successCount == 0 && server.failureCount == 0 -> 1
            else -> 2
        }

        internal fun smartSortServers(
            servers: List<VpnServer>,
            nowMs: Long = System.currentTimeMillis()
        ): List<VpnServer> {
            return servers.sortedWith(
                compareBy<VpnServer> { it.cooldownUntil > nowMs }
                    .thenBy { isCensoredCountry(it.countryShort) }
                    .thenBy { isRestrictedAcademicSubnet(it.ip) }
                    .thenByDescending { it.isFavorite }
                    .thenBy { !isLowLatencyRegion(it.countryShort) }
                    .thenByDescending { it.speed }
                    .thenBy { healthTier(it) }
                    .thenBy { it.ping < 0 }
                    .thenBy { if (it.ping >= 0) it.ping / 50 else Int.MAX_VALUE }
                    .thenByDescending { it.lastVerifiedAt }
                    .thenByDescending { it.score }
                    .thenBy { if (it.ping >= 0) it.ping else Int.MAX_VALUE }
            )
        }

        private fun resolvePublicHostAddress(host: String): InetAddress? {
            val sysPublic = try {
                InetAddress.getAllByName(host)
                    .firstOrNull { TunnelPackets.isPublicRoutableIpv4(it) }
            } catch (_: Exception) {
                null
            }
            if (sysPublic != null) return sysPublic

            val encryptedResolved = try {
                DnsOverTlsClient(
                    resolver = DnsResolver.CLOUDFLARE,
                    connectTimeoutMs = 3000,
                    readTimeoutMs = 3000,
                    enableDohFallback = true
                ).resolvePublicIpv4(host)
            } catch (_: Exception) {
                null
            }
            if (encryptedResolved != null) return encryptedResolved

            // Emergency Hardcoded Anycast Mapping for Core Mirror Domains during Total DNS Blackout
            val emergencyIp = when (host.lowercase()) {
                "www.vpngate.net", "vpngate.net" -> "219.100.37.121"
                "vpngate.opengw.net" -> "219.100.37.95"
                "cdn.jsdelivr.net" -> "104.16.85.20"
                "raw.githubusercontent.com" -> "185.199.108.133"
                else -> null
            }
            if (emergencyIp != null) {
                try {
                    return InetAddress.getByName(emergencyIp)
                } catch (_: Exception) {}
            }

            return try {
                InetAddress.getAllByName(host).firstOrNull { it is Inet4Address } ?: InetAddress.getByName(host)
            } catch (_: Exception) {
                null
            }
        }

        internal val DEFAULT_MIRROR_BYPASS_CANDIDATES = listOf(
            MirrorBypassCandidate("ADAPTIVE_HYBRID_DESYNC:1", SniStrategy.ADAPTIVE_HYBRID_DESYNC, 1),
            MirrorBypassCandidate("ZAPRET_SPLIT1_DESYNC:1", SniStrategy.ZAPRET_SPLIT1_DESYNC, 1),
            MirrorBypassCandidate("TLS_HEADER_DESYNC:2", SniStrategy.TLS_HEADER_DESYNC, 2),
            MirrorBypassCandidate("MULTI_CHUNK_FRAGMENTATION:16", SniStrategy.MULTI_CHUNK_FRAGMENTATION, 16),
            MirrorBypassCandidate("WINDOW_ALPN_MICRO_DESYNC:2", SniStrategy.WINDOW_ALPN_MICRO_DESYNC, 2),
            MirrorBypassCandidate("TLS_RECORD_FRAGMENTATION:40", SniStrategy.TLS_RECORD_FRAGMENTATION, 40),
            MirrorBypassCandidate("TCP_FRAGMENTATION:40", SniStrategy.TCP_FRAGMENTATION, 40),
            MirrorBypassCandidate("TCP_FRAGMENTATION:3", SniStrategy.TCP_FRAGMENTATION, 3),
            MirrorBypassCandidate("DIRECT_IP_NO_SNI:0", SniStrategy.DIRECT_IP_NO_SNI, 0)
        )

        internal fun buildOrderedBypassCandidates(preferredKey: String?): List<MirrorBypassCandidate> {
            val match = preferredKey?.takeIf { it.isNotBlank() }?.let { key ->
                DEFAULT_MIRROR_BYPASS_CANDIDATES.firstOrNull { it.key == key }
            }
            return if (match == null) {
                DEFAULT_MIRROR_BYPASS_CANDIDATES
            } else {
                listOf(match) + DEFAULT_MIRROR_BYPASS_CANDIDATES.filter { it.key != match.key }
            }
        }

        internal fun parseHttpResponse(input: InputStream): HttpRawResponse? {
            val headerAccum = ByteArrayOutputStream()
            val buf = ByteArray(4096)
            var sepIdx = -1
            var rawHeadersAndTail = ByteArray(0)

            while (headerAccum.size() < 32768) {
                val n = input.read(buf)
                if (n <= 0) break
                headerAccum.write(buf, 0, n)
                rawHeadersAndTail = headerAccum.toByteArray()
                sepIdx = indexOfHeaderEnd(rawHeadersAndTail)
                if (sepIdx >= 0) break
            }
            if (sepIdx < 0) return null

            val headerText = String(rawHeadersAndTail, 0, sepIdx, Charsets.ISO_8859_1)
            val lines = headerText.split("\r\n")
            if (lines.isEmpty()) return null
            val statusCode = lines[0].trim().split(Regex("\\s+")).getOrNull(1)?.toIntOrNull() ?: return null

            var location: String? = null
            var contentLength = -1L
            var isChunked = false
            for (i in 1 until lines.size) {
                val colon = lines[i].indexOf(':')
                if (colon <= 0) continue
                val name = lines[i].substring(0, colon).trim().lowercase()
                val value = lines[i].substring(colon + 1).trim()
                when (name) {
                    "location" -> location = value
                    "content-length" -> contentLength = value.toLongOrNull() ?: -1L
                    "transfer-encoding" -> if (value.contains("chunked", ignoreCase = true)) isChunked = true
                }
            }

            val tailOffset = sepIdx + 4
            val tail = if (tailOffset < rawHeadersAndTail.size) {
                rawHeadersAndTail.copyOfRange(tailOffset, rawHeadersAndTail.size)
            } else {
                ByteArray(0)
            }
            val bodyStream = SequenceInputStream(ByteArrayInputStream(tail), input)

            val body = when {
                isChunked -> decodeChunkedBody(bodyStream)
                contentLength >= 0 -> readUpToLength(bodyStream, contentLength)
                else -> bodyStream.readBytes()
            }
            return HttpRawResponse(statusCode = statusCode, location = location, body = body)
        }

        private fun indexOfHeaderEnd(data: ByteArray): Int {
            for (i in 0..data.size - 4) {
                if (data[i] == '\r'.code.toByte() &&
                    data[i + 1] == '\n'.code.toByte() &&
                    data[i + 2] == '\r'.code.toByte() &&
                    data[i + 3] == '\n'.code.toByte()
                ) {
                    return i
                }
            }
            return -1
        }

        private fun decodeChunkedBody(input: InputStream): ByteArray {
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            while (true) {
                val sizeLine = readAsciiLine(input) ?: break
                val sizeHex = sizeLine.substringBefore(';').trim()
                if (sizeHex.isEmpty()) continue
                val chunkSize = sizeHex.toIntOrNull(16) ?: break
                if (chunkSize == 0) break
                var remaining = chunkSize
                while (remaining > 0) {
                    val toRead = minOf(buf.size, remaining)
                    val n = input.read(buf, 0, toRead)
                    if (n <= 0) break
                    out.write(buf, 0, n)
                    remaining -= n
                }
                readAsciiLine(input) // consume trailing CRLF after chunk payload
            }
            return out.toByteArray()
        }

        private fun readAsciiLine(input: InputStream): String? {
            val sb = StringBuilder()
            var readAny = false
            while (true) {
                val b = input.read()
                if (b == -1) return if (readAny) sb.toString() else null
                readAny = true
                if (b == '\n'.code) break
                if (b != '\r'.code) sb.append(b.toChar())
            }
            return sb.toString()
        }

        private fun readUpToLength(input: InputStream, contentLength: Long): ByteArray {
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            var remaining = contentLength
            while (remaining > 0) {
                val toRead = minOf(buf.size.toLong(), remaining).toInt()
                val n = input.read(buf, 0, toRead)
                if (n <= 0) break
                out.write(buf, 0, n)
                remaining -= n
            }
            return out.toByteArray()
        }
    }
}

