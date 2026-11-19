package com.aethervpn.vpncore.transport

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.io.EOFException
import java.net.ConnectException
import java.net.InetAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLException

enum class FilterClassification(val summaryKey: String) {
    OPEN_NO_FILTER("OPEN_NO_FILTER"),
    SNI_DPI_ACTIVE("SNI_DPI_ACTIVE"),
    DEEP_CLIENTHELLO_DPI("DEEP_CLIENTHELLO_DPI"),
    SNI_ALLOWLIST_FILTER("SNI_ALLOWLIST_FILTER"),
    IP_OR_PORT_BLOCKED("IP_OR_PORT_BLOCKED"),
    UNKNOWN("UNKNOWN")
}

data class StrategyProbeResult(
    val strategy: SniStrategy,
    val succeeded: Boolean,
    val latencyMs: Long,
    val detail: String
)

data class CensorshipDiagnosis(
    val targetHost: String,
    val targetIp: String,
    val port: Int,
    val networkProfile: String,
    val classification: FilterClassification,
    val recommendedStrategy: SniStrategy?,
    val dnsPoisoningDetected: Boolean? = null,
    val results: List<StrategyProbeResult> = emptyList(),
    val timestampMs: Long = System.currentTimeMillis()
)

interface BypassProbeExecutor {
    fun checkTcpReachable(ipAddress: InetAddress, port: Int, timeoutMs: Int): Boolean
    fun testTlsStrategy(
        strategy: SniStrategy,
        host: String,
        ipAddress: InetAddress,
        port: Int,
        customSni: String?,
        strictCert: Boolean,
        timeoutMs: Int
    ): String?
    fun abortPending() {}
}

class LiveBypassProbeExecutor(
    private val socketProtector: SocketProtector? = null
) : BypassProbeExecutor {

    private val activeSockets = ConcurrentHashMap.newKeySet<Socket>()

    override fun abortPending() {
        val iterator = activeSockets.iterator()
        while (iterator.hasNext()) {
            val sock = iterator.next()
            iterator.remove()
            try { sock.close() } catch (_: Exception) {}
        }
    }

    override fun checkTcpReachable(ipAddress: InetAddress, port: Int, timeoutMs: Int): Boolean {
        return try {
            openProtectedTcpSocket(
                ipAddress = ipAddress,
                port = port,
                connectTimeoutMs = timeoutMs,
                readTimeoutMs = timeoutMs,
                socketProtector = socketProtector
            ).use { true }
        } catch (_: Exception) {
            false
        }
    }

    override fun testTlsStrategy(
        strategy: SniStrategy,
        host: String,
        ipAddress: InetAddress,
        port: Int,
        customSni: String?,
        strictCert: Boolean,
        timeoutMs: Int
    ): String? {
        var transport: SstpTransport? = null
        var createdSocket: Socket? = null
        return try {
            transport = SniBypassSocketFactory(
                strategy = strategy,
                customSni = customSni,
                strictCert = strictCert,
                socketProtector = socketProtector,
                onSocketCreated = { sock ->
                    createdSocket = sock
                    activeSockets.add(sock)
                }
            ).createAndConnectTransport(
                host = host,
                ipAddress = ipAddress,
                port = port,
                timeoutMs = timeoutMs
            )
            null
        } catch (e: SocketTimeoutException) {
            "Timeout"
        } catch (e: EOFException) {
            "TLS EOF"
        } catch (e: ConnectException) {
            "Refused"
        } catch (e: NoRouteToHostException) {
            "No route"
        } catch (e: SSLException) {
            e.message?.take(40) ?: "TLS reset"
        } catch (e: Exception) {
            val msg = e.message.orEmpty()
            when {
                msg.contains("reset", ignoreCase = true) -> "TCP RST"
                msg.contains("timed out", ignoreCase = true) -> "Timeout"
                else -> msg.take(40).ifBlank { e.javaClass.simpleName }
            }
        } finally {
            createdSocket?.let { activeSockets.remove(it) }
            try { transport?.close() } catch (_: Exception) {}
        }
    }
}

/**
 * Automatically probes the active network's censorship behavior (IP block vs SNI DPI vs
 * deep ClientHello DPI vs allowlisted SNI) and picks the fastest working bypass strategy.
 */
object CensorshipDetector {

    suspend fun detectBestStrategy(
        host: String,
        ipAddress: InetAddress,
        port: Int,
        networkProfile: String,
        preferredStrategy: SniStrategy? = null,
        customSni: String? = null,
        strictCert: Boolean = false,
        socketProtector: SocketProtector? = null,
        stopOnFirstWinner: Boolean = true,
        includeDirectProbe: Boolean = true,
        tcpTimeoutMs: Int = 2500,
        probeTimeoutMs: Int = 3800,
        dnsPoisoningDetected: Boolean? = null,
        executor: BypassProbeExecutor = LiveBypassProbeExecutor(socketProtector)
    ): CensorshipDiagnosis = withContext(Dispatchers.IO) {
        val tcpOk = executor.checkTcpReachable(ipAddress, port, tcpTimeoutMs)
        if (!tcpOk) {
            return@withContext CensorshipDiagnosis(
                targetHost = host,
                targetIp = ipAddress.hostAddress.orEmpty(),
                port = port,
                networkProfile = networkProfile,
                classification = FilterClassification.IP_OR_PORT_BLOCKED,
                recommendedStrategy = null,
                dnsPoisoningDetected = dnsPoisoningDetected,
                results = listOf(
                    StrategyProbeResult(
                        strategy = SniStrategy.DISABLED,
                        succeeded = false,
                        latencyMs = tcpTimeoutMs.toLong(),
                        detail = "TCP unreachable"
                    )
                )
            )
        }

        val hasCustomSni = !customSni.isNullOrBlank()
        val isCellular = networkProfile.contains("CELLULAR", ignoreCase = true) ||
            networkProfile.contains("MOBILE", ignoreCase = true)
        val wave1 = buildList {
            if (preferredStrategy != null &&
                preferredStrategy.isConcreteTransport &&
                (includeDirectProbe || preferredStrategy != SniStrategy.DISABLED)
            ) {
                add(preferredStrategy)
            }
            if (includeDirectProbe && !isCellular) {
                add(SniStrategy.DISABLED)
            }
            add(SniStrategy.ADAPTIVE_HYBRID_DESYNC)
            add(SniStrategy.IRAN_ALLOWLIST_SNI_FRAGMENT)
            add(SniStrategy.ZAPRET_SPLIT1_DESYNC)
            add(SniStrategy.TLS_HEADER_DESYNC)
            add(SniStrategy.MULTI_CHUNK_FRAGMENTATION)
            if (!isCellular) {
                add(SniStrategy.DIRECT_IP_NO_SNI)
            }
        }.distinct()

        val allOrdered = buildList {
            if (includeDirectProbe && !isCellular) {
                add(SniStrategy.DISABLED)
            }
            addAll(SniStrategy.concreteFallbackOrder(preferredStrategy, hasCustomSni, isCellular))
        }.filter { (includeDirectProbe && !isCellular) || it != SniStrategy.DISABLED }
            .distinct()
        val wave2 = allOrdered.filter { it !in wave1 }

        val collected = ArrayList<StrategyProbeResult>(allOrdered.size)

        if (stopOnFirstWinner) {
            val winner1 = raceWaveForFirstWinner(
                strategies = wave1,
                host = host,
                ipAddress = ipAddress,
                port = port,
                customSni = customSni,
                strictCert = strictCert,
                timeoutMs = probeTimeoutMs,
                executor = executor,
                sink = collected
            )
            if (winner1 == null && wave2.isNotEmpty()) {
                raceWaveForFirstWinner(
                    strategies = wave2,
                    host = host,
                    ipAddress = ipAddress,
                    port = port,
                    customSni = customSni,
                    strictCert = strictCert,
                    timeoutMs = probeTimeoutMs,
                    executor = executor,
                    sink = collected
                )
            }
        } else {
            collected.addAll(
                runWaveCollectAll(wave1, host, ipAddress, port, customSni, strictCert, probeTimeoutMs, executor)
            )
            if (wave2.isNotEmpty()) {
                collected.addAll(
                    runWaveCollectAll(wave2, host, ipAddress, port, customSni, strictCert, probeTimeoutMs, executor)
                )
            }
        }

        val classification = classifyResults(tcpReachable = true, results = collected)
        val recommended = pickBestPassingStrategy(collected, preferredStrategy)
        CensorshipDiagnosis(
            targetHost = host,
            targetIp = ipAddress.hostAddress.orEmpty(),
            port = port,
            networkProfile = networkProfile,
            classification = classification,
            recommendedStrategy = recommended,
            dnsPoisoningDetected = dnsPoisoningDetected,
            results = collected
        )
    }

    private suspend fun raceWaveForFirstWinner(
        strategies: List<SniStrategy>,
        host: String,
        ipAddress: InetAddress,
        port: Int,
        customSni: String?,
        strictCert: Boolean,
        timeoutMs: Int,
        executor: BypassProbeExecutor,
        sink: MutableList<StrategyProbeResult>
    ): StrategyProbeResult? = coroutineScope {
        if (strategies.isEmpty()) return@coroutineScope null
        val channel = Channel<StrategyProbeResult>(strategies.size)
        for (strategy in strategies) {
            async(Dispatchers.IO) {
                val res = probeSingle(strategy, host, ipAddress, port, customSni, strictCert, timeoutMs, executor)
                channel.trySend(res)
            }
        }
        var winner: StrategyProbeResult? = null
        repeat(strategies.size) {
            val res = channel.receive()
            sink.add(res)
            if (res.succeeded) {
                winner = res
                executor.abortPending()
                coroutineContext.cancelChildren()
                channel.close()
                return@coroutineScope winner
            }
        }
        channel.close()
        null
    }

    private suspend fun runWaveCollectAll(
        strategies: List<SniStrategy>,
        host: String,
        ipAddress: InetAddress,
        port: Int,
        customSni: String?,
        strictCert: Boolean,
        timeoutMs: Int,
        executor: BypassProbeExecutor
    ): List<StrategyProbeResult> = coroutineScope {
        strategies.map { strategy ->
            async(Dispatchers.IO) {
                probeSingle(strategy, host, ipAddress, port, customSni, strictCert, timeoutMs, executor)
            }
        }.awaitAll()
    }

    private fun probeSingle(
        strategy: SniStrategy,
        host: String,
        ipAddress: InetAddress,
        port: Int,
        customSni: String?,
        strictCert: Boolean,
        timeoutMs: Int,
        executor: BypassProbeExecutor
    ): StrategyProbeResult {
        val start = System.currentTimeMillis()
        val failure = try {
            executor.testTlsStrategy(strategy, host, ipAddress, port, customSni, strictCert, timeoutMs)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            e.message?.take(40) ?: e.javaClass.simpleName
        }
        val elapsed = (System.currentTimeMillis() - start).coerceAtLeast(1L)
        return StrategyProbeResult(
            strategy = strategy,
            succeeded = failure == null,
            latencyMs = elapsed,
            detail = failure ?: "OK (${elapsed}ms)"
        )
    }

    fun classifyResults(
        tcpReachable: Boolean,
        results: List<StrategyProbeResult>
    ): FilterClassification {
        if (!tcpReachable) return FilterClassification.IP_OR_PORT_BLOCKED
        val passing = results.filter { it.succeeded }.map { it.strategy }.toSet()
        if (passing.isEmpty()) return FilterClassification.UNKNOWN
        if (SniStrategy.DISABLED in passing) return FilterClassification.OPEN_NO_FILTER
        if (SniStrategy.DIRECT_IP_NO_SNI in passing ||
            SniStrategy.TCP_FRAGMENTATION in passing ||
            SniStrategy.TLS_RECORD_FRAGMENTATION in passing
        ) {
            return FilterClassification.SNI_DPI_ACTIVE
        }
        if (SniStrategy.MULTI_CHUNK_FRAGMENTATION in passing ||
            SniStrategy.TLS_HEADER_DESYNC in passing ||
            SniStrategy.WINDOW_ALPN_MICRO_DESYNC in passing ||
            SniStrategy.ZAPRET_SPLIT1_DESYNC in passing ||
            SniStrategy.ADAPTIVE_HYBRID_DESYNC in passing
        ) {
            return FilterClassification.DEEP_CLIENTHELLO_DPI
        }
        if (SniStrategy.IRAN_ALLOWLIST_SNI_FRAGMENT in passing ||
            SniStrategy.DECOY_SNI_FRAGMENT in passing ||
            SniStrategy.CUSTOM_SNI in passing
        ) {
            return FilterClassification.SNI_ALLOWLIST_FILTER
        }
        return FilterClassification.UNKNOWN
    }

    fun pickBestPassingStrategy(
        results: List<StrategyProbeResult>,
        preferredStrategy: SniStrategy? = null
    ): SniStrategy? {
        val passing = results.filter { it.succeeded }
        if (passing.isEmpty()) return null
        passing.firstOrNull { it.strategy == SniStrategy.DISABLED }?.let { return it.strategy }
        val fastest = passing.minBy { it.latencyMs }
        if (preferredStrategy != null) {
            val prefRes = passing.firstOrNull { it.strategy == preferredStrategy }
            if (prefRes != null && prefRes.latencyMs <= fastest.latencyMs + 150L) {
                return prefRes.strategy
            }
        }
        return fastest.strategy
    }
}
