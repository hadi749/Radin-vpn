package com.aethervpn.vpncore.transport

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class CensorshipDetectorTest {

    private class FakeProbeExecutor(
        private val tcpReachable: Boolean,
        private val passingStrategies: Set<SniStrategy> = emptySet(),
        private val latencyByStrategy: Map<SniStrategy, Long> = emptyMap()
    ) : BypassProbeExecutor {
        var tlsProbeCount = 0

        override fun checkTcpReachable(ipAddress: InetAddress, port: Int, timeoutMs: Int): Boolean =
            tcpReachable

        override fun testTlsStrategy(
            strategy: SniStrategy,
            host: String,
            ipAddress: InetAddress,
            port: Int,
            customSni: String?,
            strictCert: Boolean,
            timeoutMs: Int
        ): String? {
            tlsProbeCount++
            val sleepMs = latencyByStrategy[strategy] ?: 10L
            if (sleepMs > 0) Thread.sleep(sleepMs)
            return if (strategy in passingStrategies) null else "TCP RST"
        }
    }

    @Test
    fun shortCircuitsImmediatelyWhenTcpPortIsBlocked() = runBlocking {
        val executor = FakeProbeExecutor(tcpReachable = false, passingStrategies = setOf(SniStrategy.DIRECT_IP_NO_SNI))
        val diagnosis = CensorshipDetector.detectBestStrategy(
            host = "blocked.opengw.net",
            ipAddress = InetAddress.getByName("198.51.100.10"),
            port = 443,
            networkProfile = "CELLULAR",
            executor = executor
        )

        assertEquals(FilterClassification.IP_OR_PORT_BLOCKED, diagnosis.classification)
        assertNull(diagnosis.recommendedStrategy)
        assertEquals(0, executor.tlsProbeCount)
    }

    @Test
    fun detectsDeepClientHelloDpiAndSelectsMultiChunkFragmentation() = runBlocking {
        val executor = FakeProbeExecutor(
            tcpReachable = true,
            passingStrategies = setOf(SniStrategy.MULTI_CHUNK_FRAGMENTATION)
        )
        val diagnosis = CensorshipDetector.detectBestStrategy(
            host = "test.opengw.net",
            ipAddress = InetAddress.getByName("203.0.113.5"),
            port = 443,
            networkProfile = "WIFI",
            stopOnFirstWinner = false,
            executor = executor
        )

        assertEquals(FilterClassification.DEEP_CLIENTHELLO_DPI, diagnosis.classification)
        assertEquals(SniStrategy.MULTI_CHUNK_FRAGMENTATION, diagnosis.recommendedStrategy)
        assertTrue(diagnosis.results.any { it.strategy == SniStrategy.DISABLED && !it.succeeded })
        assertTrue(diagnosis.results.any { it.strategy == SniStrategy.MULTI_CHUNK_FRAGMENTATION && it.succeeded })
    }

    @Test
    fun detectsSniAllowlistFilterWhenOnlyDecoySniSucceeds() = runBlocking {
        val executor = FakeProbeExecutor(
            tcpReachable = true,
            passingStrategies = setOf(SniStrategy.DECOY_SNI_FRAGMENT)
        )
        val diagnosis = CensorshipDetector.detectBestStrategy(
            host = "test.opengw.net",
            ipAddress = InetAddress.getByName("203.0.113.7"),
            port = 443,
            networkProfile = "CELLULAR",
            stopOnFirstWinner = true,
            executor = executor
        )

        assertEquals(FilterClassification.SNI_ALLOWLIST_FILTER, diagnosis.classification)
        assertEquals(SniStrategy.DECOY_SNI_FRAGMENT, diagnosis.recommendedStrategy)
    }

    @Test
    fun prefersDirectWhenNoFilterIsActive() = runBlocking {
        val executor = FakeProbeExecutor(
            tcpReachable = true,
            passingStrategies = setOf(
                SniStrategy.DISABLED,
                SniStrategy.DIRECT_IP_NO_SNI,
                SniStrategy.MULTI_CHUNK_FRAGMENTATION
            ),
            latencyByStrategy = mapOf(
                SniStrategy.DISABLED to 25L,
                SniStrategy.DIRECT_IP_NO_SNI to 15L,
                SniStrategy.MULTI_CHUNK_FRAGMENTATION to 35L
            )
        )
        val diagnosis = CensorshipDetector.detectBestStrategy(
            host = "open.opengw.net",
            ipAddress = InetAddress.getByName("203.0.113.8"),
            port = 443,
            networkProfile = "WIFI",
            stopOnFirstWinner = false,
            executor = executor
        )

        assertEquals(FilterClassification.OPEN_NO_FILTER, diagnosis.classification)
        assertEquals(SniStrategy.DISABLED, diagnosis.recommendedStrategy)
    }

    @Test
    fun classifiesTlsHeaderDesyncAsDeepClientHelloDpi() = runBlocking {
        val executor = FakeProbeExecutor(
            tcpReachable = true,
            passingStrategies = setOf(SniStrategy.TLS_HEADER_DESYNC)
        )
        val diagnosis = CensorshipDetector.detectBestStrategy(
            host = "strict-header-dpi.opengw.net",
            ipAddress = InetAddress.getByName("203.0.113.9"),
            port = 443,
            networkProfile = "CELLULAR",
            stopOnFirstWinner = true,
            executor = executor
        )

        assertEquals(FilterClassification.DEEP_CLIENTHELLO_DPI, diagnosis.classification)
        assertEquals(SniStrategy.TLS_HEADER_DESYNC, diagnosis.recommendedStrategy)
    }

    @Test
    fun skipsDirectProbeWhenDirectSstpAlreadyFailed() = runBlocking {
        val executor = FakeProbeExecutor(
            tcpReachable = true,
            passingStrategies = setOf(
                SniStrategy.DISABLED,
                SniStrategy.TLS_HEADER_DESYNC
            )
        )
        val diagnosis = CensorshipDetector.detectBestStrategy(
            host = "post-direct.opengw.net",
            ipAddress = InetAddress.getByName("203.0.113.10"),
            port = 443,
            networkProfile = "WIFI",
            preferredStrategy = SniStrategy.DISABLED,
            stopOnFirstWinner = false,
            includeDirectProbe = false,
            executor = executor
        )

        assertTrue(diagnosis.results.none { it.strategy == SniStrategy.DISABLED })
        assertEquals(SniStrategy.TLS_HEADER_DESYNC, diagnosis.recommendedStrategy)
    }

    @Test
    fun selectsWindowAlpnMicroDesyncInWave2WhenShallowBypassStrategiesFail() = runBlocking {
        val executor = FakeProbeExecutor(
            tcpReachable = true,
            passingStrategies = setOf(SniStrategy.WINDOW_ALPN_MICRO_DESYNC)
        )
        val diagnosis = CensorshipDetector.detectBestStrategy(
            host = "stateful-dpi.opengw.net",
            ipAddress = InetAddress.getByName("203.0.113.11"),
            port = 443,
            networkProfile = "CELLULAR",
            stopOnFirstWinner = true,
            executor = executor
        )

        assertEquals(FilterClassification.DEEP_CLIENTHELLO_DPI, diagnosis.classification)
        assertEquals(SniStrategy.WINDOW_ALPN_MICRO_DESYNC, diagnosis.recommendedStrategy)
    }

    @Test
    fun classifiesZapretSplit1AsDeepClientHelloDpi() = runBlocking {
        val executor = FakeProbeExecutor(
            tcpReachable = true,
            passingStrategies = setOf(SniStrategy.ZAPRET_SPLIT1_DESYNC)
        )
        val diagnosis = CensorshipDetector.detectBestStrategy(
            host = "zapret-dpi.opengw.net",
            ipAddress = InetAddress.getByName("203.0.113.12"),
            port = 443,
            networkProfile = "CELLULAR",
            stopOnFirstWinner = true,
            executor = executor
        )

        assertEquals(FilterClassification.DEEP_CLIENTHELLO_DPI, diagnosis.classification)
        assertEquals(SniStrategy.ZAPRET_SPLIT1_DESYNC, diagnosis.recommendedStrategy)
    }

    @Test
    fun classifiesAdaptiveHybridAsDeepClientHelloDpiAndRotatesDecoySnis() = runBlocking {
        val executor = FakeProbeExecutor(
            tcpReachable = true,
            passingStrategies = setOf(SniStrategy.ADAPTIVE_HYBRID_DESYNC)
        )
        val diagnosis = CensorshipDetector.detectBestStrategy(
            host = "hybrid-dpi.opengw.net",
            ipAddress = InetAddress.getByName("203.0.113.13"),
            port = 443,
            networkProfile = "CELLULAR_MCI",
            stopOnFirstWinner = true,
            executor = executor
        )

        assertEquals(FilterClassification.DEEP_CLIENTHELLO_DPI, diagnosis.classification)
        assertEquals(SniStrategy.ADAPTIVE_HYBRID_DESYNC, diagnosis.recommendedStrategy)

        val picked = (0 until SniStrategy.DEFAULT_DECOY_SNIS.size)
            .map { SniStrategy.pickDecoySni(it) }
            .toSet()
        assertEquals(SniStrategy.DEFAULT_DECOY_SNIS.toSet(), picked)
    }

    @Test
    fun detectsSniAllowlistFilterWithIranAllowlistSniFragment() = runBlocking {
        val executor = FakeProbeExecutor(
            tcpReachable = true,
            passingStrategies = setOf(SniStrategy.IRAN_ALLOWLIST_SNI_FRAGMENT)
        )
        val diagnosis = CensorshipDetector.detectBestStrategy(
            host = "allowlist-dpi.opengw.net",
            ipAddress = InetAddress.getByName("203.0.113.14"),
            port = 443,
            networkProfile = "CELLULAR_IRANCELL",
            stopOnFirstWinner = true,
            executor = executor
        )

        assertEquals(FilterClassification.SNI_ALLOWLIST_FILTER, diagnosis.classification)
        assertEquals(SniStrategy.IRAN_ALLOWLIST_SNI_FRAGMENT, diagnosis.recommendedStrategy)

        val pickedWhitelist = (0 until SniStrategy.IRAN_WHITELIST_SNIS.size)
            .map { SniStrategy.pickIranWhitelistSni(it) }
            .toSet()
        assertEquals(SniStrategy.IRAN_WHITELIST_SNIS.toSet(), pickedWhitelist)
    }
}


