package com.aethervpn.client.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.room.Room
import com.aethervpn.client.BuildConfig
import com.aethervpn.client.R
import com.aethervpn.client.data.datastore.DnsMode
import com.aethervpn.client.data.datastore.PreferencesManager
import com.aethervpn.client.data.datastore.SplitTunnelMode
import com.aethervpn.client.data.datastore.UserSettings
import com.aethervpn.client.data.datastore.VpnProtocol
import com.aethervpn.client.data.local.AppDatabase
import com.aethervpn.client.data.model.VpnServer
import com.aethervpn.client.data.repository.ServerRepository
import com.aethervpn.client.data.routing.IranRoutingRules
import com.aethervpn.client.ui.MainActivity
import com.aethervpn.vpncore.dns.DnsOverTlsClient
import com.aethervpn.vpncore.dns.DnsPacketCodec
import com.aethervpn.vpncore.dns.DnsResolver
import com.aethervpn.vpncore.dns.DnsResponseCache
import com.aethervpn.vpncore.dns.ParsedUdpDnsPacket
import com.aethervpn.vpncore.softether.SoftEtherClient
import com.aethervpn.vpncore.softether.SoftEtherConfig
import com.aethervpn.vpncore.softether.SoftEtherEventListener
import com.aethervpn.vpncore.softether.SoftEtherState
import com.aethervpn.vpncore.softether.SoftEtherVpnParameters
import com.aethervpn.vpncore.sstp.SstpClient
import com.aethervpn.vpncore.sstp.SstpConfig
import com.aethervpn.vpncore.sstp.SstpEventListener
import com.aethervpn.vpncore.sstp.SstpState
import com.aethervpn.vpncore.sstp.VpnParameters
import com.aethervpn.vpncore.transport.CensorshipDetector
import com.aethervpn.vpncore.transport.FilterClassification
import com.aethervpn.vpncore.transport.MultiServerRacer
import com.aethervpn.vpncore.transport.RaceCandidate
import com.aethervpn.vpncore.transport.SniStrategy
import com.aethervpn.vpncore.transport.SocketProtector
import com.aethervpn.vpncore.transport.TunnelClient
import com.aethervpn.vpncore.tun.Ipv4Cidr
import com.aethervpn.vpncore.tun.MssClamper
import com.aethervpn.vpncore.tun.TunnelPackets
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Foreground Android VpnService hosting the SSTP tunnel, smart internet verification,
 * traffic stall watchdog, blackhole failover, DoT/DoH DNS handling, and QUIC fallback.
 */
class AetherVpnService : VpnService(), SstpEventListener, SocketProtector {

    companion object {
        const val ACTION_CONNECT = "com.aethervpn.client.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "com.aethervpn.client.ACTION_DISCONNECT"
        const val EXTRA_SERVER_HOST = "extra_server_host"
        const val EXTRA_SERVER_IP = "extra_server_ip"
        const val EXTRA_SERVER_PORT = "extra_server_port"
        const val EXTRA_SERVER_USER = "extra_server_user"
        const val EXTRA_SERVER_PASS = "extra_server_pass"
        const val EXTRA_SERVER_COUNTRY = "extra_server_country"
        const val EXTRA_SERVER_IS_CUSTOM = "extra_server_is_custom"
        const val EXTRA_SERVER_SNI = "extra_server_sni"
        const val EXTRA_FORCE_PROTOCOL = "extra_force_protocol"
        const val EXTRA_FROM_AUTO_SMART = "extra_from_auto_smart"
        const val NOTIFICATION_ID = 1001
        const val CHANNEL_ID = "aether_vpn_channel"

        private const val DOT_WORKER_COUNT = 6
        private const val DNS_CHANNEL_CAPACITY = 64
        private const val MAX_FAILOVER_ATTEMPTS = 12
        private const val VERIFY_DNS_TIMEOUT_MS = 3800L
        private const val VERIFY_HTTP_TIMEOUT_MS = 3500L
        private const val DIRECT_SSTP_FIRST_TIMEOUT_MS = 2200
        private const val FAILOVER_HANDSHAKE_TIMEOUT_MS = 5500
        private const val DIRECT_DNS_TIMEOUT_MS = 1200
        private const val WATCHDOG_INTERVAL_MS = 15_000L
        private const val STALL_TX_THRESHOLD = 50L
        private const val STALL_CONSECUTIVE_LIMIT = 3
        private const val DNS_BUCKET_DIRECT = 1
        private const val DNS_BUCKET_TUNNEL = 2

        private val DNS_PROBE_CF = byteArrayOf(1, 1, 1, 1)
        private val DNS_PROBE_GOOGLE = byteArrayOf(8, 8, 8, 8)

        fun buildConnectIntent(
            context: Context,
            server: VpnServer,
            forceProtocolId: Int = -1,
            fromAutoSmart: Boolean = false
        ): Intent =
            Intent(context, AetherVpnService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_SERVER_HOST, server.hostName)
                putExtra(EXTRA_SERVER_IP, server.ip)
                putExtra(EXTRA_SERVER_PORT, server.customPort)
                putExtra(EXTRA_SERVER_USER, server.customUsername)
                putExtra(EXTRA_SERVER_PASS, server.customPassword)
                putExtra(EXTRA_SERVER_COUNTRY, server.countryLong)
                putExtra(EXTRA_SERVER_IS_CUSTOM, server.isCustom)
                putExtra(EXTRA_SERVER_SNI, server.customSni)
                putExtra(EXTRA_FORCE_PROTOCOL, forceProtocolId)
                putExtra(EXTRA_FROM_AUTO_SMART, fromAutoSmart)
            }

        internal fun openServerDb(context: Context): AppDatabase = Room.databaseBuilder(
            context.applicationContext,
            AppDatabase::class.java,
            "aether_vpn.db"
        )
        .addMigrations(AppDatabase.MIGRATION_2_3)
        .fallbackToDestructiveMigration()
        .build()

        internal suspend fun findBestStoredServer(context: Context): VpnServer? {
            var db: AppDatabase? = null
            return try {
                db = openServerDb(context)
                val all = db.vpnServerDao().getAllServers().first()
                val sorted = ServerRepository.smartSortServers(all, System.currentTimeMillis())
                val best = sorted.firstOrNull {
                    !ServerRepository.isRestrictedAcademicSubnet(it.ip) &&
                        !ServerRepository.isCensoredCountry(it.countryShort)
                } ?: sorted.firstOrNull()

                if (best != null) return best

                // If DB is empty, populate from bundled fallback immediately
                try {
                    context.assets.open("vpngate_fallback.csv").use { stream ->
                        val parsed = com.aethervpn.client.data.source.VpnGateCsvParser.parse(stream)
                        if (parsed.isNotEmpty()) {
                            db.vpnServerDao().insertAll(parsed)
                            val fallbackSorted = ServerRepository.smartSortServers(parsed, System.currentTimeMillis())
                            fallbackSorted.firstOrNull {
                                !ServerRepository.isRestrictedAcademicSubnet(it.ip) &&
                                    !ServerRepository.isCensoredCountry(it.countryShort)
                            } ?: fallbackSorted.firstOrNull()
                        } else null
                    }
                } catch (_: Exception) {
                    null
                }
            } catch (_: Exception) {
                null
            } finally {
                try { db?.close() } catch (_: Exception) {}
            }
        }
    }

    private data class QueuedDnsQuery(
        val parsed: ParsedUdpDnsPacket,
        val isIranDomain: Boolean
    )

    private val dnsCache = DnsResponseCache(maxEntries = 1024, maxTtlSec = 1800L)

    private val serviceScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private val isRunning = AtomicBoolean(false)
    private val userStopRequested = AtomicBoolean(false)
    private val isFailoverTransition = AtomicBoolean(false)
    private val networkSwitchRequested = AtomicBoolean(false)
    private val callbackRegistered = AtomicBoolean(false)

    @Volatile
    private var activeGeneration: Long = 0L

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunOutputStream: FileOutputStream? = null
    private val tunWriteLock = Any()

    @Volatile
    private var activeTunnelClient: TunnelClient? = null
    private val sstpClient: SstpClient?
        get() = activeTunnelClient as? SstpClient
    @Volatile
    private var dotClient: DnsOverTlsClient? = null
    @Volatile
    private var activePhysicalNetwork: Network? = null
    @Volatile
    private var lastPhysicalNetwork: Network? = null
    private val availablePhysicalNetworks = java.util.concurrent.ConcurrentHashMap.newKeySet<Network>()
    @Volatile
    private var activeSettings: UserSettings = UserSettings()
    @Volatile
    private var currentServer: VpnServer? = null
    @Volatile
    private var currentStrategyName: String = ""
    @Volatile
    private var activeMtu: Int = 1400
    @Volatile
    private var activeSplitRuleCount: Int = 0
    @Volatile
    private var latestParams: VpnParameters? = null

    @Volatile
    private var attemptVerifiedInternet: Boolean = false
    @Volatile
    private var attemptFailureReason: String? = null
    @Volatile
    private var attemptForceAbortReason: String? = null
    @Volatile
    private var attemptStrategyUsed: SniStrategy? = null
    @Volatile
    private var currentAttemptProtocol: VpnProtocol = VpnProtocol.SOFTETHER_NATIVE

    private var sessionStartTime = 0L
    private val totalTxBytes = AtomicLong(0)
    private val totalRxBytes = AtomicLong(0)
    private val prevTxBytes = AtomicLong(0)
    private val prevRxBytes = AtomicLong(0)

    private var connectionJob: Job? = null
    private var verifyJob: Job? = null
    private var watchdogJob: Job? = null
    private var metricsJob: Job? = null
    private var tunReaderJob: Job? = null
    private val tunWorkerJobs = mutableListOf<Job>()
    private var dnsChannel: Channel<QueuedDnsQuery>? = null
    private var fetchPublicIpJob: Job? = null
    @Volatile
    private var activePublicIpCall: okhttp3.Call? = null

    private val pendingDnsProbes = ConcurrentHashMap<Int, CompletableDeferred<ByteArray>>()
    private val probePortCounter = AtomicInteger(54000)

    private val httpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(6, TimeUnit.SECONDS)
            .callTimeout(8, TimeUnit.SECONDS)
            .build()
    }

    private lateinit var connectivityManager: ConnectivityManager
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val caps = connectivityManager.getNetworkCapabilities(network) ?: return
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return

            availablePhysicalNetworks.add(network)
            val prev = activePhysicalNetwork
            val isHandoff = (prev != null && prev != network) || (lastPhysicalNetwork != null && lastPhysicalNetwork != network)
            activePhysicalNetwork = network
            lastPhysicalNetwork = network
            try {
                setUnderlyingNetworks(arrayOf(network))
            } catch (_: Exception) {}

            // Reconnect seamlessly on physical network handoff (e.g. Wi-Fi <-> Cellular)
            if (isHandoff &&
                isRunning.get() &&
                attemptVerifiedInternet &&
                activeSettings.autoFailover &&
                activeSettings.dnsMode != DnsMode.DNS_ONLY
            ) {
                VpnStateHolder.log("Physical network switched to $network; re-establishing tunnel...")
                networkSwitchRequested.set(true)
                serviceScope.launch(Dispatchers.IO) {
                    delay(250)
                    try { activeTunnelClient?.close() } catch (_: Exception) {}
                }
            }
        }

        override fun onLost(network: Network) {
            availablePhysicalNetworks.remove(network)
            lastPhysicalNetwork = network
            if (activePhysicalNetwork == network) {
                activePhysicalNetwork = null
                val fallback = availablePhysicalNetworks.firstOrNull()
                if (fallback != null) {
                    activePhysicalNetwork = fallback
                    lastPhysicalNetwork = fallback
                    try {
                        setUnderlyingNetworks(arrayOf(fallback))
                    } catch (_: Exception) {}
                    if (isRunning.get() &&
                        attemptVerifiedInternet &&
                        activeSettings.autoFailover &&
                        activeSettings.dnsMode != DnsMode.DNS_ONLY
                    ) {
                        VpnStateHolder.log("Physical network lost; switching seamlessly to fallback network ($fallback)...")
                        networkSwitchRequested.set(true)
                        serviceScope.launch(Dispatchers.IO) {
                            delay(200)
                            try { activeTunnelClient?.close() } catch (_: Exception) {}
                        }
                    }
                } else {
                    try {
                        setUnderlyingNetworks(null)
                    } catch (_: Exception) {}
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val host = intent.getStringExtra(EXTRA_SERVER_HOST) ?: return START_NOT_STICKY
                val ip = intent.getStringExtra(EXTRA_SERVER_IP) ?: host
                val port = intent.getIntExtra(EXTRA_SERVER_PORT, 443)
                val user = intent.getStringExtra(EXTRA_SERVER_USER) ?: "vpn"
                val pass = intent.getStringExtra(EXTRA_SERVER_PASS) ?: "vpn"
                val country = intent.getStringExtra(EXTRA_SERVER_COUNTRY) ?: ""
                val isCustom = intent.getBooleanExtra(EXTRA_SERVER_IS_CUSTOM, false)
                val customSni = intent.getStringExtra(EXTRA_SERVER_SNI)
                val forceProtocolId = intent.getIntExtra(EXTRA_FORCE_PROTOCOL, -1)
                val fromAutoSmart = intent.getBooleanExtra(EXTRA_FROM_AUTO_SMART, false)

                val server = VpnServer(
                    hostName = host,
                    ip = ip,
                    customPort = port,
                    customUsername = user,
                    customPassword = pass,
                    countryLong = country,
                    isCustom = isCustom,
                    customSni = customSni
                )
                val isRestricted = !isCustom && (ServerRepository.isRestrictedAcademicSubnet(ip) || ServerRepository.isCensoredCountry(country))
                if (isRestricted) {
                    VpnStateHolder.log("Target $ip is an academic blackhole or censored exit; redirecting to best commercial node...")
                    serviceScope.launch(Dispatchers.IO) {
                        val best = findBestStoredServer(this@AetherVpnService)
                        if (best != null && !ServerRepository.isRestrictedAcademicSubnet(best.ip) && !ServerRepository.isCensoredCountry(best.countryShort)) {
                            startVpn(best, forceProtocolId, fromAutoSmart)
                        } else {
                            startVpn(server, forceProtocolId, fromAutoSmart)
                        }
                    }
                } else {
                    startVpn(server, forceProtocolId, fromAutoSmart)
                }
            }
            ACTION_DISCONNECT -> {
                stopVpn()
            }
        }
        return START_NOT_STICKY
    }

    private fun startVpn(
        server: VpnServer,
        forceProtocolId: Int = -1,
        fromAutoSmart: Boolean = false
    ) {
        val generation = synchronized(this) { activeGeneration + 1L }.also {
            activeGeneration = it
        }
        val wasActive = isRunning.getAndSet(true)
        userStopRequested.set(false)
        isFailoverTransition.set(true)
        networkSwitchRequested.set(false)

        connectionJob?.cancel()
        connectionJob = null
        cleanupActiveTunnelOnly()

        currentServer = server
        sessionStartTime = System.currentTimeMillis()
        totalTxBytes.set(0)
        totalRxBytes.set(0)
        prevTxBytes.set(0)
        prevRxBytes.set(0)

        val label = server.countryLong.ifBlank { server.hostName }
        val notification = buildNotification("Connecting to $label...")
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            VpnStateHolder.log("Error starting foreground service: ${e.message}")
        }

        if (wasActive) {
            VpnStateHolder.updateSwitchingServer(server, "Switching server to $label...")
        } else {
            VpnStateHolder.log("Starting Radin VPN v${BuildConfig.VERSION_NAME} (Build ${BuildConfig.VERSION_CODE})")
            VpnStateHolder.updateStatus(VpnStatus.CONNECTING, "Connecting to $label...")
        }

        registerPhysicalNetworkMonitoring()
        requestTileRefresh()
        startMetricsReporting(generation)

        connectionJob = serviceScope.launch(Dispatchers.IO) {
            runConnectionLoop(server, generation, forceProtocolId, fromAutoSmart)
        }
    }

    private fun registerPhysicalNetworkMonitoring() {
        val initNet = connectivityManager.activeNetwork
        if (initNet != null) {
            val caps = connectivityManager.getNetworkCapabilities(initNet)
            if (caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
                activePhysicalNetwork = initNet
                lastPhysicalNetwork = initNet
                availablePhysicalNetworks.add(initNet)
                try {
                    setUnderlyingNetworks(arrayOf(initNet))
                } catch (_: Exception) {}
            }
        }

        if (callbackRegistered.compareAndSet(false, true)) {
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            try {
                connectivityManager.registerNetworkCallback(request, networkCallback)
            } catch (e: Exception) {
                callbackRegistered.set(false)
                VpnStateHolder.log("NetworkCallback registration warning: ${e.message}")
            }
        }
    }

    private suspend fun runConnectionLoop(
        initialServer: VpnServer,
        generation: Long,
        forceProtocolId: Int = -1,
        fromAutoSmart: Boolean = false
    ) {
        val prefManager = PreferencesManager(applicationContext)
        val settings = prefManager.settingsFlow.first()
        val effectiveProtocol = if (forceProtocolId >= 0) VpnProtocol.fromId(forceProtocolId) else settings.vpnProtocol
        activeSettings = settings

        if (settings.dnsMode != DnsMode.VPN_DEFAULT) {
            val resolver = DnsResolver.findById(settings.selectedDnsId)
            // DNS_ONLY protects DoT sockets outside TUN; DOT_OVER_SSTP routes DoT inside SSTP tunnel.
            val protector = if (settings.dnsMode == DnsMode.DNS_ONLY) this@AetherVpnService else null
            dotClient = DnsOverTlsClient(resolver = resolver, socketProtector = protector)
        }

        if (settings.dnsMode == DnsMode.DNS_ONLY) {
            try {
                isFailoverTransition.set(false)
                currentStrategyName = "DoT Only"
                val dnsParams = VpnParameters(
                    clientIp = "10.254.254.1",
                    gatewayIp = "10.254.254.254",
                    primaryDns = "10.254.254.254",
                    secondaryDns = "",
                    mtu = settings.mtu
                )
                establishTun(dnsParams, settings)
                VpnStateHolder.updateConnected(initialServer, "DNS-over-TLS Only", "DoT (${settings.selectedDnsId})")
                updateNotification("DNS-over-TLS Active (${settings.selectedDnsId})")
            } catch (e: Exception) {
                if (!userStopRequested.get() && activeGeneration == generation) {
                    VpnStateHolder.updateStatus(VpnStatus.ERROR, "DoT setup failed: ${e.message}")
                    stopVpn(preserveError = true)
                }
            }
            return
        }

        val learnedProfiles = settings.vpnBypassProfiles.toMutableMap()
        val sessionExcludedHosts = mutableSetOf<String>()
        val sessionFailedSubnets = mutableSetOf<String>()
        var preferredCandidate: VpnServer? = initialServer
        var consecutiveFailures = 0
        var totalAttempts = 0
        var recoveringSameLinkSwitch = false
        var directAttemptedOnCurrentLink = false

        val effectiveMaxFailures = if (effectiveProtocol == VpnProtocol.AUTO_SMART && !fromAutoSmart && !initialServer.isCustom) {
            minOf(MAX_FAILOVER_ATTEMPTS, 4)
        } else {
            MAX_FAILOVER_ATTEMPTS
        }

        while (currentCoroutineContext().isActive &&
            isRunning.get() &&
            !userStopRequested.get() &&
            activeGeneration == generation &&
            consecutiveFailures < effectiveMaxFailures
        ) {
            totalAttempts++
            resetAttemptFlags()
            cleanupActiveTunnelOnly()

            val isSoftEtherOrAuto = effectiveProtocol == VpnProtocol.SOFTETHER_NATIVE ||
                effectiveProtocol == VpnProtocol.AUTO_SMART
            val profileKey = resolvePhysicalNetworkProfileKey()
            val isCellular = profileKey.contains("CELLULAR", ignoreCase = true) ||
                profileKey.contains("MOBILE", ignoreCase = true)
            val tryDirectFirst = (settings.sniStrategy == SniStrategy.AUTO_SMART || isSoftEtherOrAuto) &&
                !isCellular &&
                !directAttemptedOnCurrentLink &&
                !recoveringSameLinkSwitch
            val shouldRacePool = !tryDirectFirst &&
                !initialServer.isCustom &&
                settings.autoFailover &&
                settings.sniStrategy == SniStrategy.AUTO_SMART &&
                !recoveringSameLinkSwitch
            recoveringSameLinkSwitch = false

            var candidate: VpnServer? = null
            var strategies: List<SniStrategy> = emptyList()

            if (tryDirectFirst) {
                directAttemptedOnCurrentLink = true
                val directTarget = nextCandidate(preferredCandidate, initialServer, sessionExcludedHosts, sessionFailedSubnets, settings)
                preferredCandidate = null
                if (directTarget == null) {
                    attemptFailureReason = "No reachable VPN servers remaining"
                    break
                }
                currentServer = directTarget
                val ranClient = connectDirectThenSmartBypassFallback(
                    candidate = directTarget,
                    settings = settings,
                    effectiveProtocol = effectiveProtocol,
                    profileKey = profileKey,
                    learnedProfiles = learnedProfiles,
                    generation = generation,
                    isReconnect = totalAttempts > 1
                )
                if (!isRunning.get() || userStopRequested.get() || activeGeneration != generation) {
                    return
                }
                if (handlePostAttemptOutcome(
                        candidate = directTarget,
                        initialServer = initialServer,
                        ranClient = ranClient,
                        settings = settings,
                        profileKey = profileKey,
                        learnedProfiles = learnedProfiles,
                        sessionExcludedHosts = sessionExcludedHosts,
                        sessionFailedSubnets = sessionFailedSubnets,
                        onResetFailures = { consecutiveFailures = 0 },
                        onIncrementFailure = { consecutiveFailures++ },
                        onLinkSwitch = {
                            preferredCandidate = directTarget
                            recoveringSameLinkSwitch = true
                            directAttemptedOnCurrentLink = false
                        },
                        onSameServerRecovery = {
                            preferredCandidate = if (directTarget.isCustom && it) directTarget else null
                        }
                    )
                ) {
                    continue
                } else {
                    break
                }
            }

            if (shouldRacePool) {
                val pool = selectRacePoolCandidates(
                    preferred = preferredCandidate,
                    excludedHosts = sessionExcludedHosts,
                    deprioritizedSubnets = sessionFailedSubnets,
                    maxCandidates = 3
                )
                preferredCandidate = null
                if (pool.size >= 2) {
                    VpnStateHolder.updateConnectPhase(ConnectPhase.RACING_BACKUP_SERVERS)
                    VpnStateHolder.updateLiveStatus("مسابقه همزمان بین ${pool.size} سرور پشتیبان پرسرعت...")
                    VpnStateHolder.updateStatus(
                        if (totalAttempts == 1) VpnStatus.CONNECTING else VpnStatus.RECONNECTING,
                        "Racing ${pool.size} backup servers [$profileKey]..."
                    )
                    updateNotification("Finding fastest open server...")

                    val raceCandidates = pool.flatMap { srv ->
                        val addr = try { InetAddress.getByName(srv.ip) } catch (_: Exception) { null }
                        if (addr == null) {
                            sessionExcludedHosts.add(srv.hostName)
                            emptyList()
                        } else {
                            val pref = (learnedProfiles[profileKey] ?: settings.lastVpnBypassStrategy)
                                .takeIf { it.isNotBlank() }
                                ?.let { key -> SniStrategy.entries.firstOrNull { it.name == key && it.isConcreteTransport } }
                            val candidatePorts = if (srv.isCustom) {
                                listOf(srv.customPort)
                            } else {
                                listOf(443, srv.customPort, 992, 5555)
                                    .filter { it in 1..65535 && it != 1723 && it != 500 && it != 4500 }
                                    .distinct()
                            }
                            candidatePorts.map { port ->
                                RaceCandidate(
                                    id = "${srv.hostName}#$port",
                                    host = srv.hostName,
                                    ipAddress = addr,
                                    port = port,
                                    preferredStrategy = pref,
                                    customSni = resolveEffectiveCustomSni(srv, settings)
                                )
                            }
                        }
                    }

                    if (raceCandidates.isNotEmpty()) {
                        val outcome = MultiServerRacer.raceCandidates(
                            candidates = raceCandidates,
                            networkProfile = profileKey,
                            strictCert = settings.strictCert,
                            socketProtector = this@AetherVpnService
                        )
                        val blockedBaseHosts = outcome.blockedCandidateIds.map { it.substringBefore('#') }.toSet()
                        val nonBlockedBaseHosts = (raceCandidates.map { it.id } - outcome.blockedCandidateIds).map { it.substringBefore('#') }.toSet()
                        val completelyBlockedHosts = blockedBaseHosts - nonBlockedBaseHosts
                        for (blockedHost in completelyBlockedHosts) {
                            sessionExcludedHosts.add(blockedHost)
                            pool.firstOrNull { it.hostName == blockedHost }?.let {
                                sessionExcludedHosts.add(it.ip)
                                sessionFailedSubnets.add(ServerRepository.subnet24(it.ip))
                            }
                            recordServerOutcome(blockedHost, verifiedSuccess = false)
                        }
                        val won = outcome.winner
                        val wonDiag = outcome.diagnosis
                        val wonStrategy = wonDiag?.recommendedStrategy
                        if (won != null && wonDiag != null && wonStrategy != null) {
                            val baseHost = won.id.substringBefore('#')
                            val wonPort = won.id.substringAfter('#', "").toIntOrNull() ?: won.port
                            val matched = pool.firstOrNull { it.hostName == baseHost }
                            candidate = matched?.copy(customPort = wonPort)
                            if (candidate != null && matched != null && wonPort != matched.customPort) {
                                serviceScope.launch(Dispatchers.IO) {
                                    runCatching {
                                        openServerDb().vpnServerDao().updatePort(baseHost, wonPort)
                                    }
                                }
                                VpnStateHolder.log("Multi-port race selected fast port $wonPort for $baseHost")
                            }
                            VpnStateHolder.updateDiagnosis(wonDiag)
                            VpnStateHolder.updateConnectPhase(
                                if (wonStrategy == SniStrategy.DISABLED) ConnectPhase.TRYING_DIRECT_SSTP else ConnectPhase.CONNECTING_WITH_BYPASS,
                                if (wonStrategy == SniStrategy.DISABLED) "" else wonStrategy.displayName
                            )
                            val winnerCountryFa = candidate?.let { VpnStateHolder.translateCountryToPersian(it.countryLong.ifBlank { it.countryShort }) } ?: "پشتیبان"
                            VpnStateHolder.updateLiveStatus("سرور برتر انتخاب شد: $winnerCountryFa (پورت $wonPort) • درحال برقراری تونل...")
                            val winLatency = wonDiag.results.firstOrNull { it.strategy == wonStrategy }?.latencyMs
                            VpnStateHolder.log(
                                "Race winner (${outcome.elapsedMs}ms): ${candidate?.countryLong.orEmpty().ifBlank { won.host }}:$wonPort " +
                                    "[${wonDiag.classification.summaryKey} -> ${wonStrategy.displayName}" +
                                    (if (winLatency != null) ", ${winLatency}ms" else "") + "]"
                            )
                            val hasCustomSni = !resolveEffectiveCustomSni(candidate ?: pool.first(), settings).isNullOrBlank()
                            strategies = buildList {
                                add(wonStrategy)
                                addAll(SniStrategy.concreteFallbackOrder(wonStrategy, hasCustomSni, isCellular))
                            }.distinct()
                        } else {
                            for (tested in pool) {
                                sessionExcludedHosts.add(tested.hostName)
                                sessionExcludedHosts.add(tested.ip)
                                sessionFailedSubnets.add(ServerRepository.subnet24(tested.ip))
                                recordServerOutcome(tested.hostName, verifiedSuccess = false)
                            }
                            consecutiveFailures++
                            attemptFailureReason = "All ${pool.size} raced servers were blocked or unresponsive"
                            VpnStateHolder.updateLiveStatus("سرورهای تست شده مسدود بودند • تغییر خودکار به سرورهای جدید...")
                            VpnStateHolder.log(attemptFailureReason!!)
                            isFailoverTransition.set(true)
                            delay(250)
                            continue
                        }
                    }
                } else {
                    candidate = pool.firstOrNull()
                }
            }

            if (candidate == null) {
                candidate = nextCandidate(preferredCandidate, initialServer, sessionExcludedHosts, sessionFailedSubnets, settings)
                preferredCandidate = null
            }
            if (candidate == null) {
                attemptFailureReason = "No reachable VPN servers remaining"
                break
            }

            currentServer = candidate
            if (strategies.isEmpty() && settings.sniStrategy != SniStrategy.AUTO_SMART) {
                VpnStateHolder.updateConnectPhase(
                    if (settings.sniStrategy == SniStrategy.DISABLED) ConnectPhase.TRYING_DIRECT_SSTP else ConnectPhase.CONNECTING_WITH_BYPASS,
                    if (settings.sniStrategy == SniStrategy.DISABLED) "" else settings.sniStrategy.displayName
                )
            }
            val candCountryFa = VpnStateHolder.translateCountryToPersian(candidate.countryLong.ifBlank { candidate.countryShort })
            VpnStateHolder.updateLiveStatus("اتصال به سرور $candCountryFa (پورت ${candidate.customPort})...")
            VpnStateHolder.updateStatus(
                if (totalAttempts == 1) VpnStatus.CONNECTING else VpnStatus.RECONNECTING,
                "Connecting to ${candidate.countryLong.ifBlank { candidate.hostName }} (${candidate.ip}) [$profileKey]..."
            )
            updateNotification("Connecting (${candidate.countryLong.ifBlank { candidate.ip }})...")

            if (strategies.isEmpty()) {
                strategies = resolveStrategiesForCandidate(
                    candidate = candidate,
                    settings = settings,
                    profileKey = profileKey,
                    preferredProfileStrategy = learnedProfiles[profileKey]
                )
            }
            val ranClient = if (strategies.isEmpty()) {
                false
            } else {
                tryServerWithStrategies(candidate, settings, strategies, generation, effectiveProtocol = effectiveProtocol)
            }

            if (!isRunning.get() || userStopRequested.get() || activeGeneration != generation) {
                return
            }

            val attemptTarget = candidate
            if (!handlePostAttemptOutcome(
                    candidate = attemptTarget,
                    initialServer = initialServer,
                    ranClient = ranClient,
                    settings = settings,
                    profileKey = profileKey,
                    learnedProfiles = learnedProfiles,
                    sessionExcludedHosts = sessionExcludedHosts,
                    sessionFailedSubnets = sessionFailedSubnets,
                    onResetFailures = { consecutiveFailures = 0 },
                    onIncrementFailure = { consecutiveFailures++ },
                    onLinkSwitch = {
                        preferredCandidate = attemptTarget
                        recoveringSameLinkSwitch = true
                        directAttemptedOnCurrentLink = false
                    },
                    onSameServerRecovery = {
                        preferredCandidate = if (attemptTarget.isCustom && it) attemptTarget else null
                    }
                )
            ) {
                break
            }
        }

        if (isRunning.get() && activeGeneration == generation && !userStopRequested.get()) {
            if (effectiveProtocol == VpnProtocol.AUTO_SMART && !fromAutoSmart && !initialServer.isCustom) {
                VpnStateHolder.log("🔄 اتصال هوشمند: سرورهای VPN Gate در این شبکه مسدود بودند — انتقال خودکار به شبکه Anycast Cloudflare WARP...")
                VpnStateHolder.updateConnectPhase(ConnectPhase.CONNECTING_WITH_BYPASS, "انتقال به Cloudflare WARP")
                VpnStateHolder.updateStatus(VpnStatus.CONNECTING, "تغییر خودکار پروتکل به Cloudflare WARP...")
                handoffToWarpService()
                return
            }

            val label = currentServer?.countryLong?.ifBlank { currentServer?.hostName ?: "" }.orEmpty()
            VpnStateHolder.updateConnectPhase(ConnectPhase.IDLE)
            VpnStateHolder.updateStatus(
                VpnStatus.ERROR,
                attemptFailureReason ?: "Failed to verify internet via $label"
            )
            delay(2500)
            stopVpn(preserveError = true)
        }
    }

    /**
     * Tries plain direct TLS first; only when direct transport fails does it run
     * [CensorshipDetector.detectBestStrategy] to identify filtering and retry with the winning bypass.
     */
    private suspend fun connectDirectThenSmartBypassFallback(
        candidate: VpnServer,
        settings: UserSettings,
        effectiveProtocol: VpnProtocol,
        profileKey: String,
        learnedProfiles: MutableMap<String, String>,
        generation: Long,
        isReconnect: Boolean
    ): Boolean {
        val isSoftEtherOrAuto = effectiveProtocol == VpnProtocol.SOFTETHER_NATIVE ||
            effectiveProtocol == VpnProtocol.AUTO_SMART
        val label = candidate.countryLong.ifBlank { candidate.hostName }
        val labelFa = VpnStateHolder.translateCountryToPersian(candidate.countryLong.ifBlank { candidate.countryShort })
        VpnStateHolder.updateConnectPhase(ConnectPhase.TRYING_DIRECT_SSTP)
        if (isSoftEtherOrAuto) {
            val protoTag = if (effectiveProtocol == VpnProtocol.AUTO_SMART) "هوشمند" else "سافت‌ادر"
            VpnStateHolder.updateLiveStatus("اتصال $protoTag به سرور $labelFa...")
            VpnStateHolder.updateStatus(
                if (isReconnect) VpnStatus.RECONNECTING else VpnStatus.CONNECTING,
                "Connecting ($protoTag) to $label (${candidate.ip}) [$profileKey]..."
            )
            updateNotification("Connecting $protoTag ($label)...")
        } else {
            VpnStateHolder.updateLiveStatus("تست اتصال مستقیم به سرور $labelFa...")
            VpnStateHolder.updateStatus(
                if (isReconnect) VpnStatus.RECONNECTING else VpnStatus.CONNECTING,
                "Trying direct SSTP on $label (${candidate.ip}) [$profileKey]..."
            )
            updateNotification("Trying direct SSTP ($label)...")
        }

        val directOk = tryServerWithStrategies(
            candidate = candidate,
            settings = settings,
            strategies = listOf(SniStrategy.DIRECT_IP_NO_SNI, SniStrategy.DISABLED),
            generation = generation,
            connectTimeoutMs = if (isSoftEtherOrAuto) 3500 else DIRECT_SSTP_FIRST_TIMEOUT_MS,
            effectiveProtocol = effectiveProtocol
        )
        if (!isRunning.get() || userStopRequested.get() || activeGeneration != generation || networkSwitchRequested.get()) {
            return directOk
        }
        if (directOk && attemptVerifiedInternet) {
            return true
        }

        // Bypassing SNI cannot recover an authenticated tunnel that was blackholed or rejected at HTTP/MS-CHAPv2
        if (attemptForceAbortReason?.contains("Blackhole", ignoreCase = true) == true ||
            isNonTransportFailure(attemptFailureReason)
        ) {
            return directOk
        }

        val reasonFa = VpnStateHolder.translateFailureReasonToPersian(attemptFailureReason)
        VpnStateHolder.updateConnectPhase(ConnectPhase.DETECTING_CENSORSHIP)
        VpnStateHolder.updateLiveStatus("تست اولیه سرور $labelFa ناموفق ($reasonFa) • اعمال روش ضد فیلتر...")
        VpnStateHolder.updateStatus(
            VpnStatus.CONNECTING,
            "Direct SSTP failed (${attemptFailureReason ?: "blocked"}); detecting filter & bypass on ${candidate.ip}..."
        )
        updateNotification("Detecting filter & bypass...")

        val inetAddr = try {
            InetAddress.getByName(candidate.ip)
        } catch (_: Exception) {
            attemptFailureReason = "Invalid host IP: ${candidate.ip}"
            return false
        }

        val preferredForNetwork = learnedProfiles[profileKey]
            ?.takeIf { it.isNotBlank() }
            ?.let { key -> SniStrategy.entries.firstOrNull { it.name == key && it.isConcreteTransport } }
        val preferredLast = settings.lastVpnBypassStrategy
            .takeIf { it.isNotBlank() }
            ?.let { key -> SniStrategy.entries.firstOrNull { it.name == key && it.isConcreteTransport } }
        val effectiveCustomSni = resolveEffectiveCustomSni(candidate, settings)
        val hasCustomSni = !effectiveCustomSni.isNullOrBlank()

        val diagnosis = CensorshipDetector.detectBestStrategy(
            host = candidate.hostName,
            ipAddress = inetAddr,
            port = candidate.customPort,
            networkProfile = profileKey,
            preferredStrategy = preferredForNetwork ?: preferredLast,
            customSni = effectiveCustomSni,
            strictCert = settings.strictCert,
            socketProtector = this@AetherVpnService,
            stopOnFirstWinner = true,
            includeDirectProbe = false
        )
        VpnStateHolder.updateDiagnosis(diagnosis)

        if (!isRunning.get() || userStopRequested.get() || activeGeneration != generation) {
            return false
        }

        var effectiveDiagnosis = diagnosis
        var effectiveCandidate = candidate
        if (effectiveDiagnosis.classification == FilterClassification.IP_OR_PORT_BLOCKED &&
            !candidate.isCustom &&
            candidate.customPort == 443
        ) {
            val altPorts = listOf(992, 5555)
            for (altPort in altPorts) {
                VpnStateHolder.updateLiveStatus("پورت ۴۴۳ سرور $labelFa مسدود بود • درحال تست پورت $altPort...")
                VpnStateHolder.log("Port 443 blocked on ${candidate.ip}; probing alternative port $altPort...")
                val altDiag = CensorshipDetector.detectBestStrategy(
                    host = candidate.hostName,
                    ipAddress = inetAddr,
                    port = altPort,
                    networkProfile = profileKey,
                    preferredStrategy = preferredForNetwork ?: preferredLast,
                    customSni = effectiveCustomSni,
                    strictCert = settings.strictCert,
                    socketProtector = this@AetherVpnService,
                    stopOnFirstWinner = true,
                    includeDirectProbe = false
                )
                if (altDiag.classification != FilterClassification.IP_OR_PORT_BLOCKED && altDiag.recommendedStrategy != null) {
                    effectiveDiagnosis = altDiag
                    effectiveCandidate = candidate.copy(customPort = altPort)
                    serviceScope.launch(Dispatchers.IO) {
                        runCatching {
                            openServerDb().vpnServerDao().updatePort(candidate.hostName, altPort)
                        }
                    }
                    VpnStateHolder.updateLiveStatus("پورت $altPort سرور $labelFa باز است • برقراری تونل امن...")
                    VpnStateHolder.log("Alternative port $altPort is OPEN on ${candidate.ip} via ${altDiag.recommendedStrategy?.displayName}!")
                    break
                }
            }
        }

        val winner = effectiveDiagnosis.recommendedStrategy
        if (effectiveDiagnosis.classification == FilterClassification.IP_OR_PORT_BLOCKED) {
            attemptFailureReason = "IP/Port blocked by ISP (${effectiveCandidate.ip}:${effectiveCandidate.customPort})"
            VpnStateHolder.updateLiveStatus("پورت‌های سرور $labelFa مسدود بودند • تغییر خودکار به سرور بعدی...")
            VpnStateHolder.log("Smart Detect [$profileKey]: ${effectiveCandidate.ip}:${effectiveCandidate.customPort} -> IP/Port blocked; switching server.")
            return false
        }
        if (winner == null) {
            attemptFailureReason = "All bypass strategies blocked on ${effectiveCandidate.ip}"
            VpnStateHolder.updateLiveStatus("اتصال به سرور $labelFa ممکن نشد • تغییر خودکار به سرور بعدی...")
            VpnStateHolder.log("Smart Detect [$profileKey]: No TLS bypass succeeded on ${effectiveCandidate.ip}.")
            return false
        }

        val winLatency = effectiveDiagnosis.results.firstOrNull { it.strategy == winner }?.latencyMs
        VpnStateHolder.log(
            "Smart Detect [$profileKey]: ${effectiveDiagnosis.classification.summaryKey} -> ${winner.displayName}" +
                (if (winLatency != null) " (${winLatency}ms)" else "")
        )
        VpnStateHolder.updateConnectPhase(ConnectPhase.CONNECTING_WITH_BYPASS, winner.displayName)
        VpnStateHolder.updateLiveStatus("اعمال تکنیک ضد فیلتر (${winner.displayName}) روی سرور $labelFa...")
        VpnStateHolder.updateStatus(
            VpnStatus.CONNECTING,
            "Detected ${effectiveDiagnosis.classification.summaryKey}; connecting via ${winner.displayName}..."
        )
        updateNotification("Connecting (${winner.shortLabel})...")

        val isCellular = profileKey.contains("CELLULAR", ignoreCase = true) ||
            profileKey.contains("MOBILE", ignoreCase = true)
        val bypassStrategies = buildList {
            add(winner)
            addAll(SniStrategy.concreteFallbackOrder(winner, hasCustomSni, isCellular).filter { it != SniStrategy.DISABLED })
        }.distinct()

        resetAttemptFlags()
        cleanupActiveTunnelOnly()
        return tryServerWithStrategies(
            candidate = effectiveCandidate,
            settings = settings,
            strategies = bypassStrategies,
            generation = generation,
            effectiveProtocol = effectiveProtocol
        )
    }

    private suspend fun handlePostAttemptOutcome(
        candidate: VpnServer,
        initialServer: VpnServer,
        ranClient: Boolean,
        settings: UserSettings,
        profileKey: String,
        learnedProfiles: MutableMap<String, String>,
        sessionExcludedHosts: MutableSet<String>,
        sessionFailedSubnets: MutableSet<String>,
        onResetFailures: () -> Unit,
        onIncrementFailure: () -> Unit,
        onLinkSwitch: () -> Unit,
        onSameServerRecovery: (keepCustom: Boolean) -> Unit
    ): Boolean {
        if (attemptVerifiedInternet && attemptStrategyUsed != null) {
            learnedProfiles[profileKey] = attemptStrategyUsed!!.name
        }

        if (networkSwitchRequested.getAndSet(false)) {
            VpnStateHolder.updateStatus(
                VpnStatus.RECONNECTING,
                "Physical link switched; reconnecting ${candidate.countryLong.ifBlank { candidate.hostName }}..."
            )
            onLinkSwitch()
            delay(700)
            return true
        }

        if (!ranClient || !attemptVerifiedInternet) {
            onIncrementFailure()
            recordServerOutcome(candidate.hostName, verifiedSuccess = false)
            sessionExcludedHosts.add(candidate.hostName)
            sessionExcludedHosts.add(candidate.ip)
            sessionFailedSubnets.add(ServerRepository.subnet24(candidate.ip))

            if (!settings.autoFailover || initialServer.isCustom) {
                return false
            }
            isFailoverTransition.set(true)
            val reason = attemptForceAbortReason ?: attemptFailureReason ?: "unresponsive"
            val reasonFa = VpnStateHolder.translateFailureReasonToPersian(reason)
            val failLabelFa = VpnStateHolder.translateCountryToPersian(candidate.countryLong.ifBlank { candidate.countryShort })
            VpnStateHolder.updateConnectPhase(ConnectPhase.RACING_BACKUP_SERVERS)
            VpnStateHolder.updateLiveStatus("سرور $failLabelFa پاسخ نداد ($reasonFa) • تغییر به سرور بعدی...")
            VpnStateHolder.updateStatus(
                VpnStatus.RECONNECTING,
                "${candidate.countryLong.ifBlank { candidate.ip }} failed ($reason), auto-switching..."
            )
            delay(250)
            return true
        }

        onResetFailures()
        val stalled = attemptForceAbortReason?.contains("Stall", ignoreCase = true) == true
        if (stalled) {
            recordServerOutcome(candidate.hostName, verifiedSuccess = false)
            sessionExcludedHosts.add(candidate.hostName)
            sessionExcludedHosts.add(candidate.ip)
            sessionFailedSubnets.add(ServerRepository.subnet24(candidate.ip))
        }

        if (!settings.autoFailover) {
            return false
        }

        isFailoverTransition.set(true)
        onSameServerRecovery(!stalled)
        VpnStateHolder.updateStatus(
            VpnStatus.RECONNECTING,
            "Connection interrupted (${attemptForceAbortReason ?: attemptFailureReason ?: "reconnect"}), recovering..."
        )
        delay(1000)
        return true
    }

    private fun resolvePhysicalNetworkProfileKey(): String {
        return VpnStateHolder.resolveNetworkProfileKey(
            cm = connectivityManager,
            preferredNetwork = activePhysicalNetwork,
            context = applicationContext
        )
    }

    private fun resolveEffectiveCustomSni(candidate: VpnServer, settings: UserSettings): String? {
        return candidate.customSni?.takeIf { it.isNotBlank() }
            ?: settings.customSni.takeIf { it.isNotBlank() }
    }

    private suspend fun resolveStrategiesForCandidate(
        candidate: VpnServer,
        settings: UserSettings,
        profileKey: String,
        preferredProfileStrategy: String?
    ): List<SniStrategy> {
        val isCellular = profileKey.contains("CELLULAR", ignoreCase = true) ||
            profileKey.contains("MOBILE", ignoreCase = true)
        val preferredForNetwork = preferredProfileStrategy
            ?.takeIf { it.isNotBlank() }
            ?.let { key -> SniStrategy.entries.firstOrNull { it.name == key && it.isConcreteTransport } }
        val preferredLast = settings.lastVpnBypassStrategy
            .takeIf { it.isNotBlank() }
            ?.let { key -> SniStrategy.entries.firstOrNull { it.name == key && it.isConcreteTransport } }
        val effectiveCustomSni = resolveEffectiveCustomSni(candidate, settings)
        val hasCustomSni = !effectiveCustomSni.isNullOrBlank()

        if (settings.sniStrategy == SniStrategy.DISABLED) {
            return listOf(SniStrategy.DISABLED)
        }
        if (settings.sniStrategy != SniStrategy.AUTO_SMART) {
            return buildList {
                add(settings.sniStrategy)
                preferredForNetwork?.let { add(it) }
                preferredLast?.let { add(it) }
                addAll(SniStrategy.concreteFallbackOrder(settings.sniStrategy, hasCustomSni, isCellular))
            }.distinct()
        }

        val inetAddr = try {
            InetAddress.getByName(candidate.ip)
        } catch (e: Exception) {
            attemptFailureReason = "Invalid host IP: ${candidate.ip}"
            return emptyList()
        }

        var diagnosis = CensorshipDetector.detectBestStrategy(
            host = candidate.hostName,
            ipAddress = inetAddr,
            port = candidate.customPort,
            networkProfile = profileKey,
            preferredStrategy = preferredForNetwork ?: preferredLast,
            customSni = effectiveCustomSni,
            strictCert = settings.strictCert,
            socketProtector = this@AetherVpnService,
            stopOnFirstWinner = true
        )

        if (diagnosis.classification == FilterClassification.IP_OR_PORT_BLOCKED &&
            !candidate.isCustom &&
            candidate.customPort == 443
        ) {
            val altPorts = listOf(992, 5555)
            for (altPort in altPorts) {
                VpnStateHolder.log("Port 443 blocked on ${candidate.ip}; probing alternative port $altPort...")
                val altDiag = CensorshipDetector.detectBestStrategy(
                    host = candidate.hostName,
                    ipAddress = inetAddr,
                    port = altPort,
                    networkProfile = profileKey,
                    preferredStrategy = preferredForNetwork ?: preferredLast,
                    customSni = effectiveCustomSni,
                    strictCert = settings.strictCert,
                    socketProtector = this@AetherVpnService,
                    stopOnFirstWinner = true,
                    includeDirectProbe = false
                )
                if (altDiag.classification != FilterClassification.IP_OR_PORT_BLOCKED && altDiag.recommendedStrategy != null) {
                    diagnosis = altDiag
                    serviceScope.launch(Dispatchers.IO) {
                        runCatching {
                            openServerDb().vpnServerDao().updatePort(candidate.hostName, altPort)
                        }
                    }
                    VpnStateHolder.log("Alternative port $altPort is OPEN on ${candidate.ip} via ${altDiag.recommendedStrategy?.displayName}!")
                    break
                }
            }
        }
        VpnStateHolder.updateDiagnosis(diagnosis)

        val winner = diagnosis.recommendedStrategy
        if (diagnosis.classification == FilterClassification.IP_OR_PORT_BLOCKED) {
            attemptFailureReason = "IP/Port blocked by ISP (${candidate.ip}:${candidate.customPort})"
            VpnStateHolder.log("Smart Detect [$profileKey]: ${candidate.ip}:${candidate.customPort} -> IP/Port blocked; switching server.")
            return emptyList()
        }

        if (winner == null) {
            attemptFailureReason = "All bypass strategies blocked on ${candidate.ip}"
            VpnStateHolder.log("Smart Detect [$profileKey]: No TLS bypass succeeded on ${candidate.ip}.")
            return SniStrategy.concreteFallbackOrder(preferredForNetwork ?: preferredLast, hasCustomSni, isCellular)
        }

        val winLatency = diagnosis.results.firstOrNull { it.strategy == winner }?.latencyMs
        VpnStateHolder.log(
            "Smart Detect [$profileKey]: ${diagnosis.classification.summaryKey} -> ${winner.displayName}" +
                (if (winLatency != null) " (${winLatency}ms)" else "")
        )
        return buildList {
            add(winner)
            addAll(SniStrategy.concreteFallbackOrder(winner, hasCustomSni, isCellular))
        }.distinct()
    }

    private suspend fun selectRacePoolCandidates(
        preferred: VpnServer?,
        excludedHosts: Set<String>,
        deprioritizedSubnets: Set<String>,
        maxCandidates: Int = 3
    ): List<VpnServer> {
        var db: AppDatabase? = null
        return try {
            db = openServerDb()
            val all = db.vpnServerDao().getAllServers().first()
            ServerRepository.selectRaceCandidates(
                servers = all,
                primary = preferred,
                excludedHosts = excludedHosts,
                deprioritizedSubnets = deprioritizedSubnets,
                maxCandidates = maxCandidates,
                nowMs = System.currentTimeMillis()
            )
        } catch (_: Exception) {
            listOfNotNull(preferred)
        } finally {
            try { db?.close() } catch (_: Exception) {}
        }
    }

    private suspend fun nextCandidate(
        preferred: VpnServer?,
        initialServer: VpnServer,
        excludedHosts: Set<String>,
        deprioritizedSubnets: Set<String>,
        settings: UserSettings
    ): VpnServer? {
        if (preferred != null &&
            preferred.hostName !in excludedHosts &&
            preferred.ip !in excludedHosts &&
            !ServerRepository.isCensoredCountry(preferred.countryShort) &&
            !ServerRepository.isRestrictedAcademicSubnet(preferred.ip)
        ) {
            return preferred
        }
        if (initialServer.isCustom) {
            return if (initialServer.hostName !in excludedHosts) initialServer else null
        }
        if (!settings.autoFailover && excludedHosts.isNotEmpty()) {
            return null
        }

        var db: AppDatabase? = null
        return try {
            db = openServerDb()
            val all = db.vpnServerDao().getAllServers().first()
            ServerRepository.selectNextCandidate(
                servers = all,
                excludedHosts = excludedHosts,
                deprioritizedSubnets = deprioritizedSubnets,
                nowMs = System.currentTimeMillis()
            )
        } catch (e: Exception) {
            VpnStateHolder.log("Candidate lookup error: ${e.message}")
            null
        } finally {
            try { db?.close() } catch (_: Exception) {}
        }
    }

    private fun effectiveMtuForActiveLink(configuredMtu: Int): Int {
        val net = activePhysicalNetwork ?: connectivityManager.activeNetwork
        val caps = net?.let { runCatching { connectivityManager.getNetworkCapabilities(it) }.getOrNull() }
        val isCellular = caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true
        val physicalMtu = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && net != null) {
            runCatching { connectivityManager.getLinkProperties(net)?.mtu ?: 0 }.getOrDefault(0)
        } else {
            0
        }
        return ServerRepository.resolveEffectiveMtu(
            configuredMtu = configuredMtu,
            physicalMtu = physicalMtu,
            isCellular = isCellular
        )
    }

    private fun isNonTransportFailure(msg: String?): Boolean {
        if (msg.isNullOrBlank()) return false
        // Only classify post-TLS protocol/auth/TUN rejections as non-transport failures.
        // TCP RST, ECONNRESET, timeouts, and ECONNREFUSED are classic Iran DPI signatures and
        // MUST trigger CensorshipDetector + TLS record fragmentation / SNI bypass instead of aborting.
        return msg.contains("SSTP HTTP handshake failed") ||
            msg.contains("MS-CHAPv2 authentication rejected") ||
            msg.contains("Expected SSTP CALL_CONNECT_ACK") ||
            msg.contains("SoftEther login failed") ||
            msg.contains("during LCP negotiation") ||
            msg.contains("during MS-CHAPv2 authentication") ||
            msg.contains("during IPCP negotiation") ||
            msg.contains("Cannot set address") ||
            msg.contains("Cannot establish TUN interface") ||
            msg.contains("Server rejected IP address") ||
            msg.contains("no DHCP") ||
            msg.contains("LCP Terminate-Request")
    }

    private suspend fun tryServerWithStrategies(
        candidate: VpnServer,
        settings: UserSettings,
        strategies: List<SniStrategy>,
        generation: Long,
        connectTimeoutMs: Int = FAILOVER_HANDSHAKE_TIMEOUT_MS,
        effectiveProtocol: VpnProtocol = settings.vpnProtocol
    ): Boolean {
        val protocolsForCandidate = when (effectiveProtocol) {
            VpnProtocol.AUTO_SMART -> listOf(VpnProtocol.SOFTETHER_NATIVE, VpnProtocol.SSTP)
            VpnProtocol.SOFTETHER_NATIVE -> listOf(VpnProtocol.SOFTETHER_NATIVE)
            VpnProtocol.SSTP, VpnProtocol.WARP -> listOf(VpnProtocol.SSTP)
        }

        for (strategy in strategies) {
            if (!isRunning.get() || userStopRequested.get() || activeGeneration != generation) {
                return false
            }
            if (attemptForceAbortReason != null || networkSwitchRequested.get()) {
                // Server already completed TLS handshake and then failed health/stalled/switched; skip strategy retries
                return true
            }

            val inetAddr = try {
                InetAddress.getByName(candidate.ip)
            } catch (e: Exception) {
                attemptFailureReason = "Invalid host IP: ${candidate.ip}"
                return false
            }
            val effectiveMtu = effectiveMtuForActiveLink(settings.mtu)
            val customSniOverride = resolveEffectiveCustomSni(candidate, settings)

            for ((protoIdx, proto) in protocolsForCandidate.withIndex()) {
                if (!isRunning.get() || userStopRequested.get() || activeGeneration != generation) {
                    return false
                }
                if (attemptForceAbortReason != null || networkSwitchRequested.get()) {
                    return true
                }

                try {
                    currentAttemptProtocol = proto
                    currentStrategyName = "${proto.shortTag()} • ${strategy.name}"
                    attemptStrategyUsed = strategy
                    VpnStateHolder.log("Trying ${candidate.ip}:${candidate.customPort} (Proto: $proto, Strategy: $strategy, MTU: $effectiveMtu)...")

                    if (proto == VpnProtocol.SOFTETHER_NATIVE) {
                        val effectivePort = if (candidate.customPort in 1..65535) candidate.customPort else 443
                        val hubName = if (candidate.isCustom) "DEFAULT" else "VPNGATE"
                        val user = if (candidate.isCustom) candidate.customUsername.ifBlank { "vpn" } else "vpn"
                        val pass = if (candidate.isCustom) candidate.customPassword.ifBlank { "vpn" } else "vpn"
                        val targetCh = if (effectiveProtocol == VpnProtocol.AUTO_SMART) {
                            maxOf(settings.softEtherConnections, 4).coerceIn(1, 16)
                        } else {
                            settings.softEtherConnections.coerceIn(1, 16)
                        }

                        val seConfig = SoftEtherConfig(
                            host = candidate.hostName.ifBlank { candidate.ip },
                            ipAddress = candidate.ip,
                            port = effectivePort,
                            username = user,
                            password = pass,
                            hubName = hubName,
                            targetConnections = targetCh,
                            sniStrategy = strategy,
                            customSni = customSniOverride,
                            strictCert = settings.strictCert,
                            connectTimeoutMs = connectTimeoutMs,
                            mtu = effectiveMtu
                        )

                        val client = SoftEtherClient(
                            config = seConfig,
                            socketProtector = this@AetherVpnService,
                            listener = object : SoftEtherEventListener {
                                override fun onStateChanged(state: SoftEtherState, message: String) {
                                    if (userStopRequested.get() || !isRunning.get()) return
                                    when (state) {
                                        SoftEtherState.CONNECTING_PRIMARY -> {
                                            VpnStateHolder.updateConnectPhase(ConnectPhase.CONNECTING_WITH_BYPASS)
                                            VpnStateHolder.updateStatus(VpnStatus.CONNECTING, message)
                                            updateNotification(message)
                                        }
                                        SoftEtherState.AUTHENTICATING -> {
                                            VpnStateHolder.updateConnectPhase(ConnectPhase.CONNECTING_WITH_BYPASS)
                                            VpnStateHolder.updateStatus(VpnStatus.AUTHENTICATING, message)
                                            updateNotification(message)
                                        }
                                        SoftEtherState.ESTABLISHING_CHANNELS -> {
                                            VpnStateHolder.updateStatus(VpnStatus.CONNECTING, message)
                                            updateNotification(message)
                                        }
                                        SoftEtherState.NEGOTIATING_DHCP -> {
                                            VpnStateHolder.updateStatus(VpnStatus.AUTHENTICATING, message)
                                            updateNotification(message)
                                        }
                                        SoftEtherState.CONNECTED,
                                        SoftEtherState.DISCONNECTING,
                                        SoftEtherState.DISCONNECTED -> {}
                                    }
                                }

                                override fun onConnected(params: SoftEtherVpnParameters) {
                                    if (userStopRequested.get() || !isRunning.get()) return
                                    val server = currentServer ?: return
                                    val vpnParams = VpnParameters(
                                        clientIp = params.clientIp,
                                        gatewayIp = params.gateway,
                                        primaryDns = params.dnsServers.getOrNull(0) ?: "8.8.8.8",
                                        secondaryDns = params.dnsServers.getOrNull(1) ?: "8.8.4.4",
                                        mtu = params.mtu
                                    )
                                    latestParams = vpnParams
                                    establishTun(vpnParams, activeSettings)

                                    val srvCountryFa = VpnStateHolder.translateCountryToPersian(server.countryLong.ifBlank { server.countryShort })
                                    VpnStateHolder.updateConnectPhase(ConnectPhase.VERIFYING_INTERNET)
                                    VpnStateHolder.updateLiveStatus("بررسی دسترسی آزاد به اینترنت سرور $srvCountryFa (سافت‌ادر ${params.activeChannels} کانکشن)...")
                                    VpnStateHolder.updateStatus(
                                        VpnStatus.AUTHENTICATING,
                                        "Verifying real internet on ${server.countryLong.ifBlank { server.ip }} via SoftEther (${params.activeChannels} Ch)..."
                                    )
                                    updateNotification("Verifying internet...")

                                    verifyJob?.cancel()
                                    verifyJob = serviceScope.launch(Dispatchers.IO) {
                                        val activeClient = activeTunnelClient ?: return@launch
                                        verifyAndPromoteSession(
                                            client = activeClient,
                                            server = server,
                                            params = vpnParams,
                                            strategy = strategy,
                                            connectedMsg = "${params.clientIp} (${params.activeChannels} TCP Ch)",
                                            generation = generation
                                        )
                                    }
                                }

                                override fun onDisconnected(reason: String) {
                                    VpnStateHolder.log("SoftEther: $reason")
                                }

                                override fun onError(e: Exception) {
                                    val msg = e.message ?: e.javaClass.simpleName
                                    attemptFailureReason = msg
                                    VpnStateHolder.log("SoftEther error: $msg")
                                }

                                override fun onIpPacketReceived(packet: ByteArray, offset: Int, length: Int) {
                                    onDataPacketReceived(packet, offset, length)
                                }

                                override fun onBytesTransferred(txBytesDelta: Long, rxBytesDelta: Long) {
                                    totalTxBytes.addAndGet(txBytesDelta)
                                    totalRxBytes.addAndGet(rxBytesDelta)
                                }

                                override fun onLog(message: String) {
                                    VpnStateHolder.log(message)
                                }
                            }
                        )
                        client.setPacketProbeInterceptor { buf, off, len -> interceptProbeDnsReply(buf, off, len) }
                        activeTunnelClient = client
                        client.start(serviceScope)
                        return true
                    } else {
                        val sstpConfig = SstpConfig(
                            host = candidate.ip,
                            ipAddress = inetAddr,
                            port = candidate.customPort,
                            username = candidate.customUsername,
                            password = candidate.customPassword,
                            mtu = effectiveMtu,
                            keepaliveIntervalSec = settings.keepaliveSec,
                            strictCert = settings.strictCert,
                            sniStrategy = strategy,
                            customSni = customSniOverride,
                            connectTimeoutMs = connectTimeoutMs
                        )

                        val client = SstpClient(
                            config = sstpConfig,
                            socketProtector = this@AetherVpnService,
                            listener = this@AetherVpnService
                        )
                        client.setPacketProbeInterceptor { buf, off, len -> interceptProbeDnsReply(buf, off, len) }
                        activeTunnelClient = client
                        client.start(serviceScope)
                        return true
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    val msg = e.message ?: e.javaClass.simpleName
                    attemptFailureReason = msg
                    VpnStateHolder.log("Proto $proto / Strategy $strategy error: $msg")

                    // In AUTO_SMART, if SoftEther Native fails due to hub/protocol/auth mismatch, fall back seamlessly to SSTP on same server
                    val hasNextProto = protoIdx < protocolsForCandidate.lastIndex
                    if (hasNextProto && isRunning.get() && !userStopRequested.get() && !networkSwitchRequested.get()) {
                        VpnStateHolder.log("SoftEther Native failed on ${candidate.ip} ($msg); falling back to SSTP with $strategy...")
                        cleanupActiveTunnelOnly()
                        attemptFailureReason = null
                        continue
                    }

                    val isDefinitiveAuthFailure = (strategy == SniStrategy.DIRECT_IP_NO_SNI || strategy == SniStrategy.DISABLED) &&
                        isNonTransportFailure(msg)
                    if (isDefinitiveAuthFailure) {
                        VpnStateHolder.log("Server ${candidate.ip} rejected tunnel/auth on direct transport; skipping remaining SNI retries.")
                        return false
                    }
                    if (isRunning.get() && !userStopRequested.get()) {
                        delay(300)
                    }
                }
            }
        }
        return false
    }

    private fun VpnProtocol.shortTag(): String = when (this) {
        VpnProtocol.SOFTETHER_NATIVE -> "SoftEther-TCP"
        VpnProtocol.SSTP -> "SSTP"
        VpnProtocol.WARP -> "WARP"
        VpnProtocol.AUTO_SMART -> "AutoSmart"
    }

    private fun handoffToWarpService() {
        isFailoverTransition.set(true)
        if (!isRunning.compareAndSet(true, false)) return
        activeGeneration++
        metricsJob?.cancel()
        metricsJob = null
        cleanupActiveTunnelOnly()
        val dotToClose = dotClient
        dotClient = null
        serviceScope.launch(Dispatchers.IO) {
            try { dotToClose?.close() } catch (_: Exception) {}
        }
        if (callbackRegistered.compareAndSet(true, false)) {
            try { connectivityManager.unregisterNetworkCallback(networkCallback) } catch (_: Exception) {}
        }
        activePhysicalNetwork = null
        lastPhysicalNetwork = null
        availablePhysicalNetworks.clear()

        try {
            ContextCompat.startForegroundService(
                applicationContext,
                WarpService.buildConnectIntent(applicationContext, fromAutoSmart = true)
            )
        } catch (e: Exception) {
            VpnStateHolder.log("Failed to start WARP handoff: ${e.message}")
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        requestTileRefresh()
    }

    override fun onStateChanged(state: SstpState, message: String?) {
        if (userStopRequested.get() || !isRunning.get()) return
        when (state) {
            SstpState.CONNECTING_TCP, SstpState.TLS_HANDSHAKE, SstpState.HTTP_HANDSHAKE -> {
                if (!isFailoverTransition.get()) {
                    VpnStateHolder.updateStatus(VpnStatus.CONNECTING, message)
                } else if (message != null) {
                    VpnStateHolder.log(message)
                }
                updateNotification(message ?: "Connecting...")
            }
            SstpState.SSTP_CONNECTING, SstpState.PPP_LCP, SstpState.PPP_AUTH, SstpState.PPP_IPCP -> {
                val status = if (isFailoverTransition.get()) VpnStatus.RECONNECTING else VpnStatus.AUTHENTICATING
                VpnStateHolder.updateStatus(status, message)
                updateNotification(message ?: "Authenticating...")
            }
            SstpState.CONNECTED -> {
                val client = activeTunnelClient ?: return
                val server = currentServer ?: return
                val params = latestParams ?: return
                val generation = activeGeneration
                val strategy = attemptStrategyUsed

                val srvCountryFa = VpnStateHolder.translateCountryToPersian(server.countryLong.ifBlank { server.countryShort })
                VpnStateHolder.updateConnectPhase(ConnectPhase.VERIFYING_INTERNET)
                VpnStateHolder.updateLiveStatus("بررسی دسترسی آزاد به اینترنت سرور $srvCountryFa...")
                VpnStateHolder.updateStatus(
                    VpnStatus.AUTHENTICATING,
                    "Verifying real internet on ${server.countryLong.ifBlank { server.ip }}..."
                )
                updateNotification("Verifying internet...")

                verifyJob?.cancel()
                verifyJob = serviceScope.launch(Dispatchers.IO) {
                    verifyAndPromoteSession(client, server, params, strategy, message ?: "", generation)
                }
            }
            SstpState.DISCONNECTING, SstpState.DISCONNECTED -> {
                // Handled explicitly by runConnectionLoop / stopVpn so failover transitions don't flash Disconnected
            }
        }
    }

    private suspend fun verifyAndPromoteSession(
        client: TunnelClient,
        server: VpnServer,
        params: VpnParameters,
        strategy: SniStrategy?,
        connectedMsg: String,
        generation: Long
    ) {
        delay(80)
        if (!isRunning.get() || activeGeneration != generation || activeTunnelClient !== client) return

        val ok = verifyTunnelInternet(client, params, activeSettings)
        if (!isRunning.get() || activeGeneration != generation || activeTunnelClient !== client) return

        if (!ok) {
            val srvCountryFa = VpnStateHolder.translateCountryToPersian(server.countryLong.ifBlank { server.countryShort })
            VpnStateHolder.updateLiveStatus("سرور $srvCountryFa دسترسی آزاد به اینترنت نداشت • تغییر خودکار به سرور بعدی...")
            VpnStateHolder.log("Health check failed on ${server.ip}: tunnel passed handshake but dropped internet packets! Quarantining 20m...")
            attemptForceAbortReason = "Blackhole: 0 valid internet replies"
            attemptFailureReason = "Server blackholed internet traffic"
            try { client.close() } catch (_: Exception) {}
            return
        }

        attemptVerifiedInternet = true
        isFailoverTransition.set(false)
        recordServerOutcome(server.hostName, verifiedSuccess = true)
        val profileKey = resolvePhysicalNetworkProfileKey()
        strategy?.let { used ->
            try {
                val pref = PreferencesManager(applicationContext)
                pref.updateVpnBypassProfile(profileKey, used.name)
                pref.updateVpnProtocolProfile(profileKey, currentAttemptProtocol.name)
            } catch (_: Exception) {}
        }

        val strategyBadge = buildString {
            append(profileKey)
            append(" • ")
            append(currentStrategyName.ifBlank { "Active" })
        }
        VpnStateHolder.updateConnected(
            server = server,
            clientIp = connectedMsg,
            strategy = strategyBadge,
            physicalNetworkLabel = profileKey,
            splitRuleCount = activeSplitRuleCount
        )
        val label = server.countryLong.ifBlank { server.hostName }
        updateNotification("Connected ($label)")
        requestTileRefresh()
        fetchPublicIp(generation)
        startTrafficWatchdog(client, server, params, generation)
    }

    private suspend fun verifyTunnelInternet(
        client: TunnelClient,
        params: VpnParameters,
        settings: UserSettings
    ): Boolean {
        // Fast path 1: First-success parallel HTTP/Telegram/Instagram connectivity check via established VPN interface
        if (isAppPackageRoutedViaVpn(settings)) {
            delay(80)
            val resultChannel = Channel<Boolean>(Channel.UNLIMITED)
            val verified = coroutineScope {
                val probeJobs = buildList {
                    listOf(
                        "http://connectivitycheck.gstatic.com/generate_204",
                        "https://1.1.1.1/cdn-cgi/trace"
                    ).forEach { url ->
                        add(async(Dispatchers.IO) {
                            val ok = try {
                                val req = Request.Builder().url(url).build()
                                httpClient.newCall(req).execute().use { it.code in 200..499 }
                            } catch (_: Exception) {
                                false
                            }
                            resultChannel.trySend(ok)
                        })
                    }

                    listOf(
                        java.net.InetSocketAddress("149.154.167.50", 443),
                        java.net.InetSocketAddress("149.154.167.91", 443),
                        java.net.InetSocketAddress("91.108.56.165", 443)
                    ).forEach { endpoint ->
                        add(async(Dispatchers.IO) {
                            val ok = try {
                                java.net.Socket().use { s ->
                                    s.connect(endpoint, 3200)
                                    true
                                }
                            } catch (_: Exception) {
                                false
                            }
                            resultChannel.trySend(ok)
                        })
                    }

                    listOf(
                        java.net.InetSocketAddress("157.240.241.63", 443),
                        java.net.InetSocketAddress("157.240.1.63", 443)
                    ).forEach { endpoint ->
                        add(async(Dispatchers.IO) {
                            val ok = try {
                                java.net.Socket().use { s ->
                                    s.connect(endpoint, 3200)
                                    true
                                }
                            } catch (_: Exception) {
                                false
                            }
                            resultChannel.trySend(ok)
                        })
                    }
                }

                var firstSuccess = false
                var completed = 0
                val total = probeJobs.size
                val outcome = withTimeoutOrNull(3800L) {
                    while (completed < total) {
                        if (resultChannel.receive()) {
                            firstSuccess = true
                            break
                        }
                        completed++
                    }
                    firstSuccess
                } ?: false

                probeJobs.forEach { it.cancel() }
                outcome
            }

            if (verified) {
                VpnStateHolder.log("Tunnel verification succeeded (fast first-response).")
                return true
            } else {
                VpnStateHolder.log("Tunnel verification failed: all probes failed; failing over...")
                return false
            }
        }

        // Fast path 2: Raw in-tunnel DNS health probe (for split tunnel excluded mode)
        if (probeTunnelDnsHealth(client, params)) {
            return true
        }

        return false
    }

    private suspend fun probeTunnelDnsHealth(client: TunnelClient, params: VpnParameters): Boolean {
        val srcIpBytes = try {
            InetAddress.getByName(params.clientIp).address
        } catch (_: Exception) {
            return false
        }
        if (srcIpBytes.size != 4) return false

        // Only probe server-assigned primary DNS if it is a routable public IP (skip dead 10.x.x.x virtual-hub IPs)
        val primaryDns = params.primaryDns.trim()
        if (primaryDns.isNotBlank() && primaryDns != "0.0.0.0" && TunnelPackets.isPublicRoutableIpv4(primaryDns)) {
            val primaryDnsBytes = try { InetAddress.getByName(primaryDns).address } catch (_: Exception) { null }
            if (primaryDnsBytes != null && primaryDnsBytes.size == 4) {
                val query0 = TunnelPackets.buildDnsARecordQuery("google.com", 0xC33A)
                val resp0 = queryTunnelRawDns(client, srcIpBytes, primaryDnsBytes, query0, timeoutMs = 2500L)
                if (resp0 != null && TunnelPackets.parseDnsARecordFirstPublicIpv4(resp0) != null) return true
            }
        }

        val query1 = TunnelPackets.buildDnsARecordQuery("cloudflare.com", 0xA11E)
        val resp1 = queryTunnelRawDns(client, srcIpBytes, DNS_PROBE_CF, query1, timeoutMs = 2500L)
        if (resp1 != null && TunnelPackets.parseDnsARecordFirstPublicIpv4(resp1) != null) return true

        val query2 = TunnelPackets.buildDnsARecordQuery("google.com", 0xB22F)
        val resp2 = queryTunnelRawDns(client, srcIpBytes, DNS_PROBE_GOOGLE, query2, timeoutMs = 2500L)
        return resp2 != null && TunnelPackets.parseDnsARecordFirstPublicIpv4(resp2) != null
    }

    private suspend fun queryTunnelRawDns(
        client: TunnelClient,
        clientIpBytes: ByteArray,
        dnsServerIp: ByteArray,
        dnsPayload: ByteArray,
        timeoutMs: Long = 2200L
    ): ByteArray? {
        if (clientIpBytes.size != 4 || dnsServerIp.size != 4) return null
        val srcPort = probePortCounter.updateAndGet { cur -> if (cur >= 59999) 54000 else cur + 1 }
        val deferred = CompletableDeferred<ByteArray>()
        pendingDnsProbes[srcPort] = deferred

        return try {
            val ipPkt = TunnelPackets.buildUdpIpv4Packet(
                srcIp = clientIpBytes,
                dstIp = dnsServerIp,
                srcPort = srcPort,
                dstPort = 53,
                payload = dnsPayload
            )
            client.sendIpPacket(ipPkt, ipPkt.size)
            withTimeoutOrNull(timeoutMs) { deferred.await() }
        } catch (_: Exception) {
            null
        } finally {
            pendingDnsProbes.remove(srcPort)
        }
    }

    private fun interceptProbeDnsReply(
        packet: ByteArray,
        offset: Int = 0,
        length: Int = packet.size
    ): Boolean {
        if (pendingDnsProbes.isEmpty()) return false
        val udp = TunnelPackets.extractUdpHeader(packet, offset, length) ?: return false
        if (udp.srcPort != 53 || udp.payloadLength < 12) return false
        val deferred = pendingDnsProbes.remove(udp.dstPort) ?: return false
        val dnsPayload = packet.copyOfRange(udp.payloadOffset, udp.payloadOffset + udp.payloadLength)
        deferred.complete(dnsPayload)
        return true
    }

    private suspend fun isSocialAppReachable(): Boolean = withContext(Dispatchers.IO) {
        val endpoints = listOf(
            java.net.InetSocketAddress("1.1.1.1", 80),
            java.net.InetSocketAddress("8.8.8.8", 53),
            java.net.InetSocketAddress("149.154.167.91", 443),
            java.net.InetSocketAddress("157.240.241.63", 443),
            java.net.InetSocketAddress("91.108.4.1", 443),    // Telegram DC1
            java.net.InetSocketAddress("149.154.167.1", 443)  // Telegram DC5
        )
        coroutineScope {
            endpoints.map { ep ->
                async {
                    try {
                        java.net.Socket().use { s ->
                            s.connect(ep, 6000)
                            true
                        }
                    } catch (_: Exception) {
                        false
                    }
                }
            }.any { it.await() }
        }
    }

    private fun startTrafficWatchdog(
        client: TunnelClient,
        server: VpnServer,
        params: VpnParameters,
        generation: Long
    ) {
        watchdogJob?.cancel()
        watchdogJob = serviceScope.launch(Dispatchers.IO) {
            var lastSnap = client.snapshotTraffic()
            var stalledCycles = 0
            while (isActive && isRunning.get() && activeGeneration == generation && activeTunnelClient === client) {
                delay(WATCHDOG_INTERVAL_MS)
                val snap = client.snapshotTraffic()
                val txDelta = snap.txPackets - lastSnap.txPackets
                val rxDelta = snap.rxUnicastPackets - lastSnap.rxUnicastPackets
                lastSnap = snap

                val effectiveStallThreshold = if (activeTunnelClient is SoftEtherClient) STALL_TX_THRESHOLD * 2 else STALL_TX_THRESHOLD
                if (txDelta >= effectiveStallThreshold && rxDelta <= 1L) {
                    stalledCycles++
                    if (stalledCycles >= STALL_CONSECUTIVE_LIMIT) {
                        if (isRunning.get() && activeGeneration == generation) {
                            val alive = isSocialAppReachable()
                            if (!alive) {
                                VpnStateHolder.log("Stall watchdog triggered on ${server.ip} (txDelta=$txDelta, rxDelta=$rxDelta, apps unresponsive). Auto-recovering...")
                                attemptForceAbortReason = "Stall detected: apps unresponsive"
                                attemptFailureReason = "Tunnel stalled mid-session"
                                recordServerOutcome(server.hostName, verifiedSuccess = false)
                                try { client.close() } catch (_: Exception) {}
                                break
                            } else {
                                stalledCycles = 0
                            }
                        }
                    }
                } else {
                    stalledCycles = 0
                }
            }
        }
    }

    private fun isAppPackageRoutedViaVpn(settings: UserSettings): Boolean = when (settings.splitTunnelMode) {
        SplitTunnelMode.ALL_APPS -> true
        SplitTunnelMode.ALLOWED_ONLY -> packageName in settings.allowedPackages
        SplitTunnelMode.DISALLOWED_ONLY -> packageName !in settings.disallowedPackages
    }

    override fun onParametersEstablished(params: VpnParameters) {
        latestParams = params
        establishTun(params, activeSettings)
    }

    private fun buildTunInterface(
        params: VpnParameters,
        settings: UserSettings,
        customRules: IranRoutingRules.CustomBypassRules,
        includeIpv6Guard: Boolean
    ): ParcelFileDescriptor {
        val builder = Builder()
            .setSession("RadinVpn")
            .setMtu(params.mtu)
            .addAddress(params.clientIp, 32)

        if (settings.dnsMode == DnsMode.DNS_ONLY) {
            activeSplitRuleCount = 0
            builder.addDnsServer("10.254.254.254")
            builder.addRoute("10.254.254.254", 32)
        } else {
            val dnsServers = mutableListOf<String>()
            // Add fast, public DNS first (e.g. Cloudflare / Google / user preset) so apps (like Telegram)
            // don't stall on unhandled private SoftEther 10.x.x.x hub addresses.
            val selectedPreset = DnsResolver.findById(settings.selectedDnsId)
            if (selectedPreset.ip.isNotBlank() && TunnelPackets.isPublicRoutableIpv4(selectedPreset.ip)) {
                dnsServers.add(selectedPreset.ip)
            }

            // Add server-provided DNS only if it is a routable public IP
            val pDns = params.primaryDns.trim()
            if (pDns.isNotBlank() && pDns != "0.0.0.0" && TunnelPackets.isPublicRoutableIpv4(pDns)) {
                if (!dnsServers.contains(pDns)) dnsServers.add(pDns)
            }
            val sDns = params.secondaryDns.trim()
            if (sDns.isNotBlank() && sDns != "0.0.0.0" && TunnelPackets.isPublicRoutableIpv4(sDns)) {
                if (!dnsServers.contains(sDns)) dnsServers.add(sDns)
            }
            if (!dnsServers.contains("8.8.8.8")) dnsServers.add("8.8.8.8")
            if (!dnsServers.contains("8.8.4.4")) dnsServers.add("8.8.4.4")
            if (!dnsServers.contains("9.9.9.9")) dnsServers.add("9.9.9.9")
            if (!dnsServers.contains("1.1.1.1")) dnsServers.add("1.1.1.1")

            for (dns in dnsServers) {
                try {
                    builder.addDnsServer(dns)
                } catch (e: Exception) {
                    VpnStateHolder.log("Add DNS $dns notice: ${e.message}")
                }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                builder.addRoute("0.0.0.0", 0)
                excludeSplitRoutes(builder, settings.bypassIran, customRules.cidrs)
            } else {
                addPreApi33SplitRoutes(builder, settings.bypassIran, customRules.cidrs)
            }

            if (includeIpv6Guard) {
                builder.addAddress("fd00:ae7:3::2", 128)
                builder.addRoute("::", 0)
            }
        }

        when (settings.splitTunnelMode) {
            SplitTunnelMode.ALLOWED_ONLY -> {
                for (pkg in settings.allowedPackages) {
                    try { builder.addAllowedApplication(pkg) } catch (_: Exception) {}
                }
            }
            SplitTunnelMode.DISALLOWED_ONLY -> {
                for (pkg in settings.disallowedPackages) {
                    try { builder.addDisallowedApplication(pkg) } catch (_: Exception) {}
                }
            }
            SplitTunnelMode.ALL_APPS -> {}
        }

        builder.setBlocking(true)
        return builder.establish() ?: throw IllegalStateException("Cannot establish TUN interface")
    }

    private fun establishTun(params: VpnParameters, settings: UserSettings) {
        dnsCache.clear()
        val customRules = IranRoutingRules.parseCustomRules(settings.customBypassRules)

        var ipv6GuardActive = false
        val pfd = try {
            buildTunInterface(params, settings, customRules, includeIpv6Guard = settings.blockIpv6).also {
                ipv6GuardActive = settings.blockIpv6 && settings.dnsMode != DnsMode.DNS_ONLY
            }
        } catch (e: Exception) {
            if (settings.blockIpv6 && settings.dnsMode != DnsMode.DNS_ONLY) {
                VpnStateHolder.log("IPv6 leak guard rejected by active network (${e.message}); falling back to IPv4 tunnel.")
                buildTunInterface(params, settings, customRules, includeIpv6Guard = false)
            } else {
                throw e
            }
        }
        if (ipv6GuardActive) {
            VpnStateHolder.log("IPv6 leak guard active (blocking native IPv6 bypass).")
        }
        vpnInterface = pfd
        activeMtu = params.mtu
        tunOutputStream = FileOutputStream(pfd.fileDescriptor)
        activePhysicalNetwork?.let {
            try {
                setUnderlyingNetworks(arrayOf(it))
            } catch (_: Exception) {}
        }

        // In full VPN mode, all traffic (including standard DNS) is already encrypted inside SSTP TLS.
        // Intercepting DNS to user-space DoT over physical network fails in Iran due to port 853 blocking.
        // Therefore, interceptDot is strictly restricted to DNS_ONLY mode.
        val interceptDot = settings.dnsMode == DnsMode.DNS_ONLY && dotClient != null
        val splitIranDns = settings.bypassIran
        val hasDirectDomainRules = splitIranDns || customRules.domains.isNotEmpty()
        val channel = if (interceptDot || hasDirectDomainRules) {
            Channel<QueuedDnsQuery>(
                capacity = DNS_CHANNEL_CAPACITY,
                onBufferOverflow = BufferOverflow.DROP_OLDEST
            ).also { dnsChannel = it }
        } else {
            null
        }

        if (channel != null) {
            startDnsWorkerPool(channel, params, settings)
        }

        val generation = activeGeneration
        tunReaderJob = serviceScope.launch(Dispatchers.IO) {
            val fis = FileInputStream(pfd.fileDescriptor)
            val buffer = ByteArray(32768)
            val maxMss = maxOf(536, params.mtu - 40)
            while (isActive && isRunning.get() && activeGeneration == generation) {
                val length = try {
                    fis.read(buffer)
                } catch (_: Exception) {
                    break
                }
                if (length <= 0) continue

                val version = (buffer[0].toInt() and 0xF0) ushr 4
                if (version == 6 && settings.blockIpv6 && settings.dnsMode != DnsMode.DNS_ONLY) {
                    TunnelPackets.buildIcmpv6AdminProhibited(buffer, length)?.let { icmpV6 ->
                        writePacketToTun(icmpV6)
                    }
                    continue
                }
                if (version != 4 || length < 20) continue
                if (TunnelPackets.isBroadcastOrMulticastIpv4(buffer, length)) continue

                if (settings.blockQuic && settings.dnsMode != DnsMode.DNS_ONLY && TunnelPackets.isQuicUdp443(buffer, length)) {
                    TunnelPackets.buildIcmpPortUnreachable(buffer, length)?.let { icmp ->
                        writePacketToTun(icmp)
                    }
                    continue
                }

                if (channel != null && TunnelPackets.isUdpPort53(buffer, length)) {
                    val parsedDns = DnsPacketCodec.extractUdpDnsQuery(buffer, length)
                    if (parsedDns != null) {
                        val isDirectDomain = hasDirectDomainRules && IranRoutingRules.isIranDomain(
                            domain = TunnelPackets.extractDnsQueryDomain(parsedDns.dnsPayload),
                            customDomains = customRules.domains,
                            includeBuiltinIran = splitIranDns
                        )
                        if (interceptDot || isDirectDomain) {
                            totalTxBytes.addAndGet(length.toLong())
                            channel.trySend(QueuedDnsQuery(parsedDns, isIranDomain = isDirectDomain))
                            continue
                        }
                    }
                }

                if (settings.dnsMode != DnsMode.DNS_ONLY) {
                    MssClamper.clampMss(buffer, length, maxMss)
                    try {
                        activeTunnelClient?.sendIpPacket(buffer, length)
                    } catch (e: Exception) {
                        // Prevent any client/socket write exception from crashing the tun reader coroutine
                    }
                }
            }
        }
    }

    private fun startDnsWorkerPool(
        channel: Channel<QueuedDnsQuery>,
        params: VpnParameters,
        settings: UserSettings
    ) {
        val generation = activeGeneration
        val clientIpBytes = try {
            InetAddress.getByName(params.clientIp).address
        } catch (_: Exception) {
            byteArrayOf(10, 0, 0, 2)
        }
        val dotFailCount = AtomicInteger(0)

        repeat(DOT_WORKER_COUNT) {
            val worker = serviceScope.launch(Dispatchers.IO) {
                for (query in channel) {
                    if (!isActive || !isRunning.get() || activeGeneration != generation) break
                    val dnsResp = resolveQueuedDnsQuery(query, clientIpBytes, settings, dotFailCount)
                    if (dnsResp != null && dnsResp.size >= 12) {
                        val ipResp = DnsPacketCodec.buildUdpDnsResponse(query.parsed, dnsResp)
                        writePacketToTun(ipResp)
                        totalRxBytes.addAndGet(ipResp.size.toLong())
                    }
                }
            }
            tunWorkerJobs.add(worker)
        }
    }

    private suspend fun resolveQueuedDnsQuery(
        query: QueuedDnsQuery,
        clientIpBytes: ByteArray,
        settings: UserSettings,
        dotFailCount: AtomicInteger
    ): ByteArray? {
        val parsedDns = query.parsed
        val routeBucket = if (query.isIranDomain) DNS_BUCKET_DIRECT else DNS_BUCKET_TUNNEL
        val cached = dnsCache.getWithStale(parsedDns.dnsPayload, routeBucket)
        if (cached != null) {
            if (cached.isStale) {
                val gen = activeGeneration
                serviceScope.launch(Dispatchers.IO) {
                    if (!isRunning.get() || activeGeneration != gen) return@launch
                    val refreshed = resolveUncachedDnsQuery(query, clientIpBytes, settings, dotFailCount)
                    if (refreshed != null && refreshed.size >= 12) {
                        dnsCache.put(parsedDns.dnsPayload, refreshed, routeBucket)
                    }
                }
            }
            return cached.wireResponse
        }

        val resolved: ByteArray? = resolveUncachedDnsQuery(query, clientIpBytes, settings, dotFailCount)
        if (resolved != null && resolved.size >= 12) {
            dnsCache.put(parsedDns.dnsPayload, resolved, routeBucket)
        }
        return resolved
    }

    private suspend fun resolveUncachedDnsQuery(
        query: QueuedDnsQuery,
        clientIpBytes: ByteArray,
        settings: UserSettings,
        dotFailCount: AtomicInteger
    ): ByteArray? {
        val parsedDns = query.parsed
        if (query.isIranDomain) {
            resolveDirectPhysicalDns(parsedDns.dnsPayload)?.let { return it }
        }

        val dot = if (settings.dnsMode == DnsMode.DNS_ONLY) dotClient else null
        if (dot != null) {
            try {
                return dot.query(parsedDns.dnsPayload).also { dotFailCount.set(0) }
            } catch (e: Exception) {
                val fails = dotFailCount.incrementAndGet()
                if (fails <= 3 || fails % 10 == 0) {
                    VpnStateHolder.log("DoT query fallback (#$fails): ${e.message}")
                }
            }
        }

        if (settings.dnsMode == DnsMode.DNS_ONLY) return null
        val client = activeTunnelClient ?: return null
        val directIp = if (parsedDns.dstIp.size == 4 &&
            !parsedDns.dstIp.contentEquals(byteArrayOf(10, 254.toByte(), 254.toByte(), 254.toByte()))
        ) {
            parsedDns.dstIp
        } else {
            DNS_PROBE_GOOGLE
        }
        return queryTunnelRawDns(client, clientIpBytes, directIp, parsedDns.dnsPayload)
    }

    private fun resolveDirectPhysicalDns(dnsQueryPayload: ByteArray): ByteArray? {
        if (dnsQueryPayload.size < 12) return null
        val dnsServers = getPhysicalIpv4DnsServers()
        val network = activePhysicalNetwork
        for (serverAddr in dnsServers) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                if (!this.protect(socket)) {
                    socket.close()
                    continue
                }
                if (network != null) {
                    try {
                        network.bindSocket(socket)
                    } catch (_: Exception) {}
                }
                socket.soTimeout = DIRECT_DNS_TIMEOUT_MS
                socket.send(DatagramPacket(dnsQueryPayload, dnsQueryPayload.size, serverAddr, 53))

                val respBuf = ByteArray(2048)
                val respPacket = DatagramPacket(respBuf, respBuf.size)
                socket.receive(respPacket)
                if (respPacket.length < 12) continue
                val reply = respBuf.copyOf(respPacket.length)
                if (reply[0] != dnsQueryPayload[0] || reply[1] != dnsQueryPayload[1]) continue
                if (TunnelPackets.containsNonPublicARecord(reply)) continue
                return reply
            } catch (_: Exception) {
            } finally {
                try { socket?.close() } catch (_: Exception) {}
            }
        }
        return null
    }

    private fun getPhysicalIpv4DnsServers(): List<InetAddress> {
        val fromLink = activePhysicalNetwork?.let { network ->
            try {
                connectivityManager.getLinkProperties(network)?.dnsServers
                    ?.filterIsInstance<Inet4Address>()
                    ?.filter { !it.isLoopbackAddress && !it.isAnyLocalAddress }
            } catch (_: Exception) {
                null
            }
        }.orEmpty()
        val fallbacks = listOf(
            InetAddress.getByAddress(DNS_PROBE_CF),
            InetAddress.getByAddress(DNS_PROBE_GOOGLE)
        )
        return (fromLink + fallbacks).distinctBy { it.hostAddress }.take(3)
    }

    private fun writePacketToTun(packet: ByteArray, offset: Int = 0, length: Int = packet.size) {
        try {
            synchronized(tunWriteLock) {
                tunOutputStream?.write(packet, offset, length)
            }
        } catch (_: Exception) {}
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun excludeSplitRoutes(
        builder: Builder,
        bypassIran: Boolean,
        extraCidrs: List<Ipv4Cidr> = emptyList()
    ) {
        val excluded = IranRoutingRules.getExcludedRoutes(applicationContext, bypassIran, extraCidrs)
        var applied = 0
        for (cidr in excluded) {
            try {
                builder.excludeRoute(IpPrefix(cidr.toInetAddress(), cidr.prefixLen))
                applied++
            } catch (_: Exception) {}
        }
        activeSplitRuleCount = if (bypassIran || extraCidrs.isNotEmpty()) applied else 0
        if (bypassIran || extraCidrs.isNotEmpty()) {
            VpnStateHolder.log(
                "Split routing active: $applied direct/LAN CIDRs (${extraCidrs.size} custom) via ISP; foreign via tunnel."
            )
        }
    }

    private fun addPreApi33SplitRoutes(
        builder: Builder,
        bypassIran: Boolean,
        extraCidrs: List<Ipv4Cidr> = emptyList()
    ) {
        if (!bypassIran && extraCidrs.isEmpty()) {
            activeSplitRuleCount = 0
            builder.addRoute("0.0.0.0", 0)
            return
        }
        val excluded = IranRoutingRules.getExcludedRoutes(applicationContext, bypassIran, extraCidrs)
        val allowed = IranRoutingRules.getAllowedRoutesPreApi33(applicationContext, bypassIran, extraCidrs)
        for (cidr in allowed) {
            try {
                builder.addRoute(cidr.hostAddress, cidr.prefixLen)
            } catch (_: Exception) {}
        }
        activeSplitRuleCount = excluded.size
        VpnStateHolder.log("Pre-API 33 split routing active: ${allowed.size} tunneled CIDRs (${extraCidrs.size} custom bypass).")
    }

    override fun protect(socket: Socket): Boolean {
        val ok = super.protect(socket)
        if (!ok) {
            VpnStateHolder.log("WARNING: VpnService.protect(socket) returned false")
        }
        return ok
    }

    override fun onDataPacketReceived(packet: ByteArray, offset: Int, length: Int) {
        // Clamp incoming TCP SYN-ACK MSS (fast O(1) no-op on non-SYN data packets) to prevent
        // remote servers from sending oversized segments that trigger PMTUD blackholes on cellular/PPPoE.
        val maxMss = maxOf(536, activeMtu - 40)
        MssClamper.clampMss(packet, offset, length, maxMss)
        writePacketToTun(packet, offset, length)
    }

    override fun onBytesTransferred(txBytesDelta: Long, rxBytesDelta: Long) {
        totalTxBytes.addAndGet(txBytesDelta)
        totalRxBytes.addAndGet(rxBytesDelta)
    }

    override fun onError(t: Throwable) {
        val msg = t.message ?: t.javaClass.simpleName
        attemptFailureReason = msg
        VpnStateHolder.log("Tunnel error: $msg")
    }

    override fun onLog(message: String) {
        VpnStateHolder.log(message)
    }

    private fun startMetricsReporting(generation: Long) {
        metricsJob?.cancel()
        metricsJob = serviceScope.launch {
            val pm = getSystemService(Context.POWER_SERVICE) as? android.os.PowerManager
            var lastReportMs = System.currentTimeMillis()
            while (isActive && isRunning.get() && activeGeneration == generation) {
                val isInteractive = pm?.isInteractive ?: true
                val intervalMs = if (isInteractive) 1500L else 8000L
                delay(intervalMs)
                val now = System.currentTimeMillis()
                val elapsedSec = maxOf(1L, (now - lastReportMs) / 1000L)
                lastReportMs = now

                val curTx = totalTxBytes.get()
                val curRx = totalRxBytes.get()
                val speedTx = ((curTx - prevTxBytes.getAndSet(curTx)) * 8) / elapsedSec
                val speedRx = ((curRx - prevRxBytes.getAndSet(curRx)) * 8) / elapsedSec
                val duration = if (sessionStartTime > 0) (now - sessionStartTime) / 1000 else 0

                val cacheStats = dnsCache.snapshotStats()
                VpnStateHolder.updateMetrics(
                    bytesIn = curRx,
                    bytesOut = curTx,
                    speedIn = speedRx,
                    speedOut = speedTx,
                    duration = duration,
                    dnsCacheHits = cacheStats.hits,
                    dnsCacheMisses = cacheStats.misses
                )
            }
        }
    }

    private fun fetchPublicIp(generation: Long) {
        fetchPublicIpJob?.cancel()
        fetchPublicIpJob = serviceScope.launch(Dispatchers.IO) {
            delay(500)
            val endpoints = listOf(
                "https://api.ipify.org",
                "https://icanhazip.com",
                "https://checkip.amazonaws.com"
            )
            for (i in endpoints.indices) {
                if (!isRunning.get() || activeGeneration != generation || !isActive) return@launch
                try {
                    val req = Request.Builder().url(endpoints[i]).build()
                    val call = httpClient.newCall(req)
                    activePublicIpCall = call
                    try {
                        call.execute().use { resp ->
                            if (resp.isSuccessful && isRunning.get() && activeGeneration == generation && isActive) {
                                val ip = resp.body?.string()?.trim().orEmpty()
                                if (ip.length in 7..45 && !ip.contains('<') && !ip.contains(' ')) {
                                    if (isRunning.get() && activeGeneration == generation && isActive) {
                                        VpnStateHolder.updatePublicIp(ip)
                                    }
                                    return@launch
                                }
                            }
                        }
                    } finally {
                        if (activePublicIpCall === call) {
                            activePublicIpCall = null
                        }
                    }
                } catch (_: Exception) {}
                if (i < endpoints.lastIndex && isRunning.get() && activeGeneration == generation) {
                    delay(1200)
                }
            }
        }
    }

    private fun openServerDb(): AppDatabase = openServerDb(applicationContext)

    private fun recordServerOutcome(hostName: String, verifiedSuccess: Boolean) {
        if (hostName.isBlank()) return
        var db: AppDatabase? = null
        try {
            db = openServerDb()
            val dao = db.vpnServerDao()
            kotlinx.coroutines.runBlocking {
                if (verifiedSuccess) {
                    dao.recordSuccess(hostName, System.currentTimeMillis())
                } else {
                    dao.recordFailure(hostName, System.currentTimeMillis() + ServerRepository.DEFAULT_COOLDOWN_MS)
                }
            }
        } catch (_: Exception) {
        } finally {
            try { db?.close() } catch (_: Exception) {}
        }
    }

    private fun resetAttemptFlags() {
        attemptVerifiedInternet = false
        attemptFailureReason = null
        attemptForceAbortReason = null
        attemptStrategyUsed = null
        latestParams = null
    }

    private fun cleanupActiveTunnelOnly() {
        verifyJob?.cancel()
        verifyJob = null
        watchdogJob?.cancel()
        watchdogJob = null
        fetchPublicIpJob?.cancel()
        fetchPublicIpJob = null
        try { activePublicIpCall?.cancel() } catch (_: Exception) {}
        activePublicIpCall = null
        tunReaderJob?.cancel()
        tunReaderJob = null

        tunWorkerJobs.forEach { it.cancel() }
        tunWorkerJobs.clear()
        dnsChannel?.close()
        dnsChannel = null

        pendingDnsProbes.values.forEach { it.cancel() }
        pendingDnsProbes.clear()

        val clientToClose = activeTunnelClient
        activeTunnelClient = null
        clientToClose?.setProbeInterceptor(null)
        serviceScope.launch(Dispatchers.IO) {
            try { clientToClose?.close() } catch (_: Exception) {}
        }

        dnsCache.clear()
        try { tunOutputStream?.close() } catch (_: Exception) {}
        tunOutputStream = null
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
    }

    private fun requestTileRefresh() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            try {
                TileService.requestListeningState(
                    applicationContext,
                    ComponentName(applicationContext, AetherTileService::class.java)
                )
            } catch (_: Exception) {}
        }
    }

    private fun stopVpn(preserveError: Boolean = false) {
        userStopRequested.set(true)
        isFailoverTransition.set(false)
        if (!isRunning.compareAndSet(true, false)) return

        activeGeneration++
        VpnStateHolder.log("Disconnecting tunnel...")
        connectionJob?.cancel()
        connectionJob = null
        metricsJob?.cancel()
        metricsJob = null

        cleanupActiveTunnelOnly()

        val dotToClose = dotClient
        dotClient = null
        serviceScope.launch(Dispatchers.IO) {
            try { dotToClose?.close() } catch (_: Exception) {}
        }

        if (callbackRegistered.compareAndSet(true, false)) {
            try { connectivityManager.unregisterNetworkCallback(networkCallback) } catch (_: Exception) {}
        }
        activePhysicalNetwork = null
        lastPhysicalNetwork = null
        availablePhysicalNetworks.clear()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        if (!preserveError) {
            VpnStateHolder.reset()
        }
        requestTileRefresh()
    }

    override fun onRevoke() {
        VpnStateHolder.log("VPN revoked by system.")
        stopVpn()
        super.onRevoke()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Radin VPN Tunnel",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows live VPN connection status"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(statusText: String): Notification {
        val openAppIntent = Intent(this, MainActivity::class.java)
        val pOpenIntent = PendingIntent.getActivity(
            this, 0, openAppIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val disconnectIntent = Intent(this, AetherVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val pDisconnect = PendingIntent.getService(
            this, 1, disconnectIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Radin VPN")
            .setContentText(statusText)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentIntent(pOpenIntent)
            .setOngoing(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", pDisconnect)
            .build()
    }

    private fun updateNotification(statusText: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildNotification(statusText))
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
