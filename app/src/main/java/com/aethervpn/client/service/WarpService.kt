package com.aethervpn.client.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.aethervpn.client.R
import com.aethervpn.client.data.datastore.PreferencesManager
import com.aethervpn.client.data.datastore.SplitTunnelMode
import com.aethervpn.client.data.datastore.UserSettings
import com.aethervpn.client.data.datastore.VpnProtocol
import com.aethervpn.client.data.model.VpnServer
import com.aethervpn.client.ui.MainActivity
import com.aethervpn.vpncore.warp.CleanEndpoint
import com.aethervpn.vpncore.warp.CloudflareCleanIpScanner
import com.aethervpn.vpncore.warp.WarpAccount
import com.aethervpn.vpncore.warp.WarpConfigBuilder
import com.aethervpn.vpncore.warp.WarpNoiseProxy
import com.aethervpn.vpncore.warp.WarpRaceWinner
import com.aethervpn.vpncore.warp.WarpRegistrar
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class WarpService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunnelJob: Job? = null
    private var statsJob: Job? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private lateinit var preferencesManager: PreferencesManager
    private var backend: GoBackend? = null
    private var noiseProxy: WarpNoiseProxy? = null
    private var activeWinner: WarpRaceWinner? = null
    private var activeAccount: WarpAccount? = null
    private var activeProfileKey: String = "DEFAULT"
    private var isConnected = false

    private val warpTunnel = object : Tunnel {
        override fun getName(): String = "radin-warp"
        override fun onStateChange(state: Tunnel.State) {
            VpnStateHolder.log("WARP WireGuard tunnel state: $state")
            if (state == Tunnel.State.DOWN && isConnected) {
                isConnected = false
                closeNoiseProxySilently()
                VpnStateHolder.updateStatus(VpnStatus.DISCONNECTED)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        preferencesManager = PreferencesManager(applicationContext)
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        createNotificationChannel()
        backend = GoBackend(applicationContext)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notif = buildNotification(getString(R.string.status_connecting))
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIFICATION_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIFICATION_ID, notif)
            }
        } catch (e: Exception) {
            VpnStateHolder.log("startForeground notice: ${e.message}")
        }

        when (intent?.action) {
            ACTION_CONNECT -> {
                val fromAutoSmart = intent.getBooleanExtra(EXTRA_FROM_AUTO_SMART, false)
                startWarpTunnel(fromAutoSmart = fromAutoSmart)
            }
            ACTION_DISCONNECT -> {
                disconnectWarp()
            }
            ACTION_RESCAN -> {
                rescanAndReconnect()
            }
        }
        return START_NOT_STICKY
    }

    private fun startWarpTunnel(fromAutoSmart: Boolean = false) {
        tunnelJob?.cancel()
        tunnelJob = serviceScope.launch {
            val settings = preferencesManager.settingsFlow.first()
            try {
                teardownWireGuardSilently()

                VpnStateHolder.updateStatus(VpnStatus.CONNECTING, "مسابقه همزمان UDP با پوشش ضد فیلتر (WARP Noise)...")
                VpnStateHolder.updateConnectPhase(ConnectPhase.CONNECTING_WITH_BYPASS, "WARP Noise + UDP Race")
                VpnStateHolder.updateLiveStatus("تست همزمان ۱۸ پورت و آی‌پی کلودفلر با پوشش ضد فیلتر...")
                updateNotification("مسابقه هوشمند پورت‌های ضد فیلتر کلودفلر...")

                val profileKey = VpnStateHolder.resolveNetworkProfileKey(connectivityManager, null, applicationContext)
                activeProfileKey = profileKey

                // Step 1: Load or register WARP account (and upgrade legacy accounts missing client_id)
                var account = WarpAccount.fromJson(settings.warpAccountJson)
                if (account == null) {
                    VpnStateHolder.log("ثبت حساب کاربری رایگان WARP در کلودفلر (با شناسه ضد فیلتر client_id)...")
                    VpnStateHolder.updateStatus(VpnStatus.AUTHENTICATING, "ثبت نام حساب کاربری WARP...")
                    account = WarpRegistrar.registerAccount()
                    preferencesManager.updateWarpAccountJson(account.toJson())
                    VpnStateHolder.log(
                        "حساب WARP ایجاد شد: ID=${account.id.take(8)}..., reserved=${account.reservedBytes() != null}"
                    )
                } else if (account.reservedBytes() == null) {
                    VpnStateHolder.log("حساب WARP قدیمی فاقد فیلد reserved است؛ تلاش برای دریافت شناسه ضد فیلتر...")
                    val refreshed = runCatching { WarpRegistrar.registerAccount() }.getOrNull()
                    if (refreshed != null && refreshed.reservedBytes() != null) {
                        account = refreshed
                        preferencesManager.updateWarpAccountJson(refreshed.toJson())
                        VpnStateHolder.log("حساب WARP با شناسه ضد فیلتر (client_id) ارتقا یافت.")
                    } else {
                        VpnStateHolder.log("ادامه با حساب WARP موجود (تزریق نویز QUIC/AmneziaWG فعال است).")
                    }
                }
                activeAccount = account

                // Step 2: Parse previously verified Clean Endpoint for priority slot #1
                val targetPort = settings.warpPort.takeIf { it in 1..65535 } ?: 2408
                val preferredEndpoint = parseSavedEndpoint(settings.warpCleanEndpoint)

                // Step 3: Start local loopback WarpNoiseProxy (client_id stamping + QUIC/AmneziaWG noise + 18-way UDP race)
                val proxy = WarpNoiseProxy(
                    reservedBytes = account.reservedBytes(),
                    candidatesProvider = {
                        CloudflareCleanIpScanner.buildDiverseUdpCandidates(
                            preferredEndpoint = preferredEndpoint,
                            targetPort = targetPort,
                            count = 18
                        )
                    },
                    onLog = { VpnStateHolder.log(it) }
                )
                val localProxyPort = proxy.start()
                noiseProxy = proxy

                // Step 4: Split tunneling (always exclude our own package so WarpNoiseProxy bypasses TUN cleanly)
                val excludedPackages = when (settings.splitTunnelMode) {
                    SplitTunnelMode.DISALLOWED_ONLY -> settings.disallowedPackages
                    else -> emptySet()
                }
                val includedPackages = when (settings.splitTunnelMode) {
                    SplitTunnelMode.ALLOWED_ONLY -> settings.allowedPackages
                    else -> emptySet()
                }

                val config = WarpConfigBuilder.buildConfig(
                    account = account,
                    endpoint = CleanEndpoint(ip = "127.0.0.1", port = localProxyPort, pingMs = 1L),
                    mtu = if (settings.mtu in 1200..1420) settings.mtu else 1280,
                    keepaliveSec = if (settings.keepaliveSec in 5..60) settings.keepaliveSec else 15,
                    excludedApps = excludedPackages,
                    includedApps = includedPackages,
                    excludeAppPackage = applicationContext.packageName
                )

                val backendInstance = backend ?: GoBackend(applicationContext).also { backend = it }
                backendInstance.setState(warpTunnel, Tunnel.State.UP, config)
                isConnected = true

                // Step 5: Wait for real cryptographic WireGuard Handshake Response + Transport Data
                // Covers up to 2 full waves (36 diverse Cloudflare IP:Port endpoints across 54 UDP ports)
                VpnStateHolder.updateConnectPhase(
                    ConnectPhase.VERIFYING_INTERNET,
                    "مسابقه همزمان UDP با نویز ضد فیلتر"
                )
                val winner = proxy.awaitVerifiedTransportReady(timeoutMs = 7800L)

                if (winner == null) {
                    VpnStateHolder.log("⚠️ تمامی گره‌ها و پورت‌های UDP کلودفلر (۳۶ مسیر با نویز ضد فیلتر) مسدود بودند.")
                    teardownWireGuardSilently()
                    fallbackToTcpOrFail(settings = settings, fromAutoSmart = fromAutoSmart)
                    return@launch
                }

                // Step 6: Persist winning endpoint + learned network profile and promote UI state
                activeWinner = winner
                val cleanEndpoint = winner.endpoint
                runCatching {
                    preferencesManager.updateWarpCleanEndpoint("${cleanEndpoint.ip}:${cleanEndpoint.port}")
                    preferencesManager.updateVpnProtocolProfile(profileKey, VpnProtocol.WARP.name)
                }

                val cfServer = VpnServer(
                    hostName = "Cloudflare WARP",
                    ip = cleanEndpoint.ip,
                    customPort = cleanEndpoint.port,
                    countryLong = "Cloudflare WARP (${winner.noiseMode.label})",
                    countryShort = "CF",
                    ping = winner.handshakeRttMs.toInt()
                )
                val reservedTag = if (account.reservedBytes() != null) "ClientID+" else ""
                VpnStateHolder.updateConnected(
                    server = cfServer,
                    clientIp = account.assignedIpv4,
                    strategy = "$profileKey • WARP $reservedTag${winner.noiseMode.label} (${cleanEndpoint.ip}:${cleanEndpoint.port} • ${winner.handshakeRttMs}ms)",
                    physicalNetworkLabel = profileKey
                )

                updateNotification("WARP متصل شد • ${cleanEndpoint.ip}:${cleanEndpoint.port}")
                registerNetworkCallback()
                startMetricsLoop()
            } catch (e: CancellationException) {
                // Cancelled cleanly
            } catch (e: Exception) {
                VpnStateHolder.log("WARP connection failed: ${e.message}")
                teardownWireGuardSilently()
                if (!fromAutoSmart && settings.vpnProtocol == VpnProtocol.AUTO_SMART) {
                    fallbackToTcpOrFail(settings = settings, fromAutoSmart = false)
                } else {
                    VpnStateHolder.updateStatus(VpnStatus.ERROR, e.message ?: "خطا در اتصال به WARP")
                    updateNotification("خطا در اتصال به WARP")
                }
            }
        }
    }

    private suspend fun fallbackToTcpOrFail(settings: UserSettings, fromAutoSmart: Boolean) {
        if (fromAutoSmart) {
            VpnStateHolder.updateStatus(
                VpnStatus.ERROR,
                "تمامی پروتکل‌ها (WARP Noise / SoftEther / SSTP) در این شبکه مسدود هستند."
            )
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        VpnStateHolder.log("🔄 اتصال هوشمند رادین: مسدودی کامل UDP — جابجایی خودکار به SoftEther/SSTP با شکستن رکورد TLS و SNI مجاز...")
        VpnStateHolder.updateStatus(VpnStatus.CONNECTING, "مسدودی UDP؛ جابجایی خودکار به SoftEther ضد فیلتر...")
        VpnStateHolder.updateLiveStatus("مسدودی UDP؛ تغییر خودکار به تونل TCP ضد فیلتر...")
        updateNotification("مسدودی UDP؛ اتصال به سرور TCP ضد فیلتر...")

        val fallbackServer = AetherVpnService.findBestStoredServer(applicationContext)
        if (fallbackServer != null) {
            VpnStateHolder.log("🚀 شروع اتصال خودکار TCP به سرور: ${fallbackServer.countryLong.ifBlank { fallbackServer.hostName }} (${fallbackServer.ip})")
            val fallbackIntent = AetherVpnService.buildConnectIntent(
                context = applicationContext,
                server = fallbackServer,
                forceProtocolId = VpnProtocol.AUTO_SMART.id,
                fromAutoSmart = true
            )
            ContextCompat.startForegroundService(applicationContext, fallbackIntent)
        } else {
            VpnStateHolder.updateStatus(VpnStatus.ERROR, "پروتکل WARP مسدود است و سرور ضد فیلتر یافت نشد.")
        }

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun parseSavedEndpoint(raw: String): CleanEndpoint? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        val colonIdx = trimmed.lastIndexOf(':')
        if (colonIdx <= 0 || colonIdx >= trimmed.lastIndex) return null
        val ip = trimmed.substring(0, colonIdx).trim()
        val port = trimmed.substring(colonIdx + 1).trim().toIntOrNull() ?: return null
        if (ip.isBlank() || port !in 1..65535) return null
        return CleanEndpoint(ip = ip, port = port, pingMs = 1L)
    }

    private fun startMetricsLoop() {
        statsJob?.cancel()
        statsJob = serviceScope.launch {
            var lastRx = 0L
            var lastTx = 0L
            var durationSec = 0L
            var lastTime = System.currentTimeMillis()
            var stalledSeconds = 0
            var hotRescanAttempted = false

            while (isActive && isConnected) {
                delay(1000)
                durationSec++
                try {
                    val stats = backend?.getStatistics(warpTunnel)
                    if (stats != null) {
                        val currentRx = stats.totalRx()
                        val currentTx = stats.totalTx()
                        val deltaRx = currentRx - lastRx
                        val deltaTx = currentTx - lastTx
                        val now = System.currentTimeMillis()
                        val elapsedSec = ((now - lastTime) / 1000.0).coerceAtLeast(1.0)
                        val speedRx = ((deltaRx.toDouble() / elapsedSec).toLong()).coerceAtLeast(0L)
                        val speedTx = ((deltaTx.toDouble() / elapsedSec).toLong()).coerceAtLeast(0L)

                        lastRx = currentRx
                        lastTx = currentTx
                        lastTime = now

                        // Reflect live endpoint migration if WarpNoiseProxy migrated mid-session
                        val latestWinner = noiseProxy?.activeWinner
                        if (latestWinner != null && latestWinner.endpoint != activeWinner?.endpoint) {
                            activeWinner = latestWinner
                            runCatching {
                                preferencesManager.updateWarpCleanEndpoint(
                                    "${latestWinner.endpoint.ip}:${latestWinner.endpoint.port}"
                                )
                            }
                            VpnStateHolder.log(
                                "✅ مهاجرت سریع به گره جدید کلودفلر: ${latestWinner.endpoint.ip}:${latestWinner.endpoint.port} (${latestWinner.handshakeRttMs}ms)"
                            )
                        }

                        if (deltaTx > 1024L && deltaRx <= 0L) {
                            stalledSeconds++
                            if (stalledSeconds >= 10 && !hotRescanAttempted) {
                                hotRescanAttempted = true
                                stalledSeconds = 0
                                VpnStateHolder.log("توقف ترافیک UDP تشخیص داده شد؛ مهاجرت سریع بدون قطعی به گره جدید کلودفلر...")
                                noiseProxy?.triggerHotRescan()
                            } else if (stalledSeconds >= 12 && hotRescanAttempted) {
                                VpnStateHolder.log("گره جدید پاسخ نداد؛ اجرای مجدد اسکن کامل WARP...")
                                stalledSeconds = 0
                                hotRescanAttempted = false
                                rescanAndReconnect()
                                break
                            }
                        } else if (deltaRx > 0L) {
                            stalledSeconds = 0
                            hotRescanAttempted = false
                        }

                        VpnStateHolder.updateMetrics(
                            bytesIn = currentRx,
                            bytesOut = currentTx,
                            speedIn = speedRx,
                            speedOut = speedTx,
                            duration = durationSec
                        )

                        val speedStr = formatSpeed(speedRx)
                        updateNotification("WARP متصل است • ↓ $speedStr")
                    }
                } catch (_: Exception) {}
            }
        }
    }

    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        val cm = connectivityManager ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val caps = cm.getNetworkCapabilities(network) ?: return
                val isCellular = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                val isWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                val label = if (isWifi) "Wi-Fi" else if (isCellular) "Cellular (موبایل)" else "Network"
                VpnStateHolder.log("تغییر شبکه به $label؛ مهاجرت خودکار WARP روی مسیر جدید...")
                if (isConnected) {
                    noiseProxy?.triggerHotRescan()
                }
            }

            override fun onLost(network: Network) {
                VpnStateHolder.log("شبکه قبلی قطع شد؛ انتظار برای شبکه جایگزین...")
            }
        }
        networkCallback = callback
        try {
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            cm.registerNetworkCallback(req, callback)
        } catch (e: Exception) {
            VpnStateHolder.log("NetworkCallback registration warning: ${e.message}")
        }
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let {
            try {
                connectivityManager?.unregisterNetworkCallback(it)
            } catch (_: Exception) {}
            networkCallback = null
        }
    }

    private fun closeNoiseProxySilently() {
        val proxy = noiseProxy
        noiseProxy = null
        try {
            proxy?.close()
        } catch (_: Exception) {}
    }

    private suspend fun teardownWireGuardSilently() {
        isConnected = false
        statsJob?.cancel()
        unregisterNetworkCallback()
        try {
            backend?.setState(warpTunnel, Tunnel.State.DOWN, null)
        } catch (e: Exception) {
            VpnStateHolder.log("Notice tearing down WireGuard: ${e.message}")
        }
        closeNoiseProxySilently()
    }

    private fun rescanAndReconnect() {
        serviceScope.launch {
            VpnStateHolder.log("اسکن مجدد آی‌پی و پورت تمیز کلودفلر...")
            startWarpTunnel(fromAutoSmart = false)
        }
    }

    private fun disconnectWarp() {
        isConnected = false
        tunnelJob?.cancel()
        statsJob?.cancel()
        unregisterNetworkCallback()

        serviceScope.launch {
            try {
                backend?.setState(warpTunnel, Tunnel.State.DOWN, null)
            } catch (e: Exception) {
                VpnStateHolder.log("Error tearing down WireGuard tunnel: ${e.message}")
            } finally {
                closeNoiseProxySilently()
                withContext(Dispatchers.Main) {
                    VpnStateHolder.updateStatus(VpnStatus.DISCONNECTED)
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
    }

    override fun onDestroy() {
        closeNoiseProxySilently()
        disconnectWarp()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Radin VPN - WARP",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows live Cloudflare WARP connection status"
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

        val disconnectIntent = Intent(this, WarpService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val pDisconnect = PendingIntent.getService(
            this, 1, disconnectIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val rescanIntent = Intent(this, WarpService::class.java).apply {
            action = ACTION_RESCAN
        }
        val pRescan = PendingIntent.getService(
            this, 2, rescanIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Radin VPN • Cloudflare WARP")
            .setContentText(statusText)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentIntent(pOpenIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(0, "تغییر آی‌پی تمیز", pRescan)
            .addAction(0, getString(R.string.disconnect), pDisconnect)
            .build()
    }

    private fun updateNotification(statusText: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager?.notify(NOTIFICATION_ID, buildNotification(statusText))
    }

    private fun formatSpeed(bytesPerSec: Long): String {
        return when {
            bytesPerSec >= 1024 * 1024 -> String.format(java.util.Locale.US, "%.1f MB/s", bytesPerSec / (1024.0 * 1024.0))
            bytesPerSec >= 1024 -> String.format(java.util.Locale.US, "%.0f KB/s", bytesPerSec / 1024.0)
            else -> "$bytesPerSec B/s"
        }
    }

    companion object {
        const val ACTION_CONNECT = "com.aethervpn.client.WARP_CONNECT"
        const val ACTION_DISCONNECT = "com.aethervpn.client.WARP_DISCONNECT"
        const val ACTION_RESCAN = "com.aethervpn.client.WARP_RESCAN"
        const val EXTRA_FROM_AUTO_SMART = "extra_from_auto_smart"

        private const val CHANNEL_ID = "radin_warp_channel"
        private const val NOTIFICATION_ID = 2001

        fun buildConnectIntent(context: Context, fromAutoSmart: Boolean = false): Intent =
            Intent(context, WarpService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_FROM_AUTO_SMART, fromAutoSmart)
            }

        fun buildDisconnectIntent(context: Context): Intent =
            Intent(context, WarpService::class.java).apply {
                action = ACTION_DISCONNECT
            }
    }
}
