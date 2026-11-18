package com.aethervpn.client.ui

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aethervpn.client.BuildConfig
import com.aethervpn.client.data.datastore.DnsMode
import com.aethervpn.client.data.datastore.PreferencesManager
import com.aethervpn.client.data.datastore.SplitTunnelMode
import com.aethervpn.client.data.datastore.UserSettings
import com.aethervpn.client.data.datastore.VpnProtocol
import com.aethervpn.client.data.model.VpnServer
import com.aethervpn.client.data.repository.ServerRepository
import com.aethervpn.client.data.routing.IranRoutingRules
import com.aethervpn.client.service.AetherVpnService
import com.aethervpn.client.service.VpnSessionState
import com.aethervpn.client.service.VpnStateHolder
import com.aethervpn.client.service.VpnStatus
import com.aethervpn.client.service.WarpService
import com.aethervpn.vpncore.transport.CensorshipDetector
import com.aethervpn.vpncore.transport.FilterClassification
import com.aethervpn.vpncore.transport.SniStrategy
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val serverRepository: ServerRepository,
    private val preferencesManager: PreferencesManager
) : ViewModel() {

    val vpnState: StateFlow<VpnSessionState> = VpnStateHolder.state
    val servers: StateFlow<List<VpnServer>> = serverRepository.allServers
        .map { list -> ServerRepository.smartSortServers(list, System.currentTimeMillis()) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val settings: StateFlow<UserSettings> = preferencesManager.settingsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), UserSettings())

    private val _isRefreshing = MutableStateFlow(false)
    val isRefreshing: StateFlow<Boolean> = _isRefreshing.asStateFlow()

    private val _selectedServer = MutableStateFlow<VpnServer?>(null)
    val selectedServer: StateFlow<VpnServer?> = _selectedServer.asStateFlow()

    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

    private val _iranCidrInfo = MutableStateFlow(IranRoutingRules.getCidrSourceInfo(context))
    val iranCidrInfo: StateFlow<IranRoutingRules.CidrSourceInfo> = _iranCidrInfo.asStateFlow()

    private val _isUpdatingCidrs = MutableStateFlow(false)
    val isUpdatingCidrs: StateFlow<Boolean> = _isUpdatingCidrs.asStateFlow()

    private val _isBatchPinging = MutableStateFlow(false)
    val isBatchPinging: StateFlow<Boolean> = _isBatchPinging.asStateFlow()

    private val _batchPingProgress = MutableStateFlow<Pair<Int, Int>?>(null)
    val batchPingProgress: StateFlow<Pair<Int, Int>?> = _batchPingProgress.asStateFlow()

    val logs: StateFlow<List<String>> = VpnStateHolder.logs

    init {
        val versionBanner = "Radin VPN v${BuildConfig.VERSION_NAME} (Build ${BuildConfig.VERSION_CODE})"
        if (VpnStateHolder.logs.value.none { it.contains(versionBanner) }) {
            VpnStateHolder.log(versionBanner)
        }
        viewModelScope.launch {
            serverRepository.ensureInitialized()
            launch {
                servers.collect { list ->
                    val current = _selectedServer.value
                    val now = System.currentTimeMillis()
                    val hasLowLatencyHealthy = list.any { ServerRepository.isLowLatencyRegion(it.countryShort) && it.cooldownUntil <= now }
                    val needsSelection = current == null ||
                        ServerRepository.isRestrictedAcademicSubnet(current.ip) ||
                        ServerRepository.isCensoredCountry(current.countryShort) ||
                        (!ServerRepository.isLowLatencyRegion(current.countryShort) && hasLowLatencyHealthy)
                    if (needsSelection && list.isNotEmpty()) {
                        val candidate = (if (hasLowLatencyHealthy) {
                            list.firstOrNull {
                                ServerRepository.isLowLatencyRegion(it.countryShort) &&
                                    it.cooldownUntil <= now &&
                                    !ServerRepository.isRestrictedAcademicSubnet(it.ip) &&
                                    !ServerRepository.isCensoredCountry(it.countryShort)
                            }
                        } else null) ?: list.firstOrNull {
                            !ServerRepository.isRestrictedAcademicSubnet(it.ip) &&
                                !ServerRepository.isCensoredCountry(it.countryShort)
                        } ?: list.first()
                        _selectedServer.value = candidate
                    }
                }
            }
            refreshServers()
        }
    }

    fun selectServer(server: VpnServer) {
        _selectedServer.value = server
        VpnStateHolder.log("Selected server: ${server.countryLong.ifBlank { server.hostName }} (${server.ip}:${server.customPort})")
        val activeStatus = vpnState.value.status
        val isActive = activeStatus == VpnStatus.CONNECTED ||
            activeStatus == VpnStatus.CONNECTING ||
            activeStatus == VpnStatus.AUTHENTICATING ||
            activeStatus == VpnStatus.RECONNECTING
        if (isActive && vpnState.value.currentServer?.hostName != server.hostName && VpnService.prepare(context) == null) {
            connect(server)
        }
    }

    fun setSearchQuery(query: String) {
        _searchQuery.value = query
    }

    fun refreshServers() {
        if (_isRefreshing.value) return
        viewModelScope.launch {
            _isRefreshing.value = true
            try {
                val currentSettings = preferencesManager.settingsFlow.first()
                serverRepository.refreshServers(currentSettings.mirrorUrls)
            } finally {
                _isRefreshing.value = false
            }
        }
    }

    private fun resolveLearnedProtocolForCurrentNetwork(): String? {
        val currentSettings = settings.value
        if (currentSettings.vpnProtocol != VpnProtocol.AUTO_SMART) return null
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val profileKey = VpnStateHolder.resolveNetworkProfileKey(cm, null, context)
        return currentSettings.vpnProtocolProfiles[profileKey]
    }

    fun connectSelectedServer() {
        val proto = settings.value.vpnProtocol
        if (proto == VpnProtocol.WARP || resolveLearnedProtocolForCurrentNetwork() == VpnProtocol.WARP.name) {
            connectWarp()
            return
        }
        var server = _selectedServer.value
        val now = System.currentTimeMillis()
        val hasLowLatencyHealthy = servers.value.any { ServerRepository.isLowLatencyRegion(it.countryShort) && it.cooldownUntil <= now }
        if (server == null ||
            ServerRepository.isRestrictedAcademicSubnet(server.ip) ||
            ServerRepository.isCensoredCountry(server.countryShort) ||
            (!ServerRepository.isLowLatencyRegion(server.countryShort) && hasLowLatencyHealthy)
        ) {
            server = (if (hasLowLatencyHealthy) {
                servers.value.firstOrNull {
                    ServerRepository.isLowLatencyRegion(it.countryShort) &&
                        it.cooldownUntil <= now &&
                        !ServerRepository.isRestrictedAcademicSubnet(it.ip) &&
                        !ServerRepository.isCensoredCountry(it.countryShort)
                }
            } else null) ?: servers.value.firstOrNull {
                !ServerRepository.isRestrictedAcademicSubnet(it.ip) &&
                    !ServerRepository.isCensoredCountry(it.countryShort)
            } ?: servers.value.firstOrNull()
        }
        if (server == null) {
            addLog("No server selected. Initializing server list...")
            viewModelScope.launch {
                serverRepository.ensureInitialized()
            }
            return
        }
        connect(server)
    }

    fun connectWarp() {
        val sstpIntent = Intent(context, AetherVpnService::class.java).apply {
            action = AetherVpnService.ACTION_DISCONNECT
        }
        try { context.startService(sstpIntent) } catch (_: Exception) {}

        val warpIntent = WarpService.buildConnectIntent(context)
        try {
            ContextCompat.startForegroundService(context, warpIntent)
            addLog("Starting Cloudflare WARP with clean IP scanner...")
        } catch (e: Exception) {
            addLog("Failed to start WARP service: ${e.message}")
        }
    }

    fun quickConnect() {
        val proto = settings.value.vpnProtocol
        if (proto == VpnProtocol.WARP || resolveLearnedProtocolForCurrentNetwork() == VpnProtocol.WARP.name) {
            connectWarp()
            return
        }
        viewModelScope.launch {
            val best = serverRepository.getBestServer()
            if (best != null) {
                _selectedServer.value = best
                connect(best)
            } else {
                addLog("No server available for Quick Connect. Prepopulating...")
                serverRepository.ensureInitialized()
            }
        }
    }

    private fun connect(server: VpnServer) {
        _selectedServer.value = server
        val warpIntent = WarpService.buildDisconnectIntent(context)
        try { context.startService(warpIntent) } catch (_: Exception) {}

        val intent = AetherVpnService.buildConnectIntent(context, server)
        try {
            ContextCompat.startForegroundService(context, intent)
            addLog("Connecting to ${server.countryLong.ifBlank { server.hostName }} (${server.ip}:${server.customPort})...")
        } catch (e: Exception) {
            addLog("Failed to start VPN service: ${e.message}")
        }
    }

    fun switchToAnotherServer() {
        val isWarpActive = vpnState.value.currentServer?.countryShort == "CF"
        if (settings.value.vpnProtocol == VpnProtocol.WARP || isWarpActive) {
            rescanWarpCleanIp()
            return
        }
        viewModelScope.launch {
            if (VpnService.prepare(context) != null) return@launch
            val current = vpnState.value.currentServer ?: _selectedServer.value
            val excluded = buildSet {
                current?.hostName?.takeIf { it.isNotBlank() }?.let { add(it) }
                current?.ip?.takeIf { it.isNotBlank() }?.let { add(it) }
            }
            val next = serverRepository.getBestServer(excludeHosts = excluded)
            if (next != null) {
                addLog("Switching to next healthy server: ${next.countryLong.ifBlank { next.hostName }} (${next.ip})")
                connect(next)
            } else {
                addLog("No alternative server available right now.")
            }
        }
    }

    fun rescanWarpCleanIp() {
        val intent = Intent(context, WarpService::class.java).apply {
            action = WarpService.ACTION_RESCAN
        }
        try {
            ContextCompat.startForegroundService(context, intent)
            addLog("Rescanning for fresh Cloudflare Clean IP...")
        } catch (e: Exception) {
            addLog("Failed to rescan WARP: ${e.message}")
        }
    }

    fun setVpnProtocol(protocol: VpnProtocol) {
        viewModelScope.launch {
            preferencesManager.updateVpnProtocol(protocol)
            addLog("Selected protocol: ${protocol.displayName}")
        }
    }

    fun updateSoftEtherConnections(count: Int) {
        viewModelScope.launch {
            preferencesManager.updateSoftEtherConnections(count)
            addLog("SoftEther parallel connections set to: $count")
        }
    }

    fun disconnect() {
        val sstpIntent = Intent(context, AetherVpnService::class.java).apply {
            action = AetherVpnService.ACTION_DISCONNECT
        }
        try {
            context.startService(sstpIntent)
        } catch (_: Exception) {
            context.stopService(sstpIntent)
        }

        val warpIntent = WarpService.buildDisconnectIntent(context)
        try {
            context.startService(warpIntent)
        } catch (_: Exception) {
            context.stopService(warpIntent)
        }
        addLog("Disconnected by user.")
    }

    fun toggleFavorite(server: VpnServer) {
        viewModelScope.launch {
            serverRepository.toggleFavorite(server)
        }
    }

    fun saveCustomServer(server: VpnServer, previousHostName: String? = null) {
        viewModelScope.launch {
            serverRepository.saveCustomServer(server, previousHostName)
            val prevKey = previousHostName ?: server.hostName
            if (_selectedServer.value?.hostName == prevKey) {
                _selectedServer.value = server
            }
        }
    }

    fun deleteServer(server: VpnServer) {
        viewModelScope.launch {
            serverRepository.deleteServer(server)
        }
    }

    fun clearServerCooldowns() {
        viewModelScope.launch {
            serverRepository.clearServerCooldowns()
            addLog("Cleared temporary server cooldowns.")
        }
    }

    fun refreshIranCidrs() {
        if (_isUpdatingCidrs.value) return
        viewModelScope.launch {
            _isUpdatingCidrs.value = true
            try {
                val res = serverRepository.refreshIranCidrs()
                _iranCidrInfo.value = IranRoutingRules.getCidrSourceInfo(context)
                if (res.isSuccess) {
                    reconnectIfActive()
                }
            } finally {
                _isUpdatingCidrs.value = false
            }
        }
    }

    fun resetIranCidrsToBundled() {
        viewModelScope.launch {
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                IranRoutingRules.resetIranCidrsToBundled(context)
            }
            _iranCidrInfo.value = IranRoutingRules.getCidrSourceInfo(context)
            addLog("Restored bundled Iran CIDR table (${_iranCidrInfo.value.count} prefixes).")
            reconnectIfActive()
        }
    }

    fun testServerPing(server: VpnServer) {
        viewModelScope.launch {
            serverRepository.testServerPing(server)
        }
    }

    fun testBatchPings(maxServers: Int = 20) {
        if (_isBatchPinging.value) return
        viewModelScope.launch {
            _isBatchPinging.value = true
            _batchPingProgress.value = Pair(0, maxServers)
            try {
                serverRepository.testBatchPings(maxServers) { current, total ->
                    _batchPingProgress.value = Pair(current, total)
                }
            } finally {
                _isBatchPinging.value = false
                _batchPingProgress.value = null
            }
        }
    }

    fun updateStrictCert(enabled: Boolean) = viewModelScope.launch {
        preferencesManager.updateStrictCert(enabled)
    }

    fun updateDnsMode(mode: DnsMode) = viewModelScope.launch {
        preferencesManager.updateDnsMode(mode)
    }

    fun updateSelectedDnsId(id: String) = viewModelScope.launch {
        preferencesManager.updateSelectedDnsId(id)
    }

    fun updateSniStrategy(strategy: SniStrategy) = viewModelScope.launch {
        preferencesManager.updateSniStrategy(strategy)
    }

    fun updateCustomSni(sni: String) = viewModelScope.launch {
        preferencesManager.updateCustomSni(sni)
    }

    fun updateMtu(mtu: Int) = viewModelScope.launch {
        preferencesManager.updateMtu(mtu)
    }

    fun updateKeepalive(sec: Int) = viewModelScope.launch {
        preferencesManager.updateKeepalive(sec)
    }

    fun updateKillSwitch(enabled: Boolean) = viewModelScope.launch {
        preferencesManager.updateKillSwitch(enabled)
    }

    fun updateAutoFailover(enabled: Boolean) = viewModelScope.launch {
        preferencesManager.updateAutoFailover(enabled)
    }

    fun updateBlockQuic(enabled: Boolean) = viewModelScope.launch {
        preferencesManager.updateBlockQuic(enabled)
        reconnectIfActive()
    }

    fun updateBypassIran(enabled: Boolean) = viewModelScope.launch {
        preferencesManager.updateBypassIran(enabled)
        reconnectIfActive()
    }

    fun updateBlockIpv6(enabled: Boolean) = viewModelScope.launch {
        preferencesManager.updateBlockIpv6(enabled)
        reconnectIfActive()
    }

    fun updateCustomBypassRules(rules: String) = viewModelScope.launch {
        preferencesManager.updateCustomBypassRules(rules)
        addLog("Updated custom bypass rules.")
        reconnectIfActive()
    }

    fun clearLearnedBypassProfiles() = viewModelScope.launch {
        preferencesManager.clearLearnedBypassProfiles()
        addLog("Cleared learned per-network SNI bypass profiles.")
    }

    fun runSmartBypassScan() {
        val currentStatus = vpnState.value.status
        if (vpnState.value.isScanningBypass) return
        if (currentStatus != VpnStatus.DISCONNECTED && currentStatus != VpnStatus.ERROR) {
            addLog("Disconnect VPN first to scan raw ISP filtering behavior.")
            return
        }

        viewModelScope.launch {
            VpnStateHolder.updateScanningBypass(true)
            try {
                val currentSettings = preferencesManager.settingsFlow.first()
                val target = _selectedServer.value
                    ?: serverRepository.getBestServer()
                    ?: servers.value.firstOrNull()
                if (target == null) {
                    addLog("No server available for smart bypass scan.")
                    return@launch
                }

                val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                val profileKey = VpnStateHolder.resolveNetworkProfileKey(cm, null, context)
                val preferred = currentSettings.vpnBypassProfiles[profileKey]
                    ?.let { key -> SniStrategy.entries.firstOrNull { it.name == key && it.isConcreteTransport } }
                val customSniOverride = target.customSni?.takeIf { it.isNotBlank() }
                    ?: currentSettings.customSni.takeIf { it.isNotBlank() }

                val diagnosis = withContext(kotlinx.coroutines.Dispatchers.IO) {
                    val inetAddr = InetAddress.getByName(target.ip)
                    val dnsPoisoned = probeSystemDnsPoisoning()
                    CensorshipDetector.detectBestStrategy(
                        host = target.hostName,
                        ipAddress = inetAddr,
                        port = target.customPort,
                        networkProfile = profileKey,
                        preferredStrategy = preferred,
                        customSni = customSniOverride,
                        strictCert = currentSettings.strictCert,
                        stopOnFirstWinner = false,
                        dnsPoisoningDetected = dnsPoisoned
                    )
                }

                VpnStateHolder.updateDiagnosis(diagnosis)
                val winner = diagnosis.recommendedStrategy
                if (winner != null) {
                    preferencesManager.updateVpnBypassProfile(profileKey, winner.name)
                    addLog(
                        "Smart Scan [$profileKey] ${target.ip}: ${diagnosis.classification.summaryKey} -> " +
                            "winner ${winner.displayName} (DNS poisoned=${diagnosis.dnsPoisoningDetected == true})"
                    )
                } else {
                    addLog(
                        "Smart Scan [$profileKey] ${target.ip}: ${diagnosis.classification.summaryKey} (no bypass succeeded on this server)"
                    )
                }
            } catch (e: Exception) {
                addLog("Smart bypass scan error: ${e.message}")
            } finally {
                VpnStateHolder.updateScanningBypass(false)
            }
        }
    }

    private suspend fun probeSystemDnsPoisoning(): Boolean {
        return withTimeoutOrNull(1800L) {
            try {
                val addrs = InetAddress.getAllByName("telegram.org")
                addrs.isEmpty() || addrs.any { addr ->
                    addr.isSiteLocalAddress || addr.isLoopbackAddress || addr.isAnyLocalAddress
                }
            } catch (_: Exception) {
                true
            }
        } ?: true
    }

    private fun reconnectIfActive() {
        val status = vpnState.value.status
        val isActive = status == VpnStatus.CONNECTED ||
            status == VpnStatus.CONNECTING ||
            status == VpnStatus.AUTHENTICATING ||
            status == VpnStatus.RECONNECTING
        if (!isActive || VpnService.prepare(context) != null) return
        val target = vpnState.value.currentServer ?: _selectedServer.value ?: return
        VpnStateHolder.log("Settings changed; re-applying tunnel configuration...")
        connect(target)
    }

    fun updateSplitTunnelMode(mode: SplitTunnelMode) = viewModelScope.launch {
        preferencesManager.updateSplitTunnelMode(mode)
    }

    fun updateAllowedPackages(pkgs: Set<String>) = viewModelScope.launch {
        preferencesManager.updateAllowedPackages(pkgs)
    }

    fun updateDisallowedPackages(pkgs: Set<String>) = viewModelScope.launch {
        preferencesManager.updateDisallowedPackages(pkgs)
    }

    fun updateMirrorUrls(urls: String) = viewModelScope.launch {
        preferencesManager.updateMirrorUrls(urls)
    }

    fun resetMirrorUrlsToDefault() = viewModelScope.launch {
        preferencesManager.resetMirrorUrlsToDefault()
        addLog("Restored default censorship-resistant mirrors.")
    }

    fun updateLanguage(lang: String) = viewModelScope.launch {
        preferencesManager.updateLanguage(lang)
    }

    fun addLog(entry: String) {
        VpnStateHolder.log(entry)
    }

    fun clearLogs() {
        VpnStateHolder.clearLogs()
    }
}

