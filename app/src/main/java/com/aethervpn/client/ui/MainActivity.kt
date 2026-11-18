package com.aethervpn.client.ui

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.core.content.ContextCompat
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.aethervpn.client.data.datastore.VpnProtocol
import com.aethervpn.client.ui.components.DisclaimerDialog
import com.aethervpn.client.ui.navigation.BottomNavScreens
import com.aethervpn.client.ui.navigation.Screen
import com.aethervpn.client.ui.screens.DnsScreen
import com.aethervpn.client.ui.screens.HomeScreen
import com.aethervpn.client.ui.screens.LogsScreen
import com.aethervpn.client.ui.screens.PerAppFilterScreen
import com.aethervpn.client.ui.screens.ServersScreen
import com.aethervpn.client.ui.screens.SettingsScreen
import com.aethervpn.client.ui.theme.AetherVpnTheme
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            viewModel.addLog("Notification permission granted.")
        }
    }

    private val vpnConsentLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.addLog("VPN permission granted by user.")
            viewModel.connectSelectedServer()
        } else {
            viewModel.addLog("VPN permission was denied by user.")
            Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun checkAndConnectVpn() {
        requestNotificationPermissionIfNeeded()
        val intent = VpnService.prepare(this)
        if (intent != null) {
            viewModel.addLog("Requesting VPN system consent...")
            vpnConsentLauncher.launch(intent)
        } else {
            when (viewModel.settings.value.vpnProtocol) {
                VpnProtocol.WARP -> {
                    Toast.makeText(this, "Connecting to Cloudflare WARP...", Toast.LENGTH_SHORT).show()
                }
                VpnProtocol.AUTO_SMART -> {
                    Toast.makeText(this, "اتصال هوشمند به سریع‌ترین پروتکل ضد فیلتر...", Toast.LENGTH_SHORT).show()
                }
                else -> {
                    val server = viewModel.selectedServer.value ?: viewModel.servers.value.firstOrNull()
                    if (server != null) {
                        Toast.makeText(this, "Connecting to ${server.countryLong.ifBlank { server.hostName }}...", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            viewModel.connectSelectedServer()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNotificationPermissionIfNeeded()
        setContent {
            AetherVpnTheme {
                MainAppContent(
                    viewModel = viewModel,
                    onConnectRequest = { checkAndConnectVpn() }
                )
            }
        }
    }
}

@Composable
fun MainAppContent(
    viewModel: MainViewModel,
    onConnectRequest: () -> Unit
) {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    val vpnState by viewModel.vpnState.collectAsState()
    val servers by viewModel.servers.collectAsState()
    val selectedServer by viewModel.selectedServer.collectAsState()
    val isRefreshing by viewModel.isRefreshing.collectAsState()
    val searchQuery by viewModel.searchQuery.collectAsState()
    val settings by viewModel.settings.collectAsState()
    val iranCidrInfo by viewModel.iranCidrInfo.collectAsState()
    val isUpdatingCidrs by viewModel.isUpdatingCidrs.collectAsState()
    val isBatchPinging by viewModel.isBatchPinging.collectAsState()
    val batchPingProgress by viewModel.batchPingProgress.collectAsState()
    val logs by viewModel.logs.collectAsState()

    var showDisclaimer by remember { mutableStateOf(false) }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        bottomBar = {
            NavigationBar {
                BottomNavScreens.forEach { screen ->
                    NavigationBarItem(
                        icon = { Icon(screen.icon, contentDescription = null) },
                        label = {
                            Text(
                                text = stringResource(screen.titleResId),
                                maxLines = 1,
                                softWrap = false,
                                overflow = TextOverflow.Ellipsis
                            )
                        },
                        selected = currentRoute == screen.route ||
                            (screen == Screen.Settings && currentRoute == Screen.Logs.route),
                        onClick = {
                            if (currentRoute != screen.route) {
                                if (screen.route == Screen.Home.route) {
                                    val popped = navController.popBackStack(Screen.Home.route, inclusive = false)
                                    if (!popped) {
                                        navController.navigate(Screen.Home.route) {
                                            popUpTo(Screen.Home.route) { inclusive = false }
                                            launchSingleTop = true
                                        }
                                    }
                                } else {
                                    navController.navigate(screen.route) {
                                        popUpTo(Screen.Home.route) { saveState = true }
                                        launchSingleTop = true
                                        restoreState = true
                                    }
                                }
                            }
                        }
                    )
                }
            }
        }
    ) { paddingValues ->
        NavHost(
            navController = navController,
            startDestination = Screen.Home.route,
            modifier = Modifier.padding(paddingValues)
        ) {
            composable(Screen.Home.route) {
                HomeScreen(
                    vpnState = vpnState,
                    selectedServer = selectedServer,
                    vpnProtocol = settings.vpnProtocol,
                    onProtocolSelected = { viewModel.setVpnProtocol(it) },
                    bypassIran = settings.bypassIran,
                    blockIpv6 = settings.blockIpv6,
                    blockQuic = settings.blockQuic,
                    onConnectClick = onConnectRequest,
                    onDisconnectClick = { viewModel.disconnect() },
                    onSwitchServerClick = { viewModel.switchToAnotherServer() },
                    onSelectServerClick = {
                        val isWarpActive = vpnState.currentServer?.countryShort == "CF"
                        if (settings.vpnProtocol == VpnProtocol.WARP || isWarpActive) {
                            viewModel.rescanWarpCleanIp()
                        } else {
                            navController.navigate(Screen.Servers.route) {
                                launchSingleTop = true
                            }
                        }
                    },
                    onOpenLogs = {
                        navController.navigate(Screen.Logs.route) { launchSingleTop = true }
                    }
                )
            }
            composable(Screen.Servers.route) {
                ServersScreen(
                    servers = servers,
                    isRefreshing = isRefreshing,
                    isBatchPinging = isBatchPinging,
                    batchPingProgress = batchPingProgress,
                    searchQuery = searchQuery,
                    onSearchQueryChange = { viewModel.setSearchQuery(it) },
                    onRefresh = { viewModel.refreshServers() },
                    onBatchPing = { viewModel.testBatchPings() },
                    onServerSelect = { server ->
                        viewModel.selectServer(server)
                        navController.popBackStack(Screen.Home.route, inclusive = false)
                    },
                    onToggleFavorite = { viewModel.toggleFavorite(it) },
                    onSaveCustomServer = { server, prevHost -> viewModel.saveCustomServer(server, prevHost) },
                    onDeleteServer = { viewModel.deleteServer(it) },
                    onClearCooldowns = { viewModel.clearServerCooldowns() },
                    onPingTest = { viewModel.testServerPing(it) },
                    onBackClick = { navController.popBackStack(Screen.Home.route, inclusive = false) }
                )
            }
            composable(Screen.Dns.route) {
                DnsScreen(
                    settings = settings,
                    onDnsModeChange = { viewModel.updateDnsMode(it) },
                    onResolverSelect = { viewModel.updateSelectedDnsId(it) }
                )
            }
            composable(Screen.PerApp.route) {
                PerAppFilterScreen(
                    settings = settings,
                    onModeChange = { viewModel.updateSplitTunnelMode(it) },
                    onAllowedPackagesChange = { viewModel.updateAllowedPackages(it) },
                    onDisallowedPackagesChange = { viewModel.updateDisallowedPackages(it) }
                )
            }
            composable(Screen.Settings.route) {
                SettingsScreen(
                    settings = settings,
                    onVpnProtocolChange = { viewModel.setVpnProtocol(it) },
                    onSoftEtherConnectionsChange = { viewModel.updateSoftEtherConnections(it) },
                    onStrictCertChange = { viewModel.updateStrictCert(it) },
                    onSniStrategyChange = { viewModel.updateSniStrategy(it) },
                    onCustomSniChange = { viewModel.updateCustomSni(it) },
                    onMtuChange = { viewModel.updateMtu(it) },
                    onKeepaliveChange = { viewModel.updateKeepalive(it) },
                    onKillSwitchChange = { viewModel.updateKillSwitch(it) },
                    onAutoFailoverChange = { viewModel.updateAutoFailover(it) },
                    onBlockQuicChange = { viewModel.updateBlockQuic(it) },
                    onBypassIranChange = { viewModel.updateBypassIran(it) },
                    onBlockIpv6Change = { viewModel.updateBlockIpv6(it) },
                    onCustomBypassRulesChange = { viewModel.updateCustomBypassRules(it) },
                    onResetLearnedProfiles = { viewModel.clearLearnedBypassProfiles() },
                    isScanningBypass = vpnState.isScanningBypass,
                    latestDiagnosis = vpnState.latestDiagnosis,
                    onSmartScanClick = { viewModel.runSmartBypassScan() },
                    iranCidrInfo = iranCidrInfo,
                    isUpdatingCidrs = isUpdatingCidrs,
                    onRefreshIranCidrs = { viewModel.refreshIranCidrs() },
                    onResetIranCidrs = { viewModel.resetIranCidrsToBundled() },
                    onMirrorUrlsChange = { viewModel.updateMirrorUrls(it) },
                    onResetMirrorUrls = { viewModel.resetMirrorUrlsToDefault() },
                    onLanguageChange = { viewModel.updateLanguage(it) },
                    onOpenDisclaimer = { showDisclaimer = true },
                    onOpenLogs = {
                        navController.navigate(Screen.Logs.route) { launchSingleTop = true }
                    }
                )
            }
            composable(Screen.Logs.route) {
                LogsScreen(
                    logs = logs,
                    onClearLogs = { viewModel.clearLogs() },
                    onNavigateBack = { navController.popBackStack() }
                )
            }
        }
    }

    if (showDisclaimer) {
        DisclaimerDialog(onDismiss = { showDisclaimer = false })
    }
}

