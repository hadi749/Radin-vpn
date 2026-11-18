package com.aethervpn.client.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.aethervpn.client.BuildConfig
import com.aethervpn.client.R
import com.aethervpn.client.data.datastore.UserSettings
import com.aethervpn.client.data.datastore.VpnProtocol
import com.aethervpn.client.data.routing.IranRoutingRules
import com.aethervpn.vpncore.transport.CensorshipDiagnosis
import com.aethervpn.vpncore.transport.SniStrategy
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    settings: UserSettings,
    onVpnProtocolChange: (VpnProtocol) -> Unit = {},
    onSoftEtherConnectionsChange: (Int) -> Unit = {},
    onStrictCertChange: (Boolean) -> Unit,
    onSniStrategyChange: (SniStrategy) -> Unit,
    onCustomSniChange: (String) -> Unit,
    onMtuChange: (Int) -> Unit,
    onKeepaliveChange: (Int) -> Unit,
    onKillSwitchChange: (Boolean) -> Unit,
    onAutoFailoverChange: (Boolean) -> Unit,
    onBlockQuicChange: (Boolean) -> Unit,
    onBypassIranChange: (Boolean) -> Unit,
    onBlockIpv6Change: (Boolean) -> Unit = {},
    onCustomBypassRulesChange: (String) -> Unit = {},
    iranCidrInfo: IranRoutingRules.CidrSourceInfo = IranRoutingRules.CidrSourceInfo(0, false, 0L),
    isUpdatingCidrs: Boolean = false,
    onRefreshIranCidrs: () -> Unit = {},
    onResetIranCidrs: () -> Unit = {},
    onResetLearnedProfiles: () -> Unit = {},
    isScanningBypass: Boolean = false,
    latestDiagnosis: CensorshipDiagnosis? = null,
    onSmartScanClick: () -> Unit = {},
    onMirrorUrlsChange: (String) -> Unit,
    onResetMirrorUrls: () -> Unit = {},
    onLanguageChange: (String) -> Unit,
    onOpenDisclaimer: () -> Unit,
    onOpenLogs: () -> Unit = {}
) {
    var showSniDialog by remember { mutableStateOf(false) }
    var customBypassDraft by remember(settings.customBypassRules) { mutableStateOf(settings.customBypassRules) }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.nav_settings)) },
                actions = {
                    IconButton(onClick = onOpenLogs) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.List,
                            contentDescription = stringResource(R.string.nav_logs)
                        )
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // VPN Protocol Engine Selector
            Card(
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = stringResource(R.string.vpn_protocol_title),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = stringResource(R.string.vpn_protocol_desc),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    VpnProtocol.entries.forEach { proto ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onVpnProtocolChange(proto) }
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = (settings.vpnProtocol == proto),
                                onClick = { onVpnProtocolChange(proto) }
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Column {
                                Text(
                                    text = proto.displayName,
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = if (settings.vpnProtocol == proto) FontWeight.Bold else FontWeight.Normal
                                )
                                Text(
                                    text = when (proto) {
                                        VpnProtocol.AUTO_SMART -> "تشخیص هوشمند فیلترینگ و انتخاب خودکار سریع‌ترین پروتکل (SoftEther / SSTP / WARP)"
                                        VpnProtocol.SOFTETHER_NATIVE -> "باندینگ چندکانکشن موازی TCP • بالاترین سرعت و مقاومت"
                                        VpnProtocol.SSTP -> "تونل استاندارد تک‌سوکت HTTPS برای سرورهای VPN Gate"
                                        VpnProtocol.WARP -> "شبکه Anycast پرسرعت کلودفلر با اسکنر خودکار Clean IP"
                                    },
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }

            // SoftEther Parallel Connections Slider
            if (settings.vpnProtocol == VpnProtocol.SOFTETHER_NATIVE || settings.vpnProtocol == VpnProtocol.AUTO_SMART) {
                Card(
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = stringResource(R.string.softether_connections_title),
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = "${settings.softEtherConnections} Ch",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.primary,
                                fontWeight = FontWeight.Bold
                            )
                        }
                        Text(
                            text = stringResource(R.string.softether_connections_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Slider(
                            value = settings.softEtherConnections.toFloat(),
                            onValueChange = { onSoftEtherConnectionsChange(it.toInt()) },
                            valueRange = 1f..16f,
                            steps = 14
                        )
                    }
                }
            }

            // SNI Bypass Section
            Card(
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { showSniDialog = true },
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(stringResource(R.string.sni_bypass_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                            Text(settings.sniStrategy.displayName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                        }
                    }

                    if (settings.sniStrategy == SniStrategy.CUSTOM_SNI ||
                        settings.sniStrategy == SniStrategy.DECOY_SNI_FRAGMENT
                    ) {
                        Spacer(modifier = Modifier.height(10.dp))
                        OutlinedTextField(
                            value = settings.customSni,
                            onValueChange = onCustomSniChange,
                            label = { Text("Custom / Decoy SNI hostname") },
                            placeholder = { Text(SniStrategy.DEFAULT_DECOY_SNIS.first()) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            items(SniStrategy.DEFAULT_DECOY_SNIS) { decoy ->
                                SuggestionChip(
                                    onClick = { onCustomSniChange(decoy) },
                                    label = { Text(decoy, style = MaterialTheme.typography.labelSmall) }
                                )
                            }
                        }
                    }

                    latestDiagnosis?.let { diag ->
                        Spacer(modifier = Modifier.height(10.dp))
                        val recName = diag.recommendedStrategy?.displayName ?: "—"
                        Text(
                            text = "${stringResource(R.string.filter_type_label)}: ${filterClassificationLabel(diag.classification)} • ${stringResource(R.string.recommended_bypass_label)}: $recName",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }

                    if (isScanningBypass) {
                        Spacer(modifier = Modifier.height(8.dp))
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    }

                    if (settings.vpnBypassProfiles.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(10.dp))
                        val profileSummary = settings.vpnBypassProfiles.entries
                            .joinToString(", ") { "${it.key}: ${it.value}" }
                        Text(
                            text = "${stringResource(R.string.learned_profiles_label)}: $profileSummary",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        OutlinedButton(
                            onClick = onSmartScanClick,
                            enabled = !isScanningBypass,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(
                                text = stringResource(
                                    if (isScanningBypass) R.string.smart_detect_scanning else R.string.smart_detect_scan
                                )
                            )
                        }
                        if (settings.vpnBypassProfiles.isNotEmpty()) {
                            TextButton(onClick = onResetLearnedProfiles) {
                                Text(stringResource(R.string.reset_learned_profiles))
                            }
                        }
                    }
                }
            }

            SettingsSwitchCard(
                title = stringResource(R.string.strict_cert_title),
                description = stringResource(R.string.strict_cert_desc),
                checked = settings.strictCert,
                onCheckedChange = onStrictCertChange
            )

            SettingsSwitchCard(
                title = stringResource(R.string.kill_switch_title),
                description = stringResource(R.string.kill_switch_desc),
                checked = settings.killSwitch,
                onCheckedChange = onKillSwitchChange
            )

            SettingsSwitchCard(
                title = stringResource(R.string.auto_failover_title),
                description = stringResource(R.string.auto_failover_desc),
                checked = settings.autoFailover,
                onCheckedChange = onAutoFailoverChange
            )

            SettingsSwitchCard(
                title = stringResource(R.string.block_quic_title),
                description = stringResource(R.string.block_quic_desc),
                checked = settings.blockQuic,
                onCheckedChange = onBlockQuicChange
            )

            SettingsSwitchCard(
                title = stringResource(R.string.bypass_iran_title),
                description = stringResource(R.string.bypass_iran_desc),
                checked = settings.bypassIran,
                onCheckedChange = onBypassIranChange
            )

            SettingsSwitchCard(
                title = stringResource(R.string.block_ipv6_title),
                description = stringResource(R.string.block_ipv6_desc),
                checked = settings.blockIpv6,
                onCheckedChange = onBlockIpv6Change
            )

            // Custom Direct Bypass Rules
            Card(
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = stringResource(R.string.custom_bypass_title),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = stringResource(R.string.custom_bypass_desc),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = customBypassDraft,
                        onValueChange = { customBypassDraft = it },
                        placeholder = { Text(stringResource(R.string.custom_bypass_hint)) },
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 2,
                        maxLines = 4
                    )
                    if (customBypassDraft.trim() != settings.customBypassRules.trim()) {
                        Spacer(modifier = Modifier.height(6.dp))
                        TextButton(
                            onClick = { onCustomBypassRulesChange(customBypassDraft) },
                            modifier = Modifier.align(Alignment.End)
                        ) {
                            Text(stringResource(R.string.apply_rules), fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }

            // Iran IPv4 CIDR Source & Remote Update
            Card(
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = stringResource(R.string.iran_cidr_source_title),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    val sourceSummary = if (iranCidrInfo.isCustomUpdated) {
                        val updatedStamp = if (iranCidrInfo.updatedAtMs > 0L) {
                            " • " + SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)
                                .format(Date(iranCidrInfo.updatedAtMs))
                        } else {
                            ""
                        }
                        stringResource(R.string.iran_cidr_source_updated, iranCidrInfo.count) + updatedStamp
                    } else {
                        stringResource(R.string.iran_cidr_source_bundled, iranCidrInfo.count)
                    }
                    Text(
                        text = sourceSummary,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (isUpdatingCidrs) {
                        Spacer(modifier = Modifier.height(8.dp))
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = onRefreshIranCidrs,
                            enabled = !isUpdatingCidrs,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(
                                text = stringResource(
                                    if (isUpdatingCidrs) R.string.updating_iran_cidrs else R.string.update_iran_cidrs
                                )
                            )
                        }
                        if (iranCidrInfo.isCustomUpdated) {
                            TextButton(
                                onClick = onResetIranCidrs,
                                enabled = !isUpdatingCidrs
                            ) {
                                Text(stringResource(R.string.reset_bundled_cidrs))
                            }
                        }
                    }
                }
            }

            // MTU Slider
            Card(
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Tunnel MTU: ${settings.mtu}", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Slider(
                        value = settings.mtu.toFloat(),
                        onValueChange = { onMtuChange(it.toInt()) },
                        valueRange = 1280f..1500f,
                        steps = 21
                    )
                }
            }

            // Keepalive Slider
            Card(
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("SSTP Echo Keepalive: ${settings.keepaliveSec}s", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Slider(
                        value = settings.keepaliveSec.toFloat(),
                        onValueChange = { onKeepaliveChange(it.toInt()) },
                        valueRange = 10f..60f,
                        steps = 5
                    )
                }
            }

            // Mirror URLs
            Card(
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("VPN Gate Mirror / API URLs", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        TextButton(onClick = onResetMirrorUrls) {
                            Text(stringResource(R.string.restore_default_mirrors), style = MaterialTheme.typography.labelSmall)
                        }
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    OutlinedTextField(
                        value = settings.mirrorUrls,
                        onValueChange = onMirrorUrlsChange,
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 2,
                        maxLines = 4
                    )
                }
            }

            // Connection Logs shortcut
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onOpenLogs() },
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(stringResource(R.string.nav_logs), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        Text(stringResource(R.string.view_logs_desc), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.List,
                        contentDescription = stringResource(R.string.nav_logs),
                        tint = MaterialTheme.colorScheme.primary
                    )
                }
            }

            // Disclaimer Button
            TextButton(
                onClick = onOpenDisclaimer,
                modifier = Modifier.align(Alignment.CenterHorizontally)
            ) {
                Text(stringResource(R.string.disclaimer_title), color = MaterialTheme.colorScheme.primary)
            }

            Text(
                text = "${stringResource(R.string.app_name)} • ${stringResource(R.string.app_version_label)} ${BuildConfig.VERSION_NAME} (Build ${BuildConfig.VERSION_CODE})",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier
                    .align(Alignment.CenterHorizontally)
                    .padding(bottom = 8.dp)
            )
        }
    }

    if (showSniDialog) {
        AlertDialog(
            onDismissRequest = { showSniDialog = false },
            title = { Text(stringResource(R.string.sni_bypass_title)) },
            text = {
                Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                    for (strategy in SniStrategy.entries) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    onSniStrategyChange(strategy)
                                    showSniDialog = false
                                }
                                .padding(vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = settings.sniStrategy == strategy,
                                onClick = {
                                    onSniStrategyChange(strategy)
                                    showSniDialog = false
                                }
                            )
                            Text(strategy.displayName, modifier = Modifier.padding(start = 8.dp))
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { showSniDialog = false }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}

@Composable
private fun SettingsSwitchCard(
    title: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Switch(checked = checked, onCheckedChange = onCheckedChange)
        }
    }
}

