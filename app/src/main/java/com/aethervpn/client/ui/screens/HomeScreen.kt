package com.aethervpn.client.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aethervpn.client.R
import com.aethervpn.client.data.datastore.VpnProtocol
import com.aethervpn.client.data.model.VpnServer
import com.aethervpn.client.service.ConnectPhase
import com.aethervpn.client.service.VpnSessionState
import com.aethervpn.client.service.VpnStatus
import com.aethervpn.client.ui.theme.AccentAmber
import com.aethervpn.client.ui.theme.AccentGreen
import com.aethervpn.client.ui.theme.AccentRed
import com.aethervpn.vpncore.transport.FilterClassification
import java.util.Locale

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun HomeScreen(
    vpnState: VpnSessionState,
    selectedServer: VpnServer?,
    vpnProtocol: VpnProtocol = VpnProtocol.SSTP,
    onProtocolSelected: (VpnProtocol) -> Unit = {},
    bypassIran: Boolean = true,
    blockIpv6: Boolean = true,
    blockQuic: Boolean = true,
    onConnectClick: () -> Unit,
    onDisconnectClick: () -> Unit,
    onSwitchServerClick: () -> Unit = {},
    onSelectServerClick: () -> Unit,
    onOpenLogs: () -> Unit = {}
) {
    var diagnosticsExpanded by remember { mutableStateOf(false) }
    val isConnected = vpnState.status == VpnStatus.CONNECTED
    val isConnecting = vpnState.status == VpnStatus.CONNECTING ||
        vpnState.status == VpnStatus.AUTHENTICATING ||
        vpnState.status == VpnStatus.RECONNECTING
    val displayServer = if (isConnected || isConnecting) vpnState.currentServer ?: selectedServer else selectedServer

    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = if (isConnecting) 1.15f else 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(800, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "scale"
    )

    val radarTransition = rememberInfiniteTransition(label = "radar")
    val ripple1Progress by radarTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(2000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "ripple1"
    )
    val ripple2Progress by radarTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(2000, delayMillis = 1000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "ripple2"
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.SpaceBetween
    ) {
        // Header with App Title and quick Logs shortcut
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp, vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.Security,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Radin VPN",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }

            IconButton(onClick = onOpenLogs) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.List,
                    contentDescription = stringResource(R.string.nav_logs),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

        // THE ONLY LIVE STATUS ANNOUNCEMENT AREA
        CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = when (vpnState.status) {
                        VpnStatus.CONNECTED -> AccentGreen.copy(alpha = 0.12f)
                        VpnStatus.ERROR -> AccentRed.copy(alpha = 0.12f)
                        VpnStatus.CONNECTING, VpnStatus.AUTHENTICATING, VpnStatus.RECONNECTING -> MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)
                        else -> MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.65f)
                    }
                ),
                border = BorderStroke(
                    1.dp,
                    when (vpnState.status) {
                        VpnStatus.CONNECTED -> AccentGreen.copy(alpha = 0.45f)
                        VpnStatus.ERROR -> AccentRed.copy(alpha = 0.45f)
                        VpnStatus.CONNECTING, VpnStatus.AUTHENTICATING, VpnStatus.RECONNECTING -> MaterialTheme.colorScheme.primary.copy(alpha = 0.45f)
                        else -> MaterialTheme.colorScheme.outline.copy(alpha = 0.18f)
                    }
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 4.dp)
            ) {
                Row(
                    modifier = Modifier
                        .padding(horizontal = 16.dp, vertical = 14.dp)
                        .fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center
                ) {
                    if (isConnecting) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            strokeWidth = 2.5.dp,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                    } else {
                        Icon(
                            imageVector = when (vpnState.status) {
                                VpnStatus.CONNECTED -> Icons.Default.CheckCircle
                                VpnStatus.ERROR -> Icons.Default.Warning
                                else -> Icons.Default.PowerSettingsNew
                            },
                            contentDescription = null,
                            tint = when (vpnState.status) {
                                VpnStatus.CONNECTED -> AccentGreen
                                VpnStatus.ERROR -> AccentRed
                                else -> MaterialTheme.colorScheme.primary
                            },
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                    }

                    Text(
                        text = vpnState.liveStatusText.ifBlank {
                            when (vpnState.status) {
                                VpnStatus.CONNECTED -> "متصل شد"
                                VpnStatus.CONNECTING, VpnStatus.AUTHENTICATING, VpnStatus.RECONNECTING -> "درحال تلاش برای اتصال..."
                                VpnStatus.ERROR -> vpnState.errorMessage ?: "خطا در اتصال"
                                else -> "قطع شده — برای اتصال لمس کنید"
                            }
                        },
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = when (vpnState.status) {
                            VpnStatus.CONNECTED -> AccentGreen
                            VpnStatus.ERROR -> AccentRed
                            else -> MaterialTheme.colorScheme.onSurface
                        },
                        textAlign = TextAlign.Center
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(22.dp))

        // Big Power / Connect Button with expanding Radar ripple waves
        Box(
            modifier = Modifier.size(230.dp),
            contentAlignment = Alignment.Center
        ) {
            if (isConnecting) {
                // Expanding Radar Ripple 1
                Box(
                    modifier = Modifier
                        .size(170.dp + (60.dp * ripple1Progress))
                        .clip(CircleShape)
                        .background(
                            MaterialTheme.colorScheme.primary.copy(
                                alpha = (1f - ripple1Progress) * 0.35f
                            )
                        )
                )
                // Expanding Radar Ripple 2
                Box(
                    modifier = Modifier
                        .size(170.dp + (60.dp * ripple2Progress))
                        .clip(CircleShape)
                        .background(
                            MaterialTheme.colorScheme.primary.copy(
                                alpha = (1f - ripple2Progress) * 0.35f
                            )
                        )
                )
            }

            Box(
                modifier = Modifier
                    .size(170.dp)
                    .scale(pulseScale)
                    .clip(CircleShape)
                    .background(
                        if (isConnected) AccentGreen else MaterialTheme.colorScheme.primary
                    )
                    .clickable {
                        if (isConnected || isConnecting) {
                            onDisconnectClick()
                        } else {
                            onConnectClick()
                        }
                    },
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.PowerSettingsNew,
                    contentDescription = "Power",
                    tint = Color.White,
                    modifier = Modifier.size(70.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        Text(
            text = if (isConnected || isConnecting) stringResource(R.string.disconnect) else stringResource(R.string.connect),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.clickable {
                if (isConnected || isConnecting) {
                    onDisconnectClick()
                } else {
                    onConnectClick()
                }
            }
        )

        Spacer(modifier = Modifier.height(8.dp))

        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            StatusPillChip(
                text = if (bypassIran) {
                    stringResource(R.string.split_routing_badge)
                } else {
                    stringResource(R.string.global_routing_badge)
                },
                highlighted = bypassIran
            )
            if (blockIpv6) {
                StatusPillChip(
                    text = stringResource(R.string.ipv6_guard_badge),
                    highlighted = true
                )
            }
            if (vpnState.appliedSniStrategy.isNotBlank()) {
                StatusPillChip(
                    text = vpnState.appliedSniStrategy,
                    highlighted = false
                )
            }
        }

        Spacer(modifier = Modifier.height(22.dp))

        // Real-time Metrics Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceAround
                ) {
                    // Download
                    MetricItem(
                        icon = Icons.Default.ArrowDownward,
                        label = stringResource(R.string.download_speed),
                        value = formatSpeed(vpnState.speedInBps),
                        color = AccentGreen
                    )
                    // Upload
                    MetricItem(
                        icon = Icons.Default.ArrowUpward,
                        label = stringResource(R.string.upload_speed),
                        value = formatSpeed(vpnState.speedOutBps),
                        color = MaterialTheme.colorScheme.primary
                    )
                    // Duration
                    MetricItem(
                        icon = Icons.Default.Timer,
                        label = stringResource(R.string.duration),
                        value = formatDuration(vpnState.durationSeconds),
                        color = MaterialTheme.colorScheme.secondary
                    )
                }

                // Live Speed Graph (rendered when connected or during active traffic)
                if (vpnState.status == VpnStatus.CONNECTED || vpnState.speedInBps > 0 || vpnState.speedOutBps > 0 || vpnState.speedInHistory.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(14.dp))
                    LiveSpeedGraph(
                        speedInHistory = vpnState.speedInHistory,
                        speedOutHistory = vpnState.speedOutHistory,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(72.dp)
                    )
                }

                HorizontalDivider(
                    modifier = Modifier.padding(vertical = 12.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.2f)
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.data_transferred),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = formatBytes(vpnState.bytesIn + vpnState.bytesOut),
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }

                if (vpnState.publicIp.isNotBlank()) {
                    Spacer(modifier = Modifier.height(6.dp))
                    DiagnosticRow(
                        label = stringResource(R.string.public_ip),
                        value = vpnState.publicIp,
                        valueColor = AccentGreen
                    )
                }

                HorizontalDivider(
                    modifier = Modifier.padding(vertical = 10.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.2f)
                )

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { diagnosticsExpanded = !diagnosticsExpanded },
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.diagnostics_title),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.SemiBold
                    )
                    Icon(
                        imageVector = if (diagnosticsExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                }

                if (diagnosticsExpanded) {
                    Spacer(modifier = Modifier.height(8.dp))
                    val totalDns = vpnState.dnsCacheHits + vpnState.dnsCacheMisses
                    val hitPct = if (totalDns > 0L) ((vpnState.dnsCacheHits * 100L) / totalDns).toInt() else 0
                    DiagnosticRow(
                        label = stringResource(R.string.diag_physical_link),
                        value = vpnState.physicalNetworkLabel.ifBlank { "—" }
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    DiagnosticRow(
                        label = stringResource(R.string.diag_split_cidrs),
                        value = if (vpnState.splitRuleCount > 0) "${vpnState.splitRuleCount}" else "0"
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    DiagnosticRow(
                        label = stringResource(R.string.diag_dns_cache),
                        value = if (totalDns > 0L) "${vpnState.dnsCacheHits}/$totalDns ($hitPct%)" else "0/0"
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    val guardsText = buildList {
                        if (blockIpv6) add("IPv6")
                        if (blockQuic) add("HTTP/2")
                    }.joinToString(" • ").ifBlank { "Off" }
                    DiagnosticRow(
                        label = stringResource(R.string.diag_guards),
                        value = guardsText
                    )
                    vpnState.latestDiagnosis?.let { diag ->
                        Spacer(modifier = Modifier.height(4.dp))
                        DiagnosticRow(
                            label = stringResource(R.string.filter_type_label),
                            value = filterClassificationLabel(diag.classification)
                        )
                        if (diag.recommendedStrategy != null) {
                            Spacer(modifier = Modifier.height(4.dp))
                            DiagnosticRow(
                                label = stringResource(R.string.recommended_bypass_label),
                                value = diag.recommendedStrategy!!.displayName,
                                valueColor = AccentGreen
                            )
                        }
                        if (diag.results.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(8.dp))
                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                for (res in diag.results) {
                                    val mark = if (res.succeeded) "✓ ${res.latencyMs}ms" else "✗ ${res.detail}"
                                    StatusPillChip(
                                        text = "${res.strategy.shortLabel}: $mark",
                                        highlighted = res.succeeded
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Selected Server Card
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onSelectServerClick() },
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                val showWarpCard = vpnProtocol == VpnProtocol.WARP || (isConnected && displayServer?.countryShort == "CF")
                Icon(
                    imageVector = Icons.Default.Public,
                    contentDescription = "Server",
                    tint = if (showWarpCard) AccentAmber else MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(36.dp)
                )
                Spacer(modifier = Modifier.width(16.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = if (showWarpCard) {
                            "Cloudflare WARP (سریع و نامحدود)"
                        } else {
                            displayServer?.countryLong?.ifBlank { displayServer.hostName } ?: stringResource(R.string.select_server)
                        },
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = if (showWarpCard) {
                            if (isConnected && displayServer != null) {
                                "Anycast Clean IP: ${displayServer.ip}:${displayServer.customPort}"
                            } else {
                                "اسکنر خودکار آی‌پی تمیز کلودفلر (Anti-DPI)"
                            }
                        } else if (displayServer != null) {
                            val protoTag = when (vpnProtocol) {
                                VpnProtocol.AUTO_SMART -> " • Auto Smart (Multi-TCP / SSTP / WARP)"
                                VpnProtocol.SOFTETHER_NATIVE -> " • SoftEther Multi-TCP"
                                VpnProtocol.SSTP -> " • SSTP"
                                VpnProtocol.WARP -> " • WARP"
                            }
                            "${displayServer.hostName} (${displayServer.ip}:${displayServer.customPort})$protoTag"
                        } else {
                            "Tap to choose a VPN server"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (displayServer != null && displayServer.ping >= 0) {
                    Text(
                        text = "${displayServer.ping} ms",
                        style = MaterialTheme.typography.bodySmall,
                        color = AccentGreen,
                        fontWeight = FontWeight.Bold
                    )
                }
                if (isConnected) {
                    IconButton(onClick = onSwitchServerClick) {
                        Icon(
                            imageVector = Icons.Default.SwapHoriz,
                            contentDescription = stringResource(R.string.switch_server),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }
        }
    }
}

@Composable
internal fun filterClassificationLabel(classification: FilterClassification): String {
    return when (classification) {
        FilterClassification.OPEN_NO_FILTER -> stringResource(R.string.filter_open_no_filter)
        FilterClassification.SNI_DPI_ACTIVE -> stringResource(R.string.filter_sni_dpi)
        FilterClassification.DEEP_CLIENTHELLO_DPI -> stringResource(R.string.filter_deep_dpi)
        FilterClassification.SNI_ALLOWLIST_FILTER -> stringResource(R.string.filter_sni_allowlist)
        FilterClassification.IP_OR_PORT_BLOCKED -> stringResource(R.string.filter_ip_blocked)
        FilterClassification.UNKNOWN -> stringResource(R.string.filter_unknown)
    }
}

@Composable
private fun DiagnosticRow(
    label: String,
    value: String,
    valueColor: Color = MaterialTheme.colorScheme.onSurface
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            color = valueColor,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun StatusPillChip(text: String, highlighted: Boolean) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(16.dp))
            .background(
                if (highlighted) AccentGreen.copy(alpha = 0.14f)
                else MaterialTheme.colorScheme.surfaceVariant
            )
            .padding(horizontal = 10.dp, vertical = 4.dp)
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = if (highlighted) AccentGreen else MaterialTheme.colorScheme.onSurfaceVariant,
            fontWeight = FontWeight.Medium
        )
    }
}

@Composable
fun MetricItem(icon: androidx.compose.ui.graphics.vector.ImageVector, label: String, value: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(icon, contentDescription = label, tint = color, modifier = Modifier.size(22.dp))
        Spacer(modifier = Modifier.height(4.dp))
        Text(text = value, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        Text(text = label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

private fun formatSpeed(bps: Long): String {
    return when {
        bps >= 1_000_000 -> String.format(Locale.US, "%.1f Mbps", bps / 1_000_000.0)
        bps >= 1_000 -> String.format(Locale.US, "%.0f kbps", bps / 1_000.0)
        else -> "$bps bps"
    }
}

private fun formatBytes(bytes: Long): String {
    return when {
        bytes >= 1_073_741_824 -> String.format(Locale.US, "%.2f GB", bytes / 1_073_741_824.0)
        bytes >= 1_048_576 -> String.format(Locale.US, "%.1f MB", bytes / 1_048_576.0)
        bytes >= 1024 -> String.format(Locale.US, "%.0f KB", bytes / 1024.0)
        else -> "$bytes B"
    }
}

private fun formatDuration(seconds: Long): String {
    val hrs = seconds / 3600
    val mins = (seconds % 3600) / 60
    val secs = seconds % 60
    return if (hrs > 0) {
        String.format(Locale.US, "%02d:%02d:%02d", hrs, mins, secs)
    } else {
        String.format(Locale.US, "%02d:%02d", mins, secs)
    }
}

@Composable
fun LiveSpeedGraph(
    speedInHistory: List<Long>,
    speedOutHistory: List<Long>,
    modifier: Modifier = Modifier,
    downloadColor: Color = AccentGreen,
    uploadColor: Color = MaterialTheme.colorScheme.primary
) {
    val maxPoints = 30
    val paddedIn = remember(speedInHistory) {
        if (speedInHistory.size < maxPoints) {
            List(maxPoints - speedInHistory.size) { 0L } + speedInHistory
        } else {
            speedInHistory.takeLast(maxPoints)
        }
    }
    val paddedOut = remember(speedOutHistory) {
        if (speedOutHistory.size < maxPoints) {
            List(maxPoints - speedOutHistory.size) { 0L } + speedOutHistory
        } else {
            speedOutHistory.takeLast(maxPoints)
        }
    }

    val maxSpeed = remember(paddedIn, paddedOut) {
        maxOf(
            paddedIn.maxOrNull() ?: 0L,
            paddedOut.maxOrNull() ?: 0L,
            100_000L
        ).toFloat()
    }

    Box(modifier = modifier) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val width = size.width
            val height = size.height
            if (width <= 0 || height <= 0) return@Canvas

            val stepX = width / (maxPoints - 1).coerceAtLeast(1)
            val paddingBottom = 4.dp.toPx()
            val paddingTop = 6.dp.toPx()
            val usableHeight = height - paddingBottom - paddingTop

            val gridColor = Color.White.copy(alpha = 0.08f)
            drawLine(
                color = gridColor,
                start = Offset(0f, paddingTop),
                end = Offset(width, paddingTop),
                strokeWidth = 1.dp.toPx()
            )
            drawLine(
                color = gridColor,
                start = Offset(0f, paddingTop + usableHeight / 2),
                end = Offset(width, paddingTop + usableHeight / 2),
                strokeWidth = 1.dp.toPx()
            )
            drawLine(
                color = gridColor,
                start = Offset(0f, height - paddingBottom),
                end = Offset(width, height - paddingBottom),
                strokeWidth = 1.dp.toPx()
            )

            fun buildPath(data: List<Long>): Pair<Path, Path> {
                val strokePath = Path()
                val fillPath = Path()

                val points = data.mapIndexed { idx, speed ->
                    val x = idx * stepX
                    val normalized = (speed.toFloat() / maxSpeed).coerceIn(0f, 1f)
                    val y = (height - paddingBottom) - (normalized * usableHeight)
                    Offset(x, y)
                }

                if (points.isNotEmpty()) {
                    strokePath.moveTo(points[0].x, points[0].y)
                    fillPath.moveTo(points[0].x, height - paddingBottom)
                    fillPath.lineTo(points[0].x, points[0].y)

                    for (i in 0 until points.size - 1) {
                        val p0 = points[i]
                        val p1 = points[i + 1]
                        val cx = (p0.x + p1.x) / 2
                        strokePath.cubicTo(cx, p0.y, cx, p1.y, p1.x, p1.y)
                        fillPath.cubicTo(cx, p0.y, cx, p1.y, p1.x, p1.y)
                    }

                    fillPath.lineTo(points.last().x, height - paddingBottom)
                    fillPath.close()
                }

                return Pair(strokePath, fillPath)
            }

            // Download (Green)
            val (inStroke, inFill) = buildPath(paddedIn)
            drawPath(
                path = inFill,
                brush = Brush.verticalGradient(
                    colors = listOf(downloadColor.copy(alpha = 0.35f), downloadColor.copy(alpha = 0.02f)),
                    startY = paddingTop,
                    endY = height - paddingBottom
                )
            )
            drawPath(
                path = inStroke,
                color = downloadColor,
                style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round)
            )

            // Upload (Primary / Blue)
            val (outStroke, outFill) = buildPath(paddedOut)
            drawPath(
                path = outFill,
                brush = Brush.verticalGradient(
                    colors = listOf(uploadColor.copy(alpha = 0.25f), uploadColor.copy(alpha = 0.02f)),
                    startY = paddingTop,
                    endY = height - paddingBottom
                )
            )
            drawPath(
                path = outStroke,
                color = uploadColor,
                style = Stroke(width = 1.75.dp.toPx(), cap = StrokeCap.Round)
            )
        }

        Text(
            text = formatSpeed(maxSpeed.toLong()),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
            modifier = Modifier
                .align(Alignment.TopEnd)
                .padding(top = 2.dp, end = 4.dp)
        )
    }
}

