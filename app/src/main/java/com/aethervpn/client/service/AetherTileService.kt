package com.aethervpn.client.service

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import com.aethervpn.client.R
import com.aethervpn.client.data.datastore.PreferencesManager
import com.aethervpn.client.data.datastore.VpnProtocol
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

@RequiresApi(Build.VERSION_CODES.N)
class AetherTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        val tile = qsTile ?: return
        val session = VpnStateHolder.state.value
        val isActive = isTunnelActive(session.status)
        tile.state = if (isActive) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = when (session.status) {
                VpnStatus.CONNECTED -> session.currentServer?.countryLong?.ifBlank { session.currentServer.ip }
                    ?: getString(R.string.status_connected)
                VpnStatus.CONNECTING, VpnStatus.AUTHENTICATING, VpnStatus.RECONNECTING -> getString(R.string.status_reconnecting)
                else -> getString(R.string.status_disconnected)
            }
        }
        tile.updateTile()
    }

    override fun onClick() {
        super.onClick()
        val isActive = isTunnelActive(VpnStateHolder.state.value.status)
        if (isActive) {
            val disconnectSstp = Intent(this, AetherVpnService::class.java).apply {
                action = AetherVpnService.ACTION_DISCONNECT
            }
            try { ContextCompat.startForegroundService(this, disconnectSstp) } catch (_: Exception) {}

            val disconnectWarp = WarpService.buildDisconnectIntent(this)
            try { ContextCompat.startForegroundService(this, disconnectWarp) } catch (_: Exception) {}
            return
        }

        if (VpnService.prepare(this) == null) {
            CoroutineScope(Dispatchers.IO).launch {
                val pref = PreferencesManager(applicationContext)
                val settings = pref.settingsFlow.first()
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                val profileKey = VpnStateHolder.resolveNetworkProfileKey(cm, null, applicationContext)
                val learnedProto = if (settings.vpnProtocol == VpnProtocol.AUTO_SMART) {
                    settings.vpnProtocolProfiles[profileKey]
                } else {
                    null
                }
                val startWarp = settings.vpnProtocol == VpnProtocol.WARP ||
                    (settings.vpnProtocol == VpnProtocol.AUTO_SMART &&
                        (learnedProto == null || learnedProto == VpnProtocol.WARP.name))
                if (startWarp) {
                    ContextCompat.startForegroundService(
                        applicationContext,
                        WarpService.buildConnectIntent(applicationContext)
                    )
                } else {
                    val best = AetherVpnService.findBestStoredServer(applicationContext)
                    if (best != null) {
                        ContextCompat.startForegroundService(
                            applicationContext,
                            AetherVpnService.buildConnectIntent(applicationContext, best)
                        )
                    } else {
                        launchApp()
                    }
                }
            }
        } else {
            launchApp()
        }
    }

    private fun launchApp() {
        val appIntent = packageManager.getLaunchIntentForPackage(packageName) ?: return
        appIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pending = PendingIntent.getActivity(
                this,
                0,
                appIntent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            startActivityAndCollapse(pending)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(appIntent)
        }
    }

    private fun isTunnelActive(status: VpnStatus): Boolean =
        status == VpnStatus.CONNECTED ||
            status == VpnStatus.CONNECTING ||
            status == VpnStatus.AUTHENTICATING ||
            status == VpnStatus.RECONNECTING
}

