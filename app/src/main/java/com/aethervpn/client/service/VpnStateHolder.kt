package com.aethervpn.client.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.telephony.TelephonyManager
import com.aethervpn.client.data.model.VpnServer
import com.aethervpn.vpncore.transport.CensorshipDiagnosis
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class VpnStatus {
    DISCONNECTED,
    CONNECTING,
    AUTHENTICATING,
    CONNECTED,
    DISCONNECTING,
    RECONNECTING,
    ERROR
}

enum class ConnectPhase {
    IDLE,
    TRYING_DIRECT_SSTP,
    DETECTING_CENSORSHIP,
    CONNECTING_WITH_BYPASS,
    RACING_BACKUP_SERVERS,
    VERIFYING_INTERNET
}

data class VpnSessionState(
    val status: VpnStatus = VpnStatus.DISCONNECTED,
    val currentServer: VpnServer? = null,
    val clientIp: String = "",
    val durationSeconds: Long = 0,
    val bytesIn: Long = 0,
    val bytesOut: Long = 0,
    val speedInBps: Long = 0,
    val speedOutBps: Long = 0,
    val publicIp: String = "",
    val errorMessage: String? = null,
    val appliedSniStrategy: String = "",
    val physicalNetworkLabel: String = "",
    val splitRuleCount: Int = 0,
    val dnsCacheHits: Long = 0L,
    val dnsCacheMisses: Long = 0L,
    val speedInHistory: List<Long> = emptyList(),
    val speedOutHistory: List<Long> = emptyList(),
    val isScanningBypass: Boolean = false,
    val latestDiagnosis: CensorshipDiagnosis? = null,
    val connectPhase: ConnectPhase = ConnectPhase.IDLE,
    val phaseDetail: String = "",
    val liveStatusText: String = "قطع شده — برای اتصال لمس کنید"
)

object VpnStateHolder {
    private val _state = MutableStateFlow(VpnSessionState())
    val state: StateFlow<VpnSessionState> = _state.asStateFlow()

    private val _logs = MutableStateFlow<List<String>>(listOf("Radin VPN ready"))
    val logs: StateFlow<List<String>> = _logs.asStateFlow()

    fun log(message: String) {
        val time = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        val sanitized = message.replace(Regex("(?i)(password|pass)=([^&\\s]+)"), "$1=***")
        android.util.Log.d("AetherVpn", "[$time] $sanitized")
        _logs.value = (_logs.value + "[$time] $sanitized").takeLast(500)
    }

    fun clearLogs() {
        _logs.value = emptyList()
    }

    fun updateLiveStatus(text: String) {
        _state.value = _state.value.copy(liveStatusText = text)
        log(text)
    }

    fun translateCountryToPersian(country: String?): String {
        if (country.isNullOrBlank()) return "نامشخص"
        val lower = country.lowercase(Locale.ROOT).trim()
        return when {
            lower.contains("japan") || lower == "jp" -> "ژاپن"
            lower.contains("korea") || lower == "kr" -> "کره جنوبی"
            lower.contains("united states") || lower.contains("usa") || lower == "us" -> "آمریکا"
            lower.contains("germany") || lower == "de" -> "آلمان"
            lower.contains("france") || lower == "fr" -> "فرانسه"
            lower.contains("united kingdom") || lower.contains("uk") || lower == "gb" || lower.contains("britain") -> "انگلستان"
            lower.contains("netherlands") || lower == "nl" -> "هلند"
            lower.contains("canada") || lower == "ca" -> "کانادا"
            lower.contains("singapore") || lower == "sg" -> "سنگاپور"
            lower.contains("romania") || lower == "ro" -> "رومانی"
            lower.contains("russia") || lower == "ru" -> "روسیه"
            lower.contains("finland") || lower == "fi" -> "فنلاند"
            lower.contains("sweden") || lower == "se" -> "سوئد"
            lower.contains("switzerland") || lower == "ch" -> "سوئیس"
            lower.contains("norway") || lower == "no" -> "نروژ"
            lower.contains("poland") || lower == "pl" -> "لهستان"
            lower.contains("italy") || lower == "it" -> "ایتالیا"
            lower.contains("spain") || lower == "es" -> "اسپانیا"
            lower.contains("australia") || lower == "au" -> "استرالیا"
            lower.contains("hong kong") || lower == "hk" -> "هنگ کنگ"
            lower.contains("taiwan") || lower == "tw" -> "تایوان"
            lower.contains("turkey") || lower == "tr" -> "ترکیه"
            lower.contains("ukraine") || lower == "ua" -> "اوکراین"
            lower.contains("austria") || lower == "at" -> "اتریش"
            lower.contains("czech") || lower == "cz" -> "جمهوری چک"
            lower.contains("belgium") || lower == "be" -> "بلژیک"
            lower.contains("denmark") || lower == "dk" -> "دانمارک"
            lower.contains("ireland") || lower == "ie" -> "ایرلند"
            lower.contains("brazil") || lower == "br" -> "برزیل"
            lower.contains("india") || lower == "in" -> "هند"
            lower.contains("malaysia") || lower == "my" -> "مالزی"
            lower.contains("thailand") || lower == "th" -> "تایلند"
            lower.contains("vietnam") || lower == "vn" -> "ویتنام"
            else -> country
        }
    }

    fun translateFailureReasonToPersian(reason: String?): String {
        if (reason.isNullOrBlank()) return "عدم پاسخ سرور"
        val lower = reason.lowercase(Locale.ROOT)
        return when {
            lower.contains("443") && lower.contains("block") -> "پورت ۴۴۳ توسط فیلترینگ مسدود بود"
            lower.contains("port") && lower.contains("block") -> "پورت ارتباطی توسط فیلترینگ مسدود بود"
            lower.contains("blackhole") -> "مسدودسازی مخابرات (Blackhole)"
            lower.contains("rst") || lower.contains("reset") || lower.contains("closed by peer") -> "قطع هندشیک توسط سیستم فیلترینگ"
            lower.contains("timeout") || lower.contains("timed out") -> "عدم دریافت پاسخ از سرور (تایم‌اوت)"
            lower.contains("403") || lower.contains("401") || lower.contains("auth") -> "عدم تایید دسترسی سرور"
            lower.contains("no reachable") || (lower.contains("all") && lower.contains("blocked")) -> "مسدود بودن سرورهای تست شده"
            lower.contains("verify") || lower.contains("internet") -> "عدم دسترسی آزاد سرور به اینترنت"
            lower.contains("stall") -> "افت شدید سرعت و قطعی بسته‌ها"
            lower.contains("network switch") -> "تغییر شبکه اینترنت گوشی"
            else -> reason
        }
    }

    fun updateStatus(status: VpnStatus, message: String? = null) {
        val newLiveText = when (status) {
            VpnStatus.ERROR -> {
                val reasonFa = translateFailureReasonToPersian(message)
                "خطا در اتصال: $reasonFa • لطفاً مجدد تلاش کنید"
            }
            VpnStatus.DISCONNECTED -> "قطع شده — برای اتصال لمس کنید"
            VpnStatus.DISCONNECTING -> "درحال قطع اتصال..."
            else -> _state.value.liveStatusText
        }
        _state.value = _state.value.copy(
            status = status,
            errorMessage = message,
            liveStatusText = newLiveText
        )
        if (message != null) {
            log(message)
        }
    }

    fun updateConnected(
        server: VpnServer,
        clientIp: String,
        strategy: String,
        physicalNetworkLabel: String = "",
        splitRuleCount: Int = 0
    ) {
        val countryFa = translateCountryToPersian(server.countryLong.ifBlank { server.countryShort })
        val pingStr = if (server.ping > 0) " (پینگ: ${server.ping}ms)" else ""
        val liveText = "متصل شد • سرور $countryFa$pingStr"
        _state.value = _state.value.copy(
            status = VpnStatus.CONNECTED,
            currentServer = server,
            clientIp = clientIp,
            appliedSniStrategy = strategy,
            physicalNetworkLabel = physicalNetworkLabel,
            splitRuleCount = splitRuleCount,
            errorMessage = null,
            connectPhase = ConnectPhase.IDLE,
            phaseDetail = "",
            liveStatusText = liveText
        )
        log("Tunnel verified active. Assigned IP: $clientIp (Strategy: $strategy)")
    }

    fun updateSwitchingServer(server: VpnServer, message: String) {
        _state.value = _state.value.copy(
            status = VpnStatus.CONNECTING,
            currentServer = server,
            clientIp = "",
            publicIp = "",
            appliedSniStrategy = "",
            physicalNetworkLabel = "",
            splitRuleCount = 0,
            dnsCacheHits = 0L,
            dnsCacheMisses = 0L,
            speedInHistory = emptyList(),
            speedOutHistory = emptyList(),
            errorMessage = null
        )
        log(message)
    }

    fun updateMetrics(
        bytesIn: Long,
        bytesOut: Long,
        speedIn: Long,
        speedOut: Long,
        duration: Long,
        dnsCacheHits: Long = 0L,
        dnsCacheMisses: Long = 0L
    ) {
        val current = _state.value
        val newSpeedIn = (current.speedInHistory + speedIn).takeLast(30)
        val newSpeedOut = (current.speedOutHistory + speedOut).takeLast(30)
        _state.value = current.copy(
            bytesIn = bytesIn,
            bytesOut = bytesOut,
            speedInBps = speedIn,
            speedOutBps = speedOut,
            durationSeconds = duration,
            dnsCacheHits = dnsCacheHits,
            dnsCacheMisses = dnsCacheMisses,
            speedInHistory = newSpeedIn,
            speedOutHistory = newSpeedOut
        )
    }

    fun updatePublicIp(ip: String) {
        _state.value = _state.value.copy(publicIp = ip)
        log("Public IP verified through tunnel: $ip")
    }

    fun updateScanningBypass(scanning: Boolean) {
        _state.value = _state.value.copy(isScanningBypass = scanning)
    }

    fun updateDiagnosis(diagnosis: CensorshipDiagnosis) {
        _state.value = _state.value.copy(latestDiagnosis = diagnosis, isScanningBypass = false)
    }

    fun updateConnectPhase(phase: ConnectPhase, detail: String = "") {
        _state.value = _state.value.copy(connectPhase = phase, phaseDetail = detail)
    }

    fun resolveNetworkProfileKey(
        cm: ConnectivityManager?,
        preferredNetwork: Network? = null,
        context: Context? = null
    ): String {
        if (cm == null) return "DEFAULT"
        val network = preferredNetwork ?: cm.activeNetwork
        val caps = try {
            network?.let { cm.getNetworkCapabilities(it) }
        } catch (_: Exception) {
            null
        } ?: return "DEFAULT"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> {
                val fp = buildLinkFingerprint(cm, network)
                if (fp.isNotEmpty()) "WIFI_$fp" else "WIFI"
            }
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> {
                val carrier = resolveSanitizedCarrierToken(context)
                if (carrier.isNotEmpty()) "CELLULAR_$carrier" else "CELLULAR"
            }
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> {
                val fp = buildLinkFingerprint(cm, network)
                if (fp.isNotEmpty()) "ETHERNET_$fp" else "ETHERNET"
            }
            else -> "OTHER"
        }
    }

    private fun resolveSanitizedCarrierToken(context: Context?): String {
        if (context == null) return ""
        return try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager ?: return ""
            val raw = tm.networkOperator.takeIf { !it.isNullOrBlank() }
                ?: tm.networkOperatorName.orEmpty()
            raw.replace(Regex("[^A-Za-z0-9]"), "")
                .uppercase(Locale.US)
                .take(12)
        } catch (_: Exception) {
            ""
        }
    }

    private fun buildLinkFingerprint(cm: ConnectivityManager, network: Network?): String {
        if (network == null) return ""
        return try {
            val lp = cm.getLinkProperties(network) ?: return ""
            val dnsSig = lp.dnsServers
                .mapNotNull { it.hostAddress }
                .sorted()
                .joinToString(",")
            val raw = "${lp.interfaceName.orEmpty()}|$dnsSig"
            if (raw == "|") return ""
            val code = raw.hashCode() and 0xFFFFFF
            code.toString(16).uppercase(Locale.US).padStart(6, '0')
        } catch (_: Exception) {
            ""
        }
    }

    fun reset() {
        val current = _state.value
        _state.value = VpnSessionState(
            isScanningBypass = current.isScanningBypass,
            latestDiagnosis = current.latestDiagnosis,
            connectPhase = ConnectPhase.IDLE,
            phaseDetail = ""
        )
        log("VPN session closed.")
    }
}

