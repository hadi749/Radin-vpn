package com.aethervpn.client.data.datastore

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.aethervpn.vpncore.transport.SniStrategy
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "aether_vpn_settings")

enum class DnsMode(val id: Int) {
    VPN_DEFAULT(0),
    DOT_OVER_SSTP(1),
    DNS_ONLY(2);

    companion object {
        fun fromId(id: Int): DnsMode = entries.firstOrNull { it.id == id } ?: VPN_DEFAULT
    }
}

enum class SplitTunnelMode(val id: Int) {
    ALL_APPS(0),
    ALLOWED_ONLY(1),
    DISALLOWED_ONLY(2);

    companion object {
        fun fromId(id: Int): SplitTunnelMode = entries.firstOrNull { it.id == id } ?: ALL_APPS
    }
}

enum class VpnProtocol(val id: Int, val displayName: String) {
    AUTO_SMART(3, "Auto Smart (اتصال هوشمند)"),
    SOFTETHER_NATIVE(2, "SoftEther Native (Multi-TCP)"),
    SSTP(0, "SoftEther SSTP"),
    WARP(1, "Cloudflare WARP");

    companion object {
        fun fromId(id: Int): VpnProtocol = entries.firstOrNull { it.id == id } ?: AUTO_SMART
    }
}

data class UserSettings(
    val vpnProtocol: VpnProtocol = VpnProtocol.AUTO_SMART,
    val softEtherConnections: Int = 4,
    val warpAccountJson: String = "",
    val warpCleanEndpoint: String = "",
    val warpPort: Int = 2408,
    val strictCert: Boolean = false,
    val dnsMode: DnsMode = DnsMode.VPN_DEFAULT,
    val selectedDnsId: String = "cloudflare",
    val sniStrategy: SniStrategy = SniStrategy.AUTO_SMART,
    val customSni: String = "",
    val mtu: Int = 1400,
    val keepaliveSec: Int = 10,
    val killSwitch: Boolean = false,
    val autoConnectBoot: Boolean = false,
    val splitTunnelMode: SplitTunnelMode = SplitTunnelMode.ALL_APPS,
    val allowedPackages: Set<String> = emptySet(),
    val disallowedPackages: Set<String> = emptySet(),
    val mirrorUrls: String = PreferencesManager.DEFAULT_MIRROR_URLS,
    val appLanguage: String = "system",
    val lastMirrorBypassStrategy: String = "",
    val autoFailover: Boolean = true,
    val blockQuic: Boolean = true,
    val lastVpnBypassStrategy: String = "",
    val bypassIran: Boolean = true,
    val blockIpv6: Boolean = true,
    val customBypassRules: String = "",
    val vpnBypassProfiles: Map<String, String> = emptyMap(),
    val vpnProtocolProfiles: Map<String, String> = emptyMap()
)

class PreferencesManager(private val context: Context) {

    private object Keys {
        val VPN_PROTOCOL = intPreferencesKey("vpn_protocol")
        val WARP_ACCOUNT_JSON = stringPreferencesKey("warp_account_json")
        val WARP_CLEAN_ENDPOINT = stringPreferencesKey("warp_clean_endpoint")
        val WARP_PORT = intPreferencesKey("warp_port")
        val STRICT_CERT = booleanPreferencesKey("strict_cert")
        val DNS_MODE = intPreferencesKey("dns_mode")
        val SELECTED_DNS_ID = stringPreferencesKey("selected_dns_id")
        val SNI_STRATEGY = intPreferencesKey("sni_strategy")
        val CUSTOM_SNI = stringPreferencesKey("custom_sni")
        val MTU = intPreferencesKey("mtu")
        val KEEPALIVE_SEC = intPreferencesKey("keepalive_sec")
        val KILL_SWITCH = booleanPreferencesKey("kill_switch")
        val AUTO_CONNECT_BOOT = booleanPreferencesKey("auto_connect_boot")
        val SPLIT_TUNNEL_MODE = intPreferencesKey("split_tunnel_mode")
        val ALLOWED_PACKAGES = stringSetPreferencesKey("allowed_packages")
        val DISALLOWED_PACKAGES = stringSetPreferencesKey("disallowed_packages")
        val MIRROR_URLS = stringPreferencesKey("mirror_urls")
        val APP_LANGUAGE = stringPreferencesKey("app_language")
        val LAST_MIRROR_BYPASS = stringPreferencesKey("last_mirror_bypass_strategy")
        val AUTO_FAILOVER = booleanPreferencesKey("auto_failover")
        val BLOCK_QUIC = booleanPreferencesKey("block_quic")
        val LAST_VPN_BYPASS = stringPreferencesKey("last_vpn_bypass_strategy")
        val BYPASS_IRAN = booleanPreferencesKey("bypass_iran")
        val BLOCK_IPV6 = booleanPreferencesKey("block_ipv6")
        val CUSTOM_BYPASS_RULES = stringPreferencesKey("custom_bypass_rules")
        val VPN_BYPASS_PROFILES = stringPreferencesKey("vpn_bypass_profiles")
        val VPN_PROTOCOL_PROFILES = stringPreferencesKey("vpn_protocol_profiles")
        val SOFTETHER_CONNECTIONS = intPreferencesKey("softether_connections")
    }

    val settingsFlow: Flow<UserSettings> = context.dataStore.data.map { pref ->
        UserSettings(
            vpnProtocol = pref[Keys.VPN_PROTOCOL]?.let { VpnProtocol.fromId(it) } ?: VpnProtocol.AUTO_SMART,
            softEtherConnections = (pref[Keys.SOFTETHER_CONNECTIONS] ?: 4).let { if (it == 8) 4 else it }.coerceIn(1, 16),
            warpAccountJson = pref[Keys.WARP_ACCOUNT_JSON] ?: "",
            warpCleanEndpoint = pref[Keys.WARP_CLEAN_ENDPOINT] ?: "",
            warpPort = pref[Keys.WARP_PORT] ?: 2408,
            strictCert = pref[Keys.STRICT_CERT] ?: false,
            dnsMode = DnsMode.fromId(pref[Keys.DNS_MODE] ?: 0),
            selectedDnsId = pref[Keys.SELECTED_DNS_ID] ?: "cloudflare",
            sniStrategy = SniStrategy.fromId(pref[Keys.SNI_STRATEGY] ?: SniStrategy.AUTO_SMART.id),
            customSni = pref[Keys.CUSTOM_SNI] ?: "",
            mtu = pref[Keys.MTU] ?: 1400,
            keepaliveSec = pref[Keys.KEEPALIVE_SEC] ?: 10,
            killSwitch = pref[Keys.KILL_SWITCH] ?: false,
            autoConnectBoot = pref[Keys.AUTO_CONNECT_BOOT] ?: false,
            splitTunnelMode = SplitTunnelMode.fromId(pref[Keys.SPLIT_TUNNEL_MODE] ?: 0),
            allowedPackages = pref[Keys.ALLOWED_PACKAGES] ?: emptySet(),
            disallowedPackages = pref[Keys.DISALLOWED_PACKAGES] ?: emptySet(),
            mirrorUrls = pref[Keys.MIRROR_URLS]?.takeIf {
                it.startsWith("https://raw.githubusercontent.com/hadi3146")
            } ?: DEFAULT_MIRROR_URLS,
            appLanguage = pref[Keys.APP_LANGUAGE] ?: "system",
            lastMirrorBypassStrategy = pref[Keys.LAST_MIRROR_BYPASS] ?: "",
            autoFailover = pref[Keys.AUTO_FAILOVER] ?: true,
            blockQuic = pref[Keys.BLOCK_QUIC] ?: true,
            lastVpnBypassStrategy = pref[Keys.LAST_VPN_BYPASS] ?: "",
            bypassIran = pref[Keys.BYPASS_IRAN] ?: true,
            blockIpv6 = pref[Keys.BLOCK_IPV6] ?: true,
            customBypassRules = pref[Keys.CUSTOM_BYPASS_RULES] ?: "",
            vpnBypassProfiles = parseBypassProfiles(pref[Keys.VPN_BYPASS_PROFILES].orEmpty()),
            vpnProtocolProfiles = parseBypassProfiles(pref[Keys.VPN_PROTOCOL_PROFILES].orEmpty())
        )
    }

    suspend fun updateStrictCert(enabled: Boolean) {
        context.dataStore.edit { it[Keys.STRICT_CERT] = enabled }
    }

    suspend fun updateDnsMode(mode: DnsMode) {
        context.dataStore.edit { it[Keys.DNS_MODE] = mode.id }
    }

    suspend fun updateSelectedDnsId(dnsId: String) {
        context.dataStore.edit { it[Keys.SELECTED_DNS_ID] = dnsId }
    }

    suspend fun updateSniStrategy(strategy: SniStrategy) {
        context.dataStore.edit { it[Keys.SNI_STRATEGY] = strategy.id }
    }

    suspend fun updateCustomSni(sni: String) {
        context.dataStore.edit { it[Keys.CUSTOM_SNI] = sni }
    }

    suspend fun updateMtu(mtu: Int) {
        context.dataStore.edit { it[Keys.MTU] = mtu }
    }

    suspend fun updateKeepalive(seconds: Int) {
        context.dataStore.edit { it[Keys.KEEPALIVE_SEC] = seconds }
    }

    suspend fun updateKillSwitch(enabled: Boolean) {
        context.dataStore.edit { it[Keys.KILL_SWITCH] = enabled }
    }

    suspend fun updateAutoConnectBoot(enabled: Boolean) {
        context.dataStore.edit { it[Keys.AUTO_CONNECT_BOOT] = enabled }
    }

    suspend fun updateSplitTunnelMode(mode: SplitTunnelMode) {
        context.dataStore.edit { it[Keys.SPLIT_TUNNEL_MODE] = mode.id }
    }

    suspend fun updateAllowedPackages(packages: Set<String>) {
        context.dataStore.edit { it[Keys.ALLOWED_PACKAGES] = packages }
    }

    suspend fun updateDisallowedPackages(packages: Set<String>) {
        context.dataStore.edit { it[Keys.DISALLOWED_PACKAGES] = packages }
    }

    suspend fun updateMirrorUrls(urls: String) {
        context.dataStore.edit { it[Keys.MIRROR_URLS] = urls }
    }

    suspend fun resetMirrorUrlsToDefault() {
        context.dataStore.edit { it[Keys.MIRROR_URLS] = DEFAULT_MIRROR_URLS }
    }

    suspend fun updateLanguage(lang: String) {
        context.dataStore.edit { it[Keys.APP_LANGUAGE] = lang }
    }

    suspend fun updateLastMirrorBypassStrategy(strategyKey: String) {
        context.dataStore.edit { it[Keys.LAST_MIRROR_BYPASS] = strategyKey }
    }

    suspend fun updateAutoFailover(enabled: Boolean) {
        context.dataStore.edit { it[Keys.AUTO_FAILOVER] = enabled }
    }

    suspend fun updateBlockQuic(enabled: Boolean) {
        context.dataStore.edit { it[Keys.BLOCK_QUIC] = enabled }
    }

    suspend fun updateLastVpnBypassStrategy(strategyKey: String) {
        context.dataStore.edit { it[Keys.LAST_VPN_BYPASS] = strategyKey }
    }

    suspend fun updateBypassIran(enabled: Boolean) {
        context.dataStore.edit { it[Keys.BYPASS_IRAN] = enabled }
    }

    suspend fun updateBlockIpv6(enabled: Boolean) {
        context.dataStore.edit { it[Keys.BLOCK_IPV6] = enabled }
    }

    suspend fun updateCustomBypassRules(rules: String) {
        context.dataStore.edit { it[Keys.CUSTOM_BYPASS_RULES] = rules.trim() }
    }

    suspend fun updateVpnBypassProfile(networkKey: String, strategyName: String) {
        context.dataStore.edit { pref ->
            pref[Keys.LAST_VPN_BYPASS] = strategyName
            val cleanKey = networkKey.trim().uppercase()
            val cleanStrategy = strategyName.trim()
            if (cleanKey.isNotEmpty() && cleanStrategy.isNotEmpty()) {
                val updated = parseBypassProfiles(pref[Keys.VPN_BYPASS_PROFILES].orEmpty()).toMutableMap()
                updated[cleanKey] = cleanStrategy
                pref[Keys.VPN_BYPASS_PROFILES] = encodeBypassProfiles(updated)
            }
        }
    }

    suspend fun updateVpnProtocol(protocol: VpnProtocol) {
        context.dataStore.edit { it[Keys.VPN_PROTOCOL] = protocol.id }
    }

    suspend fun updateVpnProtocolProfile(networkKey: String, protocolName: String) {
        context.dataStore.edit { pref ->
            val cleanKey = networkKey.trim().uppercase()
            val cleanProto = protocolName.trim()
            if (cleanKey.isNotEmpty() && cleanProto.isNotEmpty()) {
                val updated = parseBypassProfiles(pref[Keys.VPN_PROTOCOL_PROFILES].orEmpty()).toMutableMap()
                updated[cleanKey] = cleanProto
                pref[Keys.VPN_PROTOCOL_PROFILES] = encodeBypassProfiles(updated)
            }
        }
    }

    suspend fun updateSoftEtherConnections(count: Int) {
        context.dataStore.edit { it[Keys.SOFTETHER_CONNECTIONS] = count.coerceIn(1, 16) }
    }

    suspend fun updateWarpAccountJson(json: String) {
        context.dataStore.edit { it[Keys.WARP_ACCOUNT_JSON] = json }
    }

    suspend fun updateWarpCleanEndpoint(endpoint: String) {
        context.dataStore.edit { it[Keys.WARP_CLEAN_ENDPOINT] = endpoint }
    }

    suspend fun updateWarpPort(port: Int) {
        context.dataStore.edit { it[Keys.WARP_PORT] = port }
    }

    suspend fun clearLearnedBypassProfiles() {
        context.dataStore.edit { pref ->
            pref.remove(Keys.LAST_VPN_BYPASS)
            pref.remove(Keys.LAST_MIRROR_BYPASS)
            pref.remove(Keys.VPN_BYPASS_PROFILES)
            pref.remove(Keys.VPN_PROTOCOL_PROFILES)
        }
    }

    companion object {
        const val DEFAULT_MIRROR_URLS: String =
            "https://raw.githubusercontent.com/hadi3146/vpngate-mirrors/main/servers.csv\n" +
            "https://cdn.jsdelivr.net/gh/hadi3146/vpngate-mirrors@main/servers.csv\n" +
            "https://fastly.jsdelivr.net/gh/hadi3146/vpngate-mirrors@main/servers.csv\n" +
            "https://www.vpngate.net/api/iphone/\n" +
            "http://www.vpngate.net/api/iphone/\n" +
            "http://vpngate.opengw.net/api/iphone/\n" +
            "http://www.opengw.net/api/iphone/\n" +
            "http://219.100.37.121/api/iphone/\n" +
            "http://219.100.37.122/api/iphone/"

        private val TOKEN_REGEX = Regex("^[A-Za-z0-9_:-]+$")

        fun parseBypassProfiles(raw: String): Map<String, String> {
            if (raw.isBlank()) return emptyMap()
            val result = LinkedHashMap<String, String>()
            for (entry in raw.split(';')) {
                val idx = entry.indexOf('=')
                if (idx <= 0 || idx >= entry.length - 1) continue
                val key = entry.substring(0, idx).trim().uppercase()
                val value = entry.substring(idx + 1).trim()
                if (TOKEN_REGEX.matches(key) && TOKEN_REGEX.matches(value)) {
                    result[key] = value
                }
            }
            return result
        }

        fun encodeBypassProfiles(profiles: Map<String, String>): String {
            return profiles.entries
                .asSequence()
                .map { it.key.trim().uppercase() to it.value.trim() }
                .filter { (k, v) -> TOKEN_REGEX.matches(k) && TOKEN_REGEX.matches(v) }
                .sortedBy { it.first }
                .joinToString(";") { (k, v) -> "$k=$v" }
        }
    }
}

