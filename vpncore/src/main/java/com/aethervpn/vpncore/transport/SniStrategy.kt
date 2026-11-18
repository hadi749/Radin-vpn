package com.aethervpn.vpncore.transport

enum class SniStrategy(val id: Int, val displayName: String, val shortLabel: String) {
    AUTO_SMART(5, "Smart Auto-Detect (Recommended)", "Auto"),
    DISABLED(0, "Direct / No Bypass", "Direct"),
    DIRECT_IP_NO_SNI(1, "Connect by IP (No SNI)", "Direct IP"),
    TCP_FRAGMENTATION(2, "TCP ClientHello Fragmentation", "TCP Frag"),
    TLS_RECORD_FRAGMENTATION(3, "TLS Record Fragmentation", "TLS Frag"),
    MULTI_CHUNK_FRAGMENTATION(6, "Multi-Chunk SNI + TLS Fragment", "Multi-Chunk"),
    TLS_HEADER_DESYNC(8, "TLS Header + SNI Desync", "Hdr Desync"),
    WINDOW_ALPN_MICRO_DESYNC(9, "Window + ALPN + Micro-SNI Desync", "Micro Desync"),
    ZAPRET_SPLIT1_DESYNC(10, "Zapret Split-1 TLS Desync", "Split-1"),
    ADAPTIVE_HYBRID_DESYNC(11, "Adaptive Hybrid TLS Desync", "Hybrid"),
    DECOY_SNI_FRAGMENT(7, "Decoy SNI + Fragmentation", "Decoy SNI"),
    CUSTOM_SNI(4, "Custom / Fake SNI", "Custom SNI");

    val isConcreteTransport: Boolean
        get() = this != AUTO_SMART

    companion object {
        val DEFAULT_DECOY_SNIS: List<String> = listOf(
            "teams.microsoft.com",
            "gateway.icloud.com",
            "dl.google.com",
            "speed.cloudflare.com",
            "cdn.samsung.com",
            "www.speedtest.net",
            "ajax.googleapis.com",
            "fonts.gstatic.com",
            "edge.microsoft.com"
        )

        fun pickDecoySni(seed: Int = 0): String {
            if (DEFAULT_DECOY_SNIS.isEmpty()) return "teams.microsoft.com"
            val idx = (seed and 0x7FFFFFFF) % DEFAULT_DECOY_SNIS.size
            return DEFAULT_DECOY_SNIS[idx]
        }

        fun fromId(id: Int): SniStrategy = entries.firstOrNull { it.id == id } ?: AUTO_SMART

        fun concreteFallbackOrder(
            preferred: SniStrategy? = null,
            hasCustomSni: Boolean = false,
            isCellular: Boolean = false
        ): List<SniStrategy> {
            val base = buildList {
                if (!hasCustomSni && !isCellular) {
                    add(DIRECT_IP_NO_SNI)
                }
                if (preferred != null && preferred.isConcreteTransport && preferred != DISABLED && preferred != DIRECT_IP_NO_SNI) {
                    add(preferred)
                }
                add(ZAPRET_SPLIT1_DESYNC)
                add(ADAPTIVE_HYBRID_DESYNC)
                add(TLS_HEADER_DESYNC)
                add(WINDOW_ALPN_MICRO_DESYNC)
                add(MULTI_CHUNK_FRAGMENTATION)
                add(DECOY_SNI_FRAGMENT)
                add(DIRECT_IP_NO_SNI)
                add(TLS_RECORD_FRAGMENTATION)
                add(TCP_FRAGMENTATION)
                if (hasCustomSni) {
                    add(CUSTOM_SNI)
                }
            }
            return base.distinct()
        }
    }
}
