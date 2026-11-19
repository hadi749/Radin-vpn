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
    IRAN_ALLOWLIST_SNI_FRAGMENT(12, "Whitelist SNI + TLS Record Frag", "Whitelist Frag"),
    DECOY_SNI_FRAGMENT(7, "Decoy SNI + Fragmentation", "Decoy SNI"),
    CUSTOM_SNI(4, "Custom / Fake SNI", "Custom SNI");

    val isConcreteTransport: Boolean
        get() = this != AUTO_SMART

    companion object {
        /**
         * High-trust domestic & neutral CDN/OS SNIs that remain allowlisted on Iranian ISPs
         * (MCI, Irancell, Rightel, TCI, Shatel) even during strict protocol/SNI whitelisting.
         */
        val IRAN_WHITELIST_SNIS: List<String> = listOf(
            "digikala.com",
            "aparat.com",
            "divar.ir",
            "snapp.ir",
            "cafebazaar.ir",
            "varzesh3.com",
            "time.ir",
            "shaparak.ir",
            "soft98.ir",
            "telewebion.com"
        )

        val DEFAULT_DECOY_SNIS: List<String> = listOf(
            "digikala.com",
            "aparat.com",
            "update.googleapis.com",
            "connectivitycheck.gstatic.com",
            "divar.ir",
            "cdn.samsung.com",
            "snapp.ir",
            "cafebazaar.ir",
            "fonts.gstatic.com",
            "varzesh3.com",
            "edge.microsoft.com",
            "time.ir"
        )

        fun pickIranWhitelistSni(seed: Int = 0): String {
            if (IRAN_WHITELIST_SNIS.isEmpty()) return "digikala.com"
            val idx = (seed and 0x7FFFFFFF) % IRAN_WHITELIST_SNIS.size
            return IRAN_WHITELIST_SNIS[idx]
        }

        fun pickDecoySni(seed: Int = 0): String {
            if (DEFAULT_DECOY_SNIS.isEmpty()) return "digikala.com"
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
                add(ADAPTIVE_HYBRID_DESYNC)
                add(IRAN_ALLOWLIST_SNI_FRAGMENT)
                add(ZAPRET_SPLIT1_DESYNC)
                add(TLS_HEADER_DESYNC)
                add(MULTI_CHUNK_FRAGMENTATION)
                add(WINDOW_ALPN_MICRO_DESYNC)
                add(DECOY_SNI_FRAGMENT)
                add(TLS_RECORD_FRAGMENTATION)
                add(DIRECT_IP_NO_SNI)
                add(TCP_FRAGMENTATION)
                if (hasCustomSni) {
                    add(CUSTOM_SNI)
                }
            }
            return base.distinct()
        }
    }
}
