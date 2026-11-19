package com.aethervpn.vpncore.warp

data class WarpAccount(
    val id: String,
    val privateKey: String,
    val publicKey: String,
    val token: String,
    val assignedIpv4: String = "172.16.0.2",
    val assignedIpv6: String? = null,
    val license: String? = null,
    val isWarpPlus: Boolean = false,
    val clientId: String? = null
) {
    /**
     * Decodes Cloudflare WARP's Base64 [clientId] into the 3-byte WireGuard `reserved`
     * header field used for ECMP routing and breaking Iran's `01 00 00 00` DPI signature.
     * Implemented in pure Kotlin so it works identically on Android API 24+ and JVM tests.
     */
    fun reservedBytes(): ByteArray? {
        val raw = clientId?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val decoded = decodeBase64(raw) ?: return null
        return if (decoded.size >= 3) decoded.copyOf(3) else null
    }

    fun toJson(): String {
        val parts = ArrayList<String>(9)
        parts.add("\"id\":\"${escapeJson(id)}\"")
        parts.add("\"privateKey\":\"${escapeJson(privateKey)}\"")
        parts.add("\"publicKey\":\"${escapeJson(publicKey)}\"")
        parts.add("\"token\":\"${escapeJson(token)}\"")
        parts.add("\"assignedIpv4\":\"${escapeJson(assignedIpv4)}\"")
        if (assignedIpv6 != null) parts.add("\"assignedIpv6\":\"${escapeJson(assignedIpv6)}\"")
        if (license != null) parts.add("\"license\":\"${escapeJson(license)}\"")
        parts.add("\"isWarpPlus\":$isWarpPlus")
        if (clientId != null) parts.add("\"clientId\":\"${escapeJson(clientId)}\"")
        return "{${parts.joinToString(",")}}"
    }

    companion object {
        const val CLOUDFLARE_PEER_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

        private val B64_TABLE = IntArray(128) { -1 }.apply {
            for (c in 'A'..'Z') this[c.code] = c.code - 'A'.code
            for (c in 'a'..'z') this[c.code] = c.code - 'a'.code + 26
            for (c in '0'..'9') this[c.code] = c.code - '0'.code + 52
            this['+'.code] = 62
            this['-'.code] = 62
            this['/'.code] = 63
            this['_'.code] = 63
        }

        internal fun decodeBase64(input: String): ByteArray? {
            val clean = input.filter { !it.isWhitespace() && it != '=' }
            if (clean.isEmpty()) return null
            val out = ByteArray((clean.length * 3) / 4)
            var outIdx = 0
            var acc = 0
            var bits = 0
            for (ch in clean) {
                val code = ch.code
                val v = if (code in 0..127) B64_TABLE[code] else -1
                if (v < 0) return null
                acc = (acc shl 6) or v
                bits += 6
                if (bits >= 8) {
                    bits -= 8
                    if (outIdx < out.size) {
                        out[outIdx++] = ((acc ushr bits) and 0xFF).toByte()
                    }
                }
            }
            return if (outIdx == out.size) out else out.copyOf(outIdx)
        }

        private fun escapeJson(s: String): String = buildString(s.length) {
            for (ch in s) {
                when (ch) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(ch)
                }
            }
        }

        private fun extractJsonString(raw: String, key: String): String? {
            val regex = Regex("\"${Regex.escape(key)}\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"")
            val match = regex.find(raw) ?: return null
            val value = match.groupValues[1]
            return value
                .replace("\\\"", "\"")
                .replace("\\\\", "\\")
                .replace("\\/", "/")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
        }

        private fun extractJsonBoolean(raw: String, key: String, defaultValue: Boolean): Boolean {
            val regex = Regex("\"${Regex.escape(key)}\"\\s*:\\s*(true|false)")
            val match = regex.find(raw) ?: return defaultValue
            return match.groupValues[1] == "true"
        }

        fun fromJson(raw: String): WarpAccount? {
            if (raw.isBlank()) return null
            return try {
                val id = extractJsonString(raw, "id") ?: return null
                val privateKey = extractJsonString(raw, "privateKey") ?: return null
                val publicKey = extractJsonString(raw, "publicKey") ?: return null
                val token = extractJsonString(raw, "token") ?: return null
                WarpAccount(
                    id = id,
                    privateKey = privateKey,
                    publicKey = publicKey,
                    token = token,
                    assignedIpv4 = extractJsonString(raw, "assignedIpv4")?.takeIf { it.isNotBlank() } ?: "172.16.0.2",
                    assignedIpv6 = extractJsonString(raw, "assignedIpv6")?.takeIf { it.isNotBlank() },
                    license = extractJsonString(raw, "license")?.takeIf { it.isNotBlank() },
                    isWarpPlus = extractJsonBoolean(raw, "isWarpPlus", false),
                    clientId = extractJsonString(raw, "clientId")?.takeIf { it.isNotBlank() }
                )
            } catch (_: Exception) {
                null
            }
        }
    }
}
