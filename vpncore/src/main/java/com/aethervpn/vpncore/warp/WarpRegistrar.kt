package com.aethervpn.vpncore.warp

import com.aethervpn.vpncore.transport.SniBypassSocketFactory
import com.aethervpn.vpncore.transport.SniStrategy
import com.aethervpn.vpncore.transport.SocketProtector
import com.wireguard.crypto.KeyPair
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.TimeUnit

object WarpRegistrar {
    private const val API_HOST = "api.cloudflareclient.com"
    private const val API_PATH = "/v0a2158/reg"
    private const val API_ENDPOINT = "https://$API_HOST$API_PATH"
    private val JSON_MEDIA_TYPE = "application/json; charset=UTF-8".toMediaType()

    private val CLOUDFLARE_ANYCAST_IPS = listOf(
        byteArrayOf(162.toByte(), 159.toByte(), 192.toByte(), 1),
        byteArrayOf(188.toByte(), 114.toByte(), 97.toByte(), 1),
        byteArrayOf(162.toByte(), 159.toByte(), 193.toByte(), 1),
        byteArrayOf(188.toByte(), 114.toByte(), 98.toByte(), 1)
    )

    private val resilientDns = object : Dns {
        override fun lookup(hostname: String): List<InetAddress> {
            if (hostname.equals(API_HOST, ignoreCase = true)) {
                val resolved = runCatching { Dns.SYSTEM.lookup(hostname) }.getOrNull().orEmpty()
                val validPublic = resolved.filter { addr ->
                    val ip = addr.hostAddress.orEmpty()
                    !ip.startsWith("10.") && !ip.startsWith("127.") && !ip.startsWith("192.168.")
                }
                return validPublic.ifEmpty {
                    CLOUDFLARE_ANYCAST_IPS.map { InetAddress.getByAddress(API_HOST, it) }
                }
            } else {
                return Dns.SYSTEM.lookup(hostname)
            }
        }
    }

    private val httpClient by lazy {
        OkHttpClient.Builder()
            .dns(resilientDns)
            .connectTimeout(8, TimeUnit.SECONDS)
            .readTimeout(8, TimeUnit.SECONDS)
            .callTimeout(12, TimeUnit.SECONDS)
            .build()
    }

    suspend fun registerAccount(
        existingClient: OkHttpClient? = null,
        socketProtector: SocketProtector? = null
    ): WarpAccount = withContext(Dispatchers.IO) {
        val client = existingClient ?: httpClient
        val keyPair = KeyPair()
        val privateKeyB64 = keyPair.privateKey.toBase64()
        val publicKeyB64 = keyPair.publicKey.toBase64()

        val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val tosTime = sdf.format(Date())

        val regBody = JSONObject().apply {
            put("key", publicKeyB64)
            put("install_id", "")
            put("fcm_token", "")
            put("tos", tosTime)
            put("model", "Android")
            put("serial_number", "")
            put("locale", "en_US")
        }
        val regBodyStr = regBody.toString()

        var usedBypassStrategy: SniStrategy? = null
        var usedBypassIp: InetAddress? = null

        val respStr: String = try {
            val request = Request.Builder()
                .url(API_ENDPOINT)
                .post(regBodyStr.toRequestBody(JSON_MEDIA_TYPE))
                .header("User-Agent", "okhttp/4.12.0")
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val errBody = response.body?.string().orEmpty()
                    throw IllegalStateException("Cloudflare WARP registration failed (code=${response.code}): $errBody")
                }
                response.body?.string() ?: throw IllegalStateException("Empty response from Cloudflare")
            }
        } catch (directError: Exception) {
            if (existingClient != null) throw directError
            // Direct TLS/SNI failed (common under DPI). Escalate to SNI-desync over Cloudflare Anycast IPs.
            val bypassStrategies = listOf(
                SniStrategy.ADAPTIVE_HYBRID_DESYNC,
                SniStrategy.ZAPRET_SPLIT1_DESYNC,
                SniStrategy.TLS_HEADER_DESYNC
            )
            var resultBody: String? = null
            var lastBypassError: Exception = directError
            outer@ for (rawIp in CLOUDFLARE_ANYCAST_IPS) {
                val addr = InetAddress.getByAddress(API_HOST, rawIp)
                for ((idx, strategy) in bypassStrategies.withIndex()) {
                    try {
                        val (code, body) = executeBypassHttp(
                            method = "POST",
                            path = API_PATH,
                            jsonBody = regBodyStr,
                            ipAddress = addr,
                            strategy = strategy,
                            decoySeed = idx,
                            socketProtector = socketProtector
                        )
                        if (code in 200..299 && body.isNotBlank()) {
                            resultBody = body
                            usedBypassStrategy = strategy
                            usedBypassIp = addr
                            break@outer
                        }
                    } catch (e: Exception) {
                        lastBypassError = e
                    }
                }
            }
            resultBody ?: throw lastBypassError
        }

        val root = JSONObject(respStr)
        val id = root.getString("id")
        val token = root.getString("token")

        var assignedIpv4 = "172.16.0.2"
        var assignedIpv6: String? = null
        if (root.has("config")) {
            val configObj = root.getJSONObject("config")
            if (configObj.has("interface")) {
                val ifaceObj = configObj.getJSONObject("interface")
                if (ifaceObj.has("addresses")) {
                    val addrs = ifaceObj.getJSONObject("addresses")
                    if (addrs.has("v4")) assignedIpv4 = addrs.getString("v4")
                    if (addrs.has("v6")) assignedIpv6 = addrs.getString("v6")
                }
            }
        }

        var license: String? = null
        var isWarpPlus = false
        if (root.has("account")) {
            val acc = root.getJSONObject("account")
            if (acc.has("license")) license = acc.optString("license")
            if (acc.has("warp_plus")) isWarpPlus = acc.optBoolean("warp_plus", false)
        }

        // Enable WARP on the account
        try {
            val patchJson = JSONObject().apply { put("warp_enabled", true) }.toString()
            val bypassStrat = usedBypassStrategy
            val bypassAddr = usedBypassIp
            if (bypassStrat != null && bypassAddr != null) {
                executeBypassHttp(
                    method = "PATCH",
                    path = "$API_PATH/$id",
                    jsonBody = patchJson,
                    ipAddress = bypassAddr,
                    strategy = bypassStrat,
                    authBearer = token,
                    socketProtector = socketProtector
                )
            } else {
                val patchReq = Request.Builder()
                    .url("$API_ENDPOINT/$id")
                    .patch(patchJson.toRequestBody(JSON_MEDIA_TYPE))
                    .header("Authorization", "Bearer $token")
                    .header("User-Agent", "okhttp/4.12.0")
                    .build()
                client.newCall(patchReq).execute().close()
            }
        } catch (_: Exception) {
            // Non-fatal if patch fails, account is still valid
        }

        WarpAccount(
            id = id,
            privateKey = privateKeyB64,
            publicKey = publicKeyB64,
            token = token,
            assignedIpv4 = assignedIpv4,
            assignedIpv6 = assignedIpv6,
            license = license,
            isWarpPlus = isWarpPlus
        )
    }

    private fun executeBypassHttp(
        method: String,
        path: String,
        jsonBody: String,
        ipAddress: InetAddress,
        strategy: SniStrategy,
        authBearer: String? = null,
        decoySeed: Int = 0,
        socketProtector: SocketProtector? = null
    ): Pair<Int, String> {
        val bodyBytes = jsonBody.toByteArray(Charsets.UTF_8)
        val factory = SniBypassSocketFactory(
            strategy = strategy,
            strictCert = true,
            socketProtector = socketProtector,
            decoySeed = decoySeed
        )
        val transport = factory.createAndConnectTransport(
            host = API_HOST,
            ipAddress = ipAddress,
            port = 443,
            timeoutMs = 5000
        )
        return try {
            transport.setSoTimeout(6000)
            val req = buildString {
                append("$method $path HTTP/1.1\r\n")
                append("Host: $API_HOST\r\n")
                append("User-Agent: Mozilla/5.0 (Linux; Android 14) Chrome/131.0.0.0 Mobile Safari/537.36\r\n")
                append("Content-Type: application/json; charset=UTF-8\r\n")
                if (authBearer != null) {
                    append("Authorization: Bearer $authBearer\r\n")
                }
                append("Content-Length: ${bodyBytes.size}\r\n")
                append("Connection: close\r\n\r\n")
            }
            transport.outputStream.write(req.toByteArray(Charsets.US_ASCII))
            transport.outputStream.write(bodyBytes)
            transport.outputStream.flush()

            readHttpResponse(transport.inputStream)
        } finally {
            try { transport.close() } catch (_: Exception) {}
        }
    }

    private fun readHttpResponse(inStream: InputStream): Pair<Int, String> {
        val rawHeaders = ByteArrayOutputStream()
        var state = 0
        while (true) {
            val b = inStream.read()
            if (b == -1) break
            rawHeaders.write(b)
            state = when (state) {
                0 -> if (b == '\r'.code) 1 else 0
                1 -> if (b == '\n'.code) 2 else if (b == '\r'.code) 1 else 0
                2 -> if (b == '\r'.code) 3 else 0
                3 -> if (b == '\n'.code) 4 else if (b == '\r'.code) 1 else 0
                else -> 0
            }
            if (state == 4) break
        }
        val headerText = rawHeaders.toString(Charsets.US_ASCII.name())
        val lines = headerText.split("\r\n")
        val statusCode = lines.firstOrNull()?.split(" ")?.getOrNull(1)?.toIntOrNull() ?: 0
        var contentLength = -1
        var isChunked = false
        for (line in lines) {
            when {
                line.startsWith("Content-Length:", ignoreCase = true) -> {
                    contentLength = line.substringAfter(":").trim().toIntOrNull() ?: -1
                }
                line.startsWith("Transfer-Encoding:", ignoreCase = true) && line.contains("chunked", ignoreCase = true) -> {
                    isChunked = true
                }
            }
        }

        val bodyOut = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        if (isChunked) {
            while (true) {
                val lenLine = readAsciiLine(inStream).trim()
                val chunkSize = lenLine.substringBefore(";").trim().toIntOrNull(16) ?: break
                if (chunkSize <= 0) break
                var rem = chunkSize
                while (rem > 0) {
                    val r = inStream.read(buf, 0, minOf(rem, buf.size))
                    if (r == -1) break
                    bodyOut.write(buf, 0, r)
                    rem -= r
                }
                readAsciiLine(inStream) // trailing CRLF
            }
        } else if (contentLength > 0) {
            var rem = contentLength
            while (rem > 0) {
                val r = inStream.read(buf, 0, minOf(rem, buf.size))
                if (r == -1) break
                bodyOut.write(buf, 0, r)
                rem -= r
            }
        } else if (contentLength != 0) {
            while (true) {
                val r = inStream.read(buf)
                if (r == -1) break
                bodyOut.write(buf, 0, r)
            }
        }
        return statusCode to bodyOut.toString(Charsets.UTF_8.name())
    }

    private fun readAsciiLine(inStream: InputStream): String {
        val sb = StringBuilder()
        while (true) {
            val b = inStream.read()
            if (b == -1 || b == '\n'.code) break
            if (b != '\r'.code) sb.append(b.toChar())
        }
        return sb.toString()
    }
}

