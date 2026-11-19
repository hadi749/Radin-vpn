package com.aethervpn.vpncore.transport

import java.io.FilterOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class SniBypassSocketFactory(
    private val strategy: SniStrategy,
    private val splitPosition: Int = 40,
    private val splitDelayMs: Long = 10,
    private val customSni: String? = null,
    private val strictCert: Boolean = false,
    private val socketProtector: SocketProtector? = null,
    private val onCertificateCaptured: ((X509Certificate) -> Unit)? = null,
    private val onSocketCreated: ((Socket) -> Unit)? = null,
    private val decoySeed: Int = 0,
    private val allowHttp2Alpn: Boolean = false
) {

    private val trustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            if (chain != null && chain.isNotEmpty()) {
                onCertificateCaptured?.invoke(chain[0])
            }
            if (strictCert) {
                getDefaultTrustManager().checkServerTrusted(chain, authType)
            }
        }
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    private fun getDefaultTrustManager(): X509TrustManager {
        val tmf = javax.net.ssl.TrustManagerFactory.getInstance(
            javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()
        )
        tmf.init(null as java.security.KeyStore?)
        return tmf.trustManagers.first { it is X509TrustManager } as X509TrustManager
    }

    private fun effectiveStrategy(): SniStrategy =
        if (strategy == SniStrategy.AUTO_SMART) SniStrategy.DIRECT_IP_NO_SNI else strategy

    private fun isRawIp(host: String): Boolean {
        if (host.isBlank() || host.equals("opengw", ignoreCase = true)) return true
        val parts = host.split('.')
        if (parts.size != 4) return false
        return parts.all { it.toIntOrNull() in 0..255 }
    }

    private fun resolveTargetSni(host: String): String? {
        val eff = effectiveStrategy()
        if (eff == SniStrategy.DIRECT_IP_NO_SNI) {
            return null
        }
        if (eff == SniStrategy.IRAN_ALLOWLIST_SNI_FRAGMENT) {
            return if (!customSni.isNullOrBlank()) customSni else SniStrategy.pickIranWhitelistSni(decoySeed)
        }
        if (!customSni.isNullOrBlank()) {
            return customSni
        }
        return when (eff) {
            SniStrategy.DECOY_SNI_FRAGMENT ->
                SniStrategy.pickDecoySni(decoySeed)
            SniStrategy.CUSTOM_SNI ->
                if (isRawIp(host)) SniStrategy.pickDecoySni(decoySeed) else host
            SniStrategy.TCP_FRAGMENTATION,
            SniStrategy.TLS_RECORD_FRAGMENTATION,
            SniStrategy.MULTI_CHUNK_FRAGMENTATION,
            SniStrategy.TLS_HEADER_DESYNC,
            SniStrategy.WINDOW_ALPN_MICRO_DESYNC,
            SniStrategy.ZAPRET_SPLIT1_DESYNC,
            SniStrategy.ADAPTIVE_HYBRID_DESYNC ->
                if (isRawIp(host)) SniStrategy.pickDecoySni(decoySeed) else host
            else ->
                if (isRawIp(host)) null else host
        }
    }

    private fun openWrappedSocket(
        ipAddress: InetAddress,
        port: Int,
        timeoutMs: Int
    ): Socket {
        val eff = effectiveStrategy()
        val isWindowMicro = eff == SniStrategy.WINDOW_ALPN_MICRO_DESYNC ||
            eff == SniStrategy.ZAPRET_SPLIT1_DESYNC ||
            eff == SniStrategy.ADAPTIVE_HYBRID_DESYNC ||
            eff == SniStrategy.IRAN_ALLOWLIST_SNI_FRAGMENT
        val rawSocket = openProtectedTcpSocket(
            ipAddress = ipAddress,
            port = port,
            connectTimeoutMs = timeoutMs,
            readTimeoutMs = timeoutMs,
            socketProtector = socketProtector,
            receiveBufferSizeBytes = 8 * 1024 * 1024, // 8MB TCP Window for high-speed streaming
            trafficClass = if (isWindowMicro) 0x10 else 0x08
        )
        onSocketCreated?.invoke(rawSocket)
        return when (eff) {
            SniStrategy.TCP_FRAGMENTATION -> ClientHelloTransformSocket(
                delegate = rawSocket,
                tcpChunkSize = splitPosition.coerceIn(3, 64),
                tcpDelayMs = splitDelayMs,
                splitTlsRecords = false,
                useSniAwareTcpSlices = false
            )
            SniStrategy.TLS_RECORD_FRAGMENTATION -> ClientHelloTransformSocket(
                delegate = rawSocket,
                tcpChunkSize = 0,
                tcpDelayMs = 0L,
                splitTlsRecords = true,
                maxTlsRecordPayload = splitPosition.coerceIn(16, 128),
                useSniAwareTcpSlices = false
            )
            SniStrategy.MULTI_CHUNK_FRAGMENTATION,
            SniStrategy.DECOY_SNI_FRAGMENT -> ClientHelloTransformSocket(
                delegate = rawSocket,
                tcpChunkSize = 36,
                tcpDelayMs = minOf(splitDelayMs, 6L).coerceAtLeast(3L),
                splitTlsRecords = true,
                maxTlsRecordPayload = 64,
                surgicalSniRecordSplit = true,
                useSniAwareTcpSlices = true
            )
            SniStrategy.TLS_HEADER_DESYNC -> ClientHelloTransformSocket(
                delegate = rawSocket,
                tcpChunkSize = 24,
                tcpDelayMs = minOf(splitDelayMs, 6L).coerceAtLeast(3L),
                splitTlsRecords = false,
                useSniAwareTcpSlices = false,
                headerDesync = true
            )
            SniStrategy.WINDOW_ALPN_MICRO_DESYNC -> ClientHelloTransformSocket(
                delegate = rawSocket,
                tcpChunkSize = 24,
                tcpDelayMs = 3L,
                splitTlsRecords = false,
                useSniAwareTcpSlices = false,
                microDesync = true,
                headerStallMs = 22L
            )
            SniStrategy.ZAPRET_SPLIT1_DESYNC -> ClientHelloTransformSocket(
                delegate = rawSocket,
                tcpChunkSize = 24,
                tcpDelayMs = 4L,
                splitTlsRecords = false,
                useSniAwareTcpSlices = false,
                zapretSplit1 = true,
                headerStallMs = 28L
            )
            SniStrategy.ADAPTIVE_HYBRID_DESYNC -> ClientHelloTransformSocket(
                delegate = rawSocket,
                tcpChunkSize = 24,
                tcpDelayMs = (4L + ((decoySeed and 0x7FFFFFFF) % 5L)),
                splitTlsRecords = true,
                maxTlsRecordPayload = 48,
                surgicalSniRecordSplit = true,
                useSniAwareTcpSlices = false,
                adaptiveHybrid = true,
                adaptiveSeed = decoySeed,
                headerStallMs = (14L + ((decoySeed and 0x7FFFFFFF) % 10L))
            )
            SniStrategy.IRAN_ALLOWLIST_SNI_FRAGMENT -> ClientHelloTransformSocket(
                delegate = rawSocket,
                tcpChunkSize = 20,
                tcpDelayMs = (5L + ((decoySeed and 0x7FFFFFFF) % 6L)),
                splitTlsRecords = true,
                maxTlsRecordPayload = 40,
                surgicalSniRecordSplit = true,
                useSniAwareTcpSlices = true,
                adaptiveHybrid = true,
                adaptiveSeed = decoySeed + 7,
                headerStallMs = 16L
            )
            else -> rawSocket
        }
    }

    private fun configureSslParameters(
        params: SSLParameters,
        host: String,
        targetSni: String?,
        supportedCipherSuites: Array<String>,
        supportedProtocols: Array<String>
    ): SSLParameters {
        val eff = effectiveStrategy()
        if (eff == SniStrategy.DIRECT_IP_NO_SNI) {
            params.serverNames = emptyList()
        } else if (!targetSni.isNullOrBlank()) {
            params.serverNames = listOf(SNIHostName(targetSni))
        } else if (eff != SniStrategy.DISABLED && host.isNotBlank()) {
            // Keep default host SNI if not overridden
        }

        if (eff != SniStrategy.DISABLED) {
            val preferredProtos = listOf("TLSv1.3", "TLSv1.2").filter { it in supportedProtocols }
            if (preferredProtos.isNotEmpty()) {
                params.protocols = preferredProtos.toTypedArray()
            }
            val isWindowMicro = eff == SniStrategy.WINDOW_ALPN_MICRO_DESYNC ||
                eff == SniStrategy.ZAPRET_SPLIT1_DESYNC ||
                eff == SniStrategy.ADAPTIVE_HYBRID_DESYNC ||
                eff == SniStrategy.IRAN_ALLOWLIST_SNI_FRAGMENT
            val isBrowserMimic = isWindowMicro ||
                eff == SniStrategy.TLS_HEADER_DESYNC ||
                eff == SniStrategy.DECOY_SNI_FRAGMENT ||
                eff == SniStrategy.MULTI_CHUNK_FRAGMENTATION
            val prioritizedCiphers = prioritizeBrowserCipherSuites(
                supportedCipherSuites,
                limitTail = if (isWindowMicro) 6 else Int.MAX_VALUE
            )
            if (prioritizedCiphers.isNotEmpty()) {
                params.cipherSuites = prioritizedCiphers
            }
            if (isBrowserMimic) {
                params.useCipherSuitesOrder = true
                // Guard ALPN reflection-style so both JVM 17+ and Android API 24..28 run cleanly without NewApi issues.
                // Never advertise h2 unless the caller actually speaks HTTP/2 (raw HTTP/1.1 callers fail if server selects h2).
                runCatching {
                    val alpn = if (allowHttp2Alpn) arrayOf("h2", "http/1.1") else arrayOf("http/1.1")
                    params.javaClass
                        .getMethod("setApplicationProtocols", Array<String>::class.java)
                        .invoke(params, alpn)
                }
            }
        }
        return params
    }

    private fun prioritizeBrowserCipherSuites(
        supported: Array<String>,
        limitTail: Int = Int.MAX_VALUE
    ): Array<String> {
        if (supported.isEmpty()) return supported
        val browserTop = listOf(
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        )
        val supportedSet = supported.toHashSet()
        val head = browserTop.filter { it in supportedSet }
        if (head.isEmpty()) return supported
        val headSet = head.toHashSet()
        val tail = supported.filter { it !in headSet }
        val boundedTail = if (limitTail < tail.size) tail.take(limitTail) else tail
        return (head + boundedTail).toTypedArray()
    }

    fun createAndConnectTransport(
        host: String,
        ipAddress: InetAddress,
        port: Int,
        timeoutMs: Int = 10000
    ): SstpTransport {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(trustManager), null)

        val eff = effectiveStrategy()
        val targetSni = resolveTargetSni(host)
        val peerHost = when {
            eff == SniStrategy.DIRECT_IP_NO_SNI -> ipAddress.hostAddress
            !targetSni.isNullOrBlank() -> targetSni
            else -> host.ifBlank { ipAddress.hostAddress }
        }
        val engine: SSLEngine = sslContext.createSSLEngine(peerHost, port)
        engine.useClientMode = true
        engine.sslParameters = configureSslParameters(
            params = engine.sslParameters,
            host = host,
            targetSni = targetSni,
            supportedCipherSuites = engine.supportedCipherSuites,
            supportedProtocols = engine.supportedProtocols
        )

        val wrappedSocket = openWrappedSocket(ipAddress, port, timeoutMs)
        val transport = SslEngineTransport(wrappedSocket, engine)
        transport.doHandshake()
        return transport
    }

    fun createAndConnectSocket(
        host: String,
        ipAddress: InetAddress,
        port: Int,
        timeoutMs: Int = 10000
    ): SSLSocket {
        val wrappedSocket = openWrappedSocket(ipAddress, port, timeoutMs)
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(trustManager), null)
        val sslSocketFactory: SSLSocketFactory = sslContext.socketFactory

        val eff = effectiveStrategy()
        val targetSni = resolveTargetSni(host)
        val sslSocket = if (eff == SniStrategy.DIRECT_IP_NO_SNI) {
            sslSocketFactory.createSocket(
                wrappedSocket, ipAddress.hostAddress, port, true
            ) as SSLSocket
        } else if (!targetSni.isNullOrBlank()) {
            sslSocketFactory.createSocket(
                wrappedSocket, targetSni, port, true
            ) as SSLSocket
        } else {
            sslSocketFactory.createSocket(
                wrappedSocket, host.ifBlank { ipAddress.hostAddress }, port, true
            ) as SSLSocket
        }
        sslSocket.sslParameters = configureSslParameters(
            params = sslSocket.sslParameters ?: SSLParameters(),
            host = host,
            targetSni = targetSni,
            supportedCipherSuites = sslSocket.supportedCipherSuites,
            supportedProtocols = sslSocket.supportedProtocols
        )

        sslSocket.useClientMode = true
        sslSocket.startHandshake()
        return sslSocket
    }

    /**
     * Unified first-flight TLS ClientHello transformer supporting surgical SNI-midpoint
     * multi-record TLS splitting, 2-byte TLS record header desync, and bounded TCP pacing.
     */
    private class ClientHelloTransformSocket(
        private val delegate: Socket,
        private val tcpChunkSize: Int,
        private val tcpDelayMs: Long,
        private val splitTlsRecords: Boolean,
        private val maxTlsRecordPayload: Int = 40,
        private val surgicalSniRecordSplit: Boolean = false,
        private val useSniAwareTcpSlices: Boolean = false,
        private val headerDesync: Boolean = false,
        private val microDesync: Boolean = false,
        private val zapretSplit1: Boolean = false,
        private val adaptiveHybrid: Boolean = false,
        private val adaptiveSeed: Int = 0,
        private val headerStallMs: Long = 0L
    ) : Socket() {
        private var transformed = false

        override fun getInputStream(): InputStream = delegate.inputStream

        override fun getOutputStream(): OutputStream {
            val original = delegate.outputStream
            return object : FilterOutputStream(original) {
                override fun write(b: ByteArray, off: Int, len: Int) {
                    if (!transformed && len > 8 &&
                        b[off] == 0x16.toByte() && b[off + 1] == 0x03.toByte()
                    ) {
                        transformed = true
                        val records = if (splitTlsRecords) {
                            TlsClientHelloInspector.splitTlsRecord(
                                packet = b,
                                offset = off,
                                length = len,
                                maxPayloadPerRecord = maxTlsRecordPayload,
                                surgicalSniOnly = surgicalSniRecordSplit
                            )
                        } else {
                            listOf(b.copyOfRange(off, off + len))
                        }

                        for ((idx, record) in records.withIndex()) {
                            // When splitting into multiple TLS records surgically around SNI,
                            // segment only the initial SNI-bearing records to avoid excessive micro-packets.
                            val applySegmentation = !splitTlsRecords || !surgicalSniRecordSplit || idx <= 1
                            if (applySegmentation) {
                                writeSegmented(original, record)
                            } else {
                                original.write(record)
                                original.flush()
                            }
                        }
                    } else {
                        original.write(b, off, len)
                    }
                }

                override fun write(b: Int) {
                    original.write(b)
                }

                override fun flush() {
                    original.flush()
                }

                override fun close() {
                    original.close()
                }
            }
        }

        private fun writeSegmented(out: OutputStream, bytes: ByteArray) {
            if (adaptiveHybrid && bytes.size > 5) {
                val slices = TlsClientHelloInspector.computeAdaptiveHybridSlices(
                    packet = bytes,
                    offset = 0,
                    length = bytes.size,
                    cutSeed = adaptiveSeed
                )
                writeSlices(out, bytes, slices)
                return
            }
            if (zapretSplit1 && bytes.size > 5) {
                val slices = TlsClientHelloInspector.computeSplit1Slices(bytes)
                writeSlices(out, bytes, slices)
                return
            }
            if (microDesync && bytes.size > 5) {
                val slices = TlsClientHelloInspector.computeMicroDesyncSlices(bytes)
                writeSlices(out, bytes, slices)
                return
            }
            if (headerDesync && bytes.size > 2) {
                val slices = TlsClientHelloInspector.computeDesyncSlices(bytes)
                writeSlices(out, bytes, slices)
                return
            }
            if (tcpChunkSize <= 0 || bytes.size <= tcpChunkSize) {
                out.write(bytes)
                out.flush()
                return
            }

            if (useSniAwareTcpSlices) {
                val slices = TlsClientHelloInspector.computeTcpSplitSlices(
                    packet = bytes,
                    offset = 0,
                    length = bytes.size,
                    chunkSize = tcpChunkSize,
                    maxSegments = 6
                )
                writeSlices(out, bytes, slices)
            } else {
                val split = tcpChunkSize.coerceIn(1, bytes.size - 1)
                out.write(bytes, 0, split)
                out.flush()
                if (tcpDelayMs > 0) {
                    try {
                        Thread.sleep(tcpDelayMs)
                    } catch (_: InterruptedException) {}
                }
                out.write(bytes, split, bytes.size - split)
                out.flush()
            }
        }

        private fun writeSlices(out: OutputStream, bytes: ByteArray, slices: List<IntRange>) {
            for ((idx, range) in slices.withIndex()) {
                val sliceLen = range.last - range.first + 1
                if (sliceLen > 0) {
                    out.write(bytes, range.first, sliceLen)
                    out.flush()
                    if (idx < slices.lastIndex) {
                        val pauseMs = if (headerStallMs > 0L && (range.last == 0 || range.last == 4)) headerStallMs else tcpDelayMs
                        if (pauseMs > 0) {
                            try {
                                Thread.sleep(pauseMs)
                            } catch (_: InterruptedException) {}
                        }
                    }
                }
            }
        }

        override fun isConnected(): Boolean = delegate.isConnected
        override fun isClosed(): Boolean = delegate.isClosed
        override fun close() = delegate.close()
        override fun setSoTimeout(timeout: Int) { delegate.soTimeout = timeout }
        override fun getSoTimeout(): Int = delegate.soTimeout
    }
}
