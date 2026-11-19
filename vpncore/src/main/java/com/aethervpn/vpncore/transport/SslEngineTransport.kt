package com.aethervpn.vpncore.transport

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult

interface SstpTransport {
    val inputStream: InputStream
    val outputStream: OutputStream
    fun setSoTimeout(timeoutMs: Int)
    fun setTcpNoDelay(enable: Boolean) {}
    fun close()
}

/**
 * TLS transport built on raw TCP Socket + non-blocking memory SSLEngine.
 * Unlike Android Conscrypt SSLSocket, concurrent reads and writes on separate
 * threads never contend on a shared SSLSocket stream lock.
 */
class SslEngineTransport(
    private val socket: Socket,
    private val engine: SSLEngine
) : SstpTransport {

    private val rawIn = socket.inputStream
    private val rawOut = socket.outputStream
    private val writeLock = Any()

    private var netInBuffer = ByteBuffer.allocate(maxOf(engine.session.packetBufferSize, 65536)).also { it.limit(0) }
    private var netOutBuffer = ByteBuffer.allocate(maxOf(engine.session.packetBufferSize, 65536))
    private var appInBuffer = ByteBuffer.allocate(maxOf(engine.session.applicationBufferSize, 65536) + 4096).also { it.limit(0) }

    fun doHandshake() {
        engine.beginHandshake()
        val empty = ByteBuffer.allocate(0)
        var status = engine.handshakeStatus
        var tempApp = ByteBuffer.allocate(maxOf(engine.session.applicationBufferSize, 16384))

        while (status != SSLEngineResult.HandshakeStatus.FINISHED &&
            status != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
        ) {
            when (status) {
                SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                    netOutBuffer.clear()
                    val res = engine.wrap(empty, netOutBuffer)
                    if (res.status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        netOutBuffer = ByteBuffer.allocate(maxOf(netOutBuffer.capacity() * 2, engine.session.packetBufferSize))
                        continue
                    }
                    netOutBuffer.flip()
                    if (netOutBuffer.hasRemaining()) {
                        rawOut.write(
                            netOutBuffer.array(),
                            netOutBuffer.arrayOffset() + netOutBuffer.position(),
                            netOutBuffer.remaining()
                        )
                        netOutBuffer.position(netOutBuffer.limit())
                        rawOut.flush()
                    }
                    if (res.handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
                        break
                    }
                    status = engine.handshakeStatus
                }

                SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                    tempApp.clear()
                    val res = unwrapNextRecord(tempApp)
                    if (res.status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        tempApp = ByteBuffer.allocate(maxOf(tempApp.capacity() * 2, engine.session.applicationBufferSize + 4096))
                        continue
                    }
                    tempApp.flip()
                    if (tempApp.hasRemaining()) {
                        val needed = appInBuffer.remaining() + tempApp.remaining()
                        if (needed > appInBuffer.capacity()) {
                            val newBuf = ByteBuffer.allocate(needed + 4096)
                            newBuf.put(appInBuffer)
                            newBuf.put(tempApp)
                            newBuf.flip()
                            appInBuffer = newBuf
                        } else {
                            appInBuffer.compact()
                            appInBuffer.put(tempApp)
                            appInBuffer.flip()
                        }
                    }
                    if (res.handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
                        break
                    }
                    status = engine.handshakeStatus
                }

                SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                    runDelegatedTasks()
                    status = engine.handshakeStatus
                }

                else -> break
            }
        }

        val reqPacket = maxOf(engine.session.packetBufferSize, 65536)
        if (netOutBuffer.capacity() < reqPacket) {
            netOutBuffer = ByteBuffer.allocate(reqPacket)
        }
        val reqApp = maxOf(engine.session.applicationBufferSize, 65536) + 4096
        if (appInBuffer.capacity() < reqApp) {
            val newBuf = ByteBuffer.allocate(reqApp)
            newBuf.put(appInBuffer)
            newBuf.flip()
            appInBuffer = newBuf
        }
    }

    private fun runDelegatedTasks() {
        var task = engine.delegatedTask
        while (task != null) {
            task.run()
            task = engine.delegatedTask
        }
    }

    private fun unwrapNextRecord(dest: ByteBuffer): SSLEngineResult {
        while (true) {
            if (netInBuffer.hasRemaining()) {
                val res = engine.unwrap(netInBuffer, dest)
                when (res.status) {
                    SSLEngineResult.Status.OK -> {
                        if (res.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                            runDelegatedTasks()
                        }
                        return res
                    }
                    SSLEngineResult.Status.BUFFER_OVERFLOW -> return res
                    SSLEngineResult.Status.CLOSED -> throw EOFException("TLS connection closed by peer")
                    SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                        // Fall through to read more bytes from socket
                    }
                }
            }

            netInBuffer.compact()
            if (!netInBuffer.hasRemaining()) {
                val newCap = maxOf(netInBuffer.capacity() * 2, engine.session.packetBufferSize)
                val bigger = ByteBuffer.allocate(newCap)
                netInBuffer.flip()
                bigger.put(netInBuffer)
                netInBuffer = bigger
            }

            val readCount = try {
                rawIn.read(netInBuffer.array(), netInBuffer.position(), netInBuffer.remaining())
            } catch (e: SocketTimeoutException) {
                netInBuffer.flip()
                throw e
            }

            if (readCount == -1) {
                netInBuffer.flip()
                throw EOFException("TLS stream ended")
            }
            netInBuffer.position(netInBuffer.position() + readCount)
            netInBuffer.flip()
        }
    }

    override val inputStream: InputStream = object : InputStream() {
        override fun read(): Int {
            val b = ByteArray(1)
            val n = read(b, 0, 1)
            return if (n == -1) -1 else (b[0].toInt() and 0xFF)
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            while (!appInBuffer.hasRemaining()) {
                appInBuffer.clear()
                val res = try {
                    unwrapNextRecord(appInBuffer)
                } catch (_: EOFException) {
                    appInBuffer.limit(0)
                    return -1
                } catch (e: SocketTimeoutException) {
                    appInBuffer.limit(0)
                    throw e
                }
                if (res.status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                    val needed = maxOf(appInBuffer.capacity() * 2, engine.session.applicationBufferSize + 4096)
                    appInBuffer = ByteBuffer.allocate(needed).also { it.limit(0) }
                    continue
                }
                appInBuffer.flip()
            }
            val toCopy = minOf(len, appInBuffer.remaining())
            appInBuffer.get(b, off, toCopy)
            return toCopy
        }
    }

    override val outputStream: OutputStream = object : OutputStream() {
        override fun write(b: Int) {
            write(byteArrayOf(b.toByte()), 0, 1)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (len == 0) return
            synchronized(writeLock) {
                val src = ByteBuffer.wrap(b, off, len)
                while (src.hasRemaining()) {
                    netOutBuffer.clear()
                    val res = engine.wrap(src, netOutBuffer)
                    if (res.status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        netOutBuffer = ByteBuffer.allocate(maxOf(netOutBuffer.capacity() * 2, engine.session.packetBufferSize))
                        continue
                    }
                    if (res.status == SSLEngineResult.Status.CLOSED) {
                        throw IOException("TLS connection closed")
                    }
                    if (res.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                        runDelegatedTasks()
                    }
                    netOutBuffer.flip()
                    if (netOutBuffer.hasRemaining()) {
                        rawOut.write(
                            netOutBuffer.array(),
                            netOutBuffer.arrayOffset() + netOutBuffer.position(),
                            netOutBuffer.remaining()
                        )
                        netOutBuffer.position(netOutBuffer.limit())
                    }
                }
                rawOut.flush()
            }
        }

        override fun flush() {
            synchronized(writeLock) {
                rawOut.flush()
            }
        }

        override fun close() {
            this@SslEngineTransport.close()
        }
    }

    override fun setSoTimeout(timeoutMs: Int) {
        socket.soTimeout = timeoutMs
    }

    override fun setTcpNoDelay(enable: Boolean) {
        socket.tcpNoDelay = enable
    }

    override fun close() {
        try { engine.closeOutbound() } catch (_: Exception) {}
        try { socket.close() } catch (_: Exception) {}
    }
}
