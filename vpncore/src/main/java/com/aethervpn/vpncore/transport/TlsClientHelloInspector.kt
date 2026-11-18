package com.aethervpn.vpncore.transport

/**
 * Byte offsets (relative to the start of the TLS record) locating the `server_name`
 * (SNI) extension and hostname inside a TLS ClientHello message.
 */
data class SniRange(
    val extensionStart: Int,
    val hostStart: Int,
    val hostEnd: Int
) {
    val hostLength: Int get() = (hostEnd - hostStart).coerceAtLeast(0)
    val hostMidpoint: Int get() = hostStart + (hostLength / 2)
}

/**
 * Pure, bounds-checked inspector & fragment planner for TLS ClientHello packets.
 * Enables DPI bypasses that slice directly across the SNI extension regardless of
 * TLS 1.3 cipher/GREASE/key_share sizes.
 */
object TlsClientHelloInspector {

    private const val TLS_CONTENT_TYPE_HANDSHAKE = 0x16
    private const val TLS_HANDSHAKE_CLIENT_HELLO = 0x01
    private const val EXT_SERVER_NAME = 0x0000
    private const val SNI_TYPE_HOST_NAME = 0x00

    fun isTlsClientHello(packet: ByteArray, offset: Int = 0, length: Int = packet.size - offset): Boolean {
        if (offset < 0 || length < 10 || offset + length > packet.size) return false
        return (packet[offset].toInt() and 0xFF) == TLS_CONTENT_TYPE_HANDSHAKE &&
            (packet[offset + 1].toInt() and 0xFF) == 0x03 &&
            (packet[offset + 5].toInt() and 0xFF) == TLS_HANDSHAKE_CLIENT_HELLO
    }

    /**
     * Parses a TLS record buffer starting at [offset] and locates the SNI extension and
     * ASCII hostname range relative to [offset], or null if not a valid ClientHello or SNI absent.
     */
    fun findSniRange(packet: ByteArray, offset: Int = 0, length: Int = packet.size - offset): SniRange? {
        if (!isTlsClientHello(packet, offset, length)) return null
        val end = offset + length

        val recordPayloadLen = u16(packet, offset + 3)
        val recordEnd = minOf(end, offset + 5 + recordPayloadLen)
        if (offset + 5 + 4 + 34 > recordEnd) return null

        var pos = offset + 5 + 4 + 34 // record(5) + hsHeader(4) + legacyVer(2) + random(32)

        // Session ID
        if (pos + 1 > recordEnd) return null
        val sessionIdLen = packet[pos].toInt() and 0xFF
        pos += 1 + sessionIdLen

        // Cipher suites
        if (pos + 2 > recordEnd) return null
        val cipherSuitesLen = u16(packet, pos)
        pos += 2 + cipherSuitesLen

        // Compression methods
        if (pos + 1 > recordEnd) return null
        val compMethodsLen = packet[pos].toInt() and 0xFF
        pos += 1 + compMethodsLen

        // Extensions length
        if (pos + 2 > recordEnd) return null
        val extensionsLen = u16(packet, pos)
        pos += 2
        val extensionsEnd = minOf(recordEnd, pos + extensionsLen)

        while (pos + 4 <= extensionsEnd) {
            val extStartRel = pos - offset
            val extType = u16(packet, pos)
            val extLen = u16(packet, pos + 2)
            pos += 4
            if (pos + extLen > extensionsEnd) return null

            if (extType == EXT_SERVER_NAME && extLen >= 5) {
                var sniPos = pos
                val listLen = u16(packet, sniPos)
                sniPos += 2
                val listEnd = minOf(pos + extLen, sniPos + listLen)
                while (sniPos + 3 <= listEnd) {
                    val nameType = packet[sniPos].toInt() and 0xFF
                    val nameLen = u16(packet, sniPos + 1)
                    sniPos += 3
                    if (sniPos + nameLen > listEnd) return null
                    if (nameType == SNI_TYPE_HOST_NAME && nameLen > 0) {
                        val relHostStart = sniPos - offset
                        return SniRange(
                            extensionStart = extStartRel,
                            hostStart = relHostStart,
                            hostEnd = relHostStart + nameLen
                        )
                    }
                    sniPos += nameLen
                }
            }
            pos += extLen
        }
        return null
    }

    /**
     * Computes deterministic relative byte slices `[IntRange]` for TCP segmentation.
     * Guarantees a segment boundary right inside the SNI hostname (when present) and limits
     * total segments so handshakes remain low-latency.
     */
    fun computeTcpSplitSlices(
        packet: ByteArray,
        offset: Int = 0,
        length: Int = packet.size - offset,
        chunkSize: Int = 18,
        maxSegments: Int = 12
    ): List<IntRange> {
        if (length <= 1) return if (length == 1) listOf(0..0) else emptyList()
        val safeChunk = chunkSize.coerceAtLeast(3)
        val sni = findSniRange(packet, offset, length)

        val cuts = sortedSetOf<Int>()
        if (sni != null && sni.hostLength >= 2) {
            cuts.add(sni.hostMidpoint.coerceIn(1, length - 1))
            cuts.add(sni.extensionStart.coerceIn(1, length - 1))
        }

        // Fill prefix/interior cuts up to budget
        var cursor = safeChunk
        while (cursor < length && cuts.size < maxSegments - 1) {
            cuts.add(cursor)
            cursor += safeChunk
        }

        if (cuts.isEmpty()) {
            val mid = (length / 2).coerceIn(1, length - 1)
            return listOf(0 until mid, mid until length)
        }

        val slices = ArrayList<IntRange>(cuts.size + 1)
        var start = 0
        for (cut in cuts) {
            if (cut > start && cut < length) {
                slices.add(start until cut)
                start = cut
            }
        }
        if (start < length) {
            slices.add(start until length)
        }
        return slices
    }

    /**
     * Computes TLS header + SNI midpoint desync slices.
     * Slice 0 isolates the first 2 bytes (`0x16 0x03`) of the TLSPlaintext record header
     * so DPI parsers expecting an intact 5-byte header + ClientHello byte in packet 1 fail
     * signature matching, while cutting again directly across the SNI hostname midpoint.
     */
    fun computeDesyncSlices(
        packet: ByteArray,
        offset: Int = 0,
        length: Int = packet.size - offset
    ): List<IntRange> {
        if (length <= 2) return if (length > 0) listOf(0 until length) else emptyList()
        val cuts = sortedSetOf<Int>()
        cuts.add(2) // Split inside the 5-byte TLS record header

        val sni = findSniRange(packet, offset, length)
        if (sni != null && sni.hostLength >= 2) {
            cuts.add(sni.extensionStart.coerceIn(3, length - 1))
            cuts.add(sni.hostMidpoint.coerceIn(3, length - 1))
        } else if (length > 24) {
            cuts.add((length / 3).coerceIn(3, length - 1))
            cuts.add(((length * 2) / 3).coerceIn(4, length - 1))
        }

        val slices = ArrayList<IntRange>(cuts.size + 1)
        var start = 0
        for (cut in cuts) {
            if (cut > start && cut < length) {
                slices.add(start until cut)
                start = cut
            }
        }
        if (start < length) {
            slices.add(start until length)
        }
        return slices
    }

    /**
     * Splits a single TLS Handshake record into valid smaller TLSPlaintext Handshake records,
     * placing a record boundary directly across the SNI hostname midpoint when found.
     * When [surgicalSniOnly] is true, emits at most 3 compact records centered around SNI to
     * prevent server/middlebox timeouts from excessive tiny record trickling.
     */
    fun splitTlsRecord(
        packet: ByteArray,
        offset: Int = 0,
        length: Int = packet.size - offset,
        maxPayloadPerRecord: Int = 40,
        maxRecords: Int = 8,
        surgicalSniOnly: Boolean = false
    ): List<ByteArray> {
        if (length <= 6 || offset < 0 || offset + length > packet.size) {
            return listOf(packet.copyOfRange(offset, offset + length))
        }
        if ((packet[offset].toInt() and 0xFF) != TLS_CONTENT_TYPE_HANDSHAKE ||
            (packet[offset + 1].toInt() and 0xFF) != 0x03
        ) {
            return listOf(packet.copyOfRange(offset, offset + length))
        }

        val verMajor = packet[offset + 1]
        val verMinor = packet[offset + 2]
        val payloadLen = u16(packet, offset + 3)
        if (payloadLen <= 4 || 5 + payloadLen > length) {
            return listOf(packet.copyOfRange(offset, offset + length))
        }

        val sni = findSniRange(packet, offset, 5 + payloadLen)
        val cuts = sortedSetOf<Int>()
        if (sni != null && sni.hostLength >= 2) {
            val sniMidPayload = sni.hostMidpoint - 5
            if (sniMidPayload in 1 until payloadLen) {
                cuts.add(sniMidPayload)
            }
            if (surgicalSniOnly) {
                val sniEndPayload = sni.hostEnd - 5
                if (sniEndPayload in (sniMidPayload + 1) until payloadLen) {
                    cuts.add(sniEndPayload)
                }
            }
        }

        if (!surgicalSniOnly) {
            val safeChunk = maxPayloadPerRecord.coerceAtLeast(8)
            var pos = safeChunk
            while (pos < payloadLen && cuts.size < maxRecords - 1) {
                cuts.add(pos)
                pos += safeChunk
            }
        } else if (cuts.isEmpty() && payloadLen >= 16) {
            cuts.add((payloadLen / 3).coerceIn(1, payloadLen - 1))
            cuts.add(((payloadLen * 2) / 3).coerceIn(2, payloadLen - 1))
        }

        if (cuts.isEmpty()) {
            val fallbackMid = (payloadLen / 2).coerceIn(1, payloadLen - 1)
            cuts.add(fallbackMid)
        }

        val out = ArrayList<ByteArray>(cuts.size + 2)
        var start = 0
        for (cut in cuts) {
            if (cut > start && cut < payloadLen) {
                out.add(buildTlsRecord(verMajor, verMinor, packet, offset + 5 + start, cut - start))
                start = cut
            }
        }
        if (start < payloadLen) {
            out.add(buildTlsRecord(verMajor, verMinor, packet, offset + 5 + start, payloadLen - start))
        }

        val remainingOffset = offset + 5 + payloadLen
        val remainingLen = (offset + length) - remainingOffset
        if (remainingLen > 0) {
            out.add(packet.copyOfRange(remainingOffset, offset + length))
        }
        return out
    }

    /**
     * Produces fine-grained TCP slice boundaries starting with a 2B+3B TLS record-header split
     * followed by [sniStepBytes]-byte micro-cuts across the entire SNI hostname so both header-prefix
     * and multi-segment stateful DPI parsers must reassemble many delayed PSH segments.
     */
    fun computeMicroDesyncSlices(
        packet: ByteArray,
        offset: Int = 0,
        length: Int = packet.size,
        sniStepBytes: Int = 2,
        maxSlices: Int = 26
    ): List<IntRange> {
        if (length <= 5 || offset < 0 || offset + length > packet.size) {
            return if (length > 0) listOf(0 until length) else emptyList()
        }
        val cuts = sortedSetOf<Int>()
        if (length > 2) cuts.add(2)
        if (length > 5) cuts.add(5)
        val sni = findSniRange(packet, offset, length)
        if (sni != null && sni.hostLength >= 2) {
            val step = sniStepBytes.coerceAtLeast(2)
            var pos = (sni.hostStart - offset).coerceIn(6, length - 1)
            val sniEndRel = (sni.hostEnd - offset).coerceIn(pos + 1, length)
            while (pos < sniEndRel && cuts.size < maxSlices - 1) {
                cuts.add(pos)
                pos += step
            }
            if (sniEndRel < length) cuts.add(sniEndRel)
        } else if (length > 20) {
            cuts.add(length / 2)
        }

        val out = ArrayList<IntRange>(cuts.size + 1)
        var start = 0
        for (cut in cuts) {
            if (cut in (start + 1) until length) {
                out.add(start until cut)
                start = cut
            }
        }
        if (start < length) {
            out.add(start until length)
        }
        return out
    }

    /**
     * Splits the initial TLS ClientHello at the 1-byte mark (isolating 0x16 Handshake ContentType
     * from the 0x03 0x01/0x03 version signature), followed by the 4-byte header remainder,
     * pre-SNI tag boundary, and SNI cuts. Inspired by the Russian Zapret / GoodbyeDPI split1 strategy.
     */
    fun computeSplit1Slices(
        packet: ByteArray,
        offset: Int = 0,
        length: Int = packet.size
    ): List<IntRange> {
        if (length <= 5 || offset < 0 || offset + length > packet.size) {
            return if (length > 0) listOf(0 until length) else emptyList()
        }
        val cuts = sortedSetOf<Int>()
        cuts.add(1)
        cuts.add(5)
        val sni = findSniRange(packet, offset, length)
        if (sni != null && sni.hostLength >= 2) {
            val preSni = (sni.hostStart - offset - 1).coerceIn(6, length - 1)
            val midSni = (sni.hostMidpoint - offset).coerceIn(preSni + 1, length - 1)
            val endSni = (sni.hostEnd - offset).coerceIn(midSni + 1, length)
            cuts.add(preSni)
            cuts.add(midSni)
            if (endSni < length) cuts.add(endSni)
        } else if (length > 20) {
            cuts.add(length / 2)
        }

        val out = ArrayList<IntRange>(cuts.size + 1)
        var start = 0
        for (cut in cuts) {
            if (cut in (start + 1) until length) {
                out.add(start until cut)
                start = cut
            }
        }
        if (start < length) {
            out.add(start until length)
        }
        return out
    }

    /**
     * Adaptive hybrid desync segmentation: combines 1-byte TLS ContentType isolation (`0x16`),
     * record header boundary split, pre-SNI cut, and seed-varied interior SNI cuts so stateful
     * DPI systems cannot fingerprint a fixed split offset.
     */
    fun computeAdaptiveHybridSlices(
        packet: ByteArray,
        offset: Int = 0,
        length: Int = packet.size,
        cutSeed: Int = 0
    ): List<IntRange> {
        if (length <= 5 || offset < 0 || offset + length > packet.size) {
            return if (length > 0) listOf(0 until length) else emptyList()
        }
        val cuts = sortedSetOf<Int>()
        cuts.add(1)
        cuts.add(3)
        cuts.add(5)

        val sni = findSniRange(packet, offset, length)
        if (sni != null && sni.hostLength >= 3) {
            val hostRelStart = (sni.hostStart - offset).coerceIn(6, length - 2)
            val hostRelEnd = (sni.hostEnd - offset).coerceIn(hostRelStart + 2, length)
            val span = (hostRelEnd - hostRelStart).coerceAtLeast(2)
            val preSni = (hostRelStart - 1).coerceIn(6, length - 1)
            // Vary the interior cut across 25%..75% of the SNI hostname based on cutSeed
            val pct = 25 + ((cutSeed and 0x7FFFFFFF) % 50)
            val cutA = (hostRelStart + ((span * pct) / 100)).coerceIn(hostRelStart + 1, hostRelEnd - 1)
            val cutB = (cutA + maxOf(2, span / 3)).coerceIn(cutA + 1, hostRelEnd)
            cuts.add(preSni)
            cuts.add(cutA)
            if (cutB < length) cuts.add(cutB)
            if (hostRelEnd < length) cuts.add(hostRelEnd)
        } else if (length > 24) {
            val mid = (length / 3 + ((cutSeed and 0x7FFFFFFF) % maxOf(2, length / 4))).coerceIn(6, length - 1)
            cuts.add(mid)
        }

        val out = ArrayList<IntRange>(cuts.size + 1)
        var start = 0
        for (cut in cuts) {
            if (cut in (start + 1) until length) {
                out.add(start until cut)
                start = cut
            }
        }
        if (start < length) {
            out.add(start until length)
        }
        return out
    }

    private fun buildTlsRecord(
        verMajor: Byte,
        verMinor: Byte,
        src: ByteArray,
        srcOffset: Int,
        chunkLen: Int
    ): ByteArray {
        val rec = ByteArray(5 + chunkLen)
        rec[0] = TLS_CONTENT_TYPE_HANDSHAKE.toByte()
        rec[1] = verMajor
        rec[2] = verMinor
        rec[3] = ((chunkLen ushr 8) and 0xFF).toByte()
        rec[4] = (chunkLen and 0xFF).toByte()
        System.arraycopy(src, srcOffset, rec, 5, chunkLen)
        return rec
    }

    private fun u16(buf: ByteArray, idx: Int): Int {
        return ((buf[idx].toInt() and 0xFF) shl 8) or (buf[idx + 1].toInt() and 0xFF)
    }
}

