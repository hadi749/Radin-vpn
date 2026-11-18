package com.aethervpn.client.data.datastore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PreferencesManagerTest {

    @Test
    fun bypassProfileCodecRoundTripsAndSanitizesEntries() {
        val original = mapOf(
            "cellular" to "TCP_FRAGMENTATION",
            "wifi" to "DIRECT_IP_NO_SNI",
            "bad key!" to "DROP_ME"
        )
        val encoded = PreferencesManager.encodeBypassProfiles(original)
        assertEquals("CELLULAR=TCP_FRAGMENTATION;WIFI=DIRECT_IP_NO_SNI", encoded)

        val decoded = PreferencesManager.parseBypassProfiles("CELLULAR=TCP_FRAGMENTATION;;WIFI=DIRECT_IP_NO_SNI;invalid")
        assertEquals(2, decoded.size)
        assertEquals("TCP_FRAGMENTATION", decoded["CELLULAR"])
        assertEquals("DIRECT_IP_NO_SNI", decoded["WIFI"])
        assertTrue(PreferencesManager.parseBypassProfiles("").isEmpty())
    }

    @Test
    fun vpnProtocolFromIdAndGranularNetworkProfilesRoundTrip() {
        assertEquals(VpnProtocol.SSTP, VpnProtocol.fromId(0))
        assertEquals(VpnProtocol.WARP, VpnProtocol.fromId(1))
        assertEquals(VpnProtocol.SOFTETHER_NATIVE, VpnProtocol.fromId(2))
        assertEquals(VpnProtocol.AUTO_SMART, VpnProtocol.fromId(3))
        assertEquals(VpnProtocol.AUTO_SMART, VpnProtocol.fromId(999))

        val protoMap = mapOf(
            "cellular_43211" to VpnProtocol.SOFTETHER_NATIVE.name,
            "wifi_1a2b3c" to VpnProtocol.WARP.name
        )
        val encoded = PreferencesManager.encodeBypassProfiles(protoMap)
        assertEquals("CELLULAR_43211=SOFTETHER_NATIVE;WIFI_1A2B3C=WARP", encoded)

        val decoded = PreferencesManager.parseBypassProfiles(encoded)
        assertEquals("SOFTETHER_NATIVE", decoded["CELLULAR_43211"])
        assertEquals("WARP", decoded["WIFI_1A2B3C"])
    }
}

