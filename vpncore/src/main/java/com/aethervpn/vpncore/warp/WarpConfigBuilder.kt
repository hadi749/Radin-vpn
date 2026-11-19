package com.aethervpn.vpncore.warp

import com.aethervpn.vpncore.tun.Ipv4Cidr
import com.aethervpn.vpncore.tun.Ipv4RouteCalculator
import com.wireguard.config.Config
import com.wireguard.config.InetNetwork
import com.wireguard.config.Interface
import com.wireguard.config.Peer
import java.net.InetAddress

object WarpConfigBuilder {
    fun buildConfig(
        account: WarpAccount,
        endpoint: CleanEndpoint,
        mtu: Int = 1280,
        keepaliveSec: Int = 15,
        excludeLan: Boolean = true,
        excludedApps: Collection<String> = emptyList(),
        includedApps: Collection<String> = emptyList(),
        excludeAppPackage: String? = null
    ): Config {
        val ifaceBuilder = Interface.Builder()
            .parsePrivateKey(account.privateKey)
            .addAddress(InetNetwork.parse("${account.assignedIpv4.substringBefore('/')}/32"))
            .addDnsServer(InetAddress.getByName("1.1.1.1"))
            .addDnsServer(InetAddress.getByName("1.0.0.1"))
            .setMtu(if (mtu in 1200..1500) mtu else 1280)

        val effectiveIncluded = if (!excludeAppPackage.isNullOrBlank() && includedApps.isNotEmpty()) {
            includedApps.filterNot { it == excludeAppPackage }
        } else {
            includedApps
        }
        val effectiveExcluded = if (!excludeAppPackage.isNullOrBlank() && effectiveIncluded.isEmpty()) {
            (excludedApps + excludeAppPackage).distinct()
        } else {
            excludedApps
        }

        if (effectiveExcluded.isNotEmpty()) {
            ifaceBuilder.excludeApplications(effectiveExcluded)
        }
        if (effectiveIncluded.isNotEmpty()) {
            ifaceBuilder.includeApplications(effectiveIncluded)
        }

        account.assignedIpv6?.let { v6 ->
            try {
                ifaceBuilder.addAddress(InetNetwork.parse("${v6.substringBefore('/')}/128"))
            } catch (_: Exception) {}
        }

        val allowedRoutes = if (excludeLan) {
            val excludes = ArrayList<Ipv4Cidr>(Ipv4RouteCalculator.LAN_AND_MULTICAST_EXCLUDES)
            Ipv4Cidr.parse("10.0.0.0/8")?.let { excludes.add(it) }
            Ipv4Cidr.parse("127.0.0.0/8")?.let { excludes.add(it) }
            Ipv4RouteCalculator.computeAllowedRoutes(excludes)
        } else {
            listOf(Ipv4Cidr(0, 0))
        }

        val peerBuilder = Peer.Builder()
            .parsePublicKey(WarpAccount.CLOUDFLARE_PEER_PUBLIC_KEY)
            .parseEndpoint("${endpoint.ip}:${endpoint.port}")

        for (cidr in allowedRoutes) {
            peerBuilder.parseAllowedIPs("${cidr.hostAddress}/${cidr.prefixLen}")
        }

        try {
            peerBuilder.parseAllowedIPs("::/0")
        } catch (_: Exception) {}

        if (keepaliveSec > 0) {
            peerBuilder.setPersistentKeepalive(keepaliveSec)
        }

        return Config.Builder()
            .setInterface(ifaceBuilder.build())
            .addPeer(peerBuilder.build())
            .build()
    }
}

