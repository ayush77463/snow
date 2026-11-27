package org.snow.network

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

/**
 * Canonical transport channels ordered strictly by M4.3 priority:
 * 0 = USB, 1 = Hotspot, 2 = Wi-Fi LAN, 3 = Remote Relay.
 */
enum class TransportRoute(
    val wireName: String,
    val priority: Int,
    val badge: String,
    val shortLabel: String,
    val isLocal: Boolean
) {
    USB("usb", 0, "USB • Zero Data", "USB", true),
    HOTSPOT("hotspot", 1, "Hotspot • Zero Data", "Hotspot", true),
    WIFI_LAN("wifi_lan", 2, "Wi-Fi • Zero Data", "Wi-Fi", true),
    REMOTE_RELAY("remote_relay", 3, "Remote • Uses Data", "Remote", false);

    companion object {
        fun fromWireName(raw: String?): TransportRoute? {
            return when (raw?.trim()?.lowercase(Locale.ROOT)) {
                "usb", "usb_adb", "adb" -> USB
                "hotspot", "softap", "ap_direct" -> HOTSPOT
                "wifi_lan", "wifi", "lan" -> WIFI_LAN
                "remote_relay", "remote", "relay" -> REMOTE_RELAY
                else -> null
            }
        }
    }
}

enum class TransportMode(val wireName: String) {
    AUTO("auto"),
    USB("usb"),
    HOTSPOT("hotspot"),
    WIFI_LAN("wifi_lan"),
    REMOTE_RELAY("remote_relay"),
    LOCAL_ONLY("local_only"),
    REMOTE_ONLY("remote_only");

    fun isSingleRouteOverride(): Boolean =
        this == USB || this == HOTSPOT || this == WIFI_LAN || this == REMOTE_RELAY

    fun targetRouteOrNull(): TransportRoute? = when (this) {
        USB -> TransportRoute.USB
        HOTSPOT -> TransportRoute.HOTSPOT
        WIFI_LAN -> TransportRoute.WIFI_LAN
        REMOTE_RELAY -> TransportRoute.REMOTE_RELAY
        else -> null
    }

    companion object {
        fun normalize(raw: String?): TransportMode? {
            return when (raw?.trim()?.lowercase(Locale.ROOT)) {
                null, "", "auto" -> AUTO
                "usb", "usb_adb", "adb" -> USB
                "hotspot", "softap" -> HOTSPOT
                "wifi_lan", "wifi", "lan" -> WIFI_LAN
                "remote_relay", "remote", "relay" -> REMOTE_RELAY
                "local_only" -> LOCAL_ONLY
                "remote_only" -> REMOTE_ONLY
                else -> null
            }
        }
    }
}

enum class RouteState(val wireName: String) {
    DISCOVERED("discovered"),
    CANDIDATE("candidate"),
    PROBING("probing"),
    VERIFIED_AVAILABLE("verified_available"),
    ACTIVE("active"),
    UNAVAILABLE("unavailable"),
    MANUALLY_SELECTED("manually_selected")
}

data class RouteCandidateEntry(
    val deviceId: String,
    val route: TransportRoute,
    val host: String = "",
    val port: Int = 8765,
    val transferPort: Int = 8766,
    val state: RouteState = RouteState.UNAVAILABLE,
    val verified: Boolean = false,
    val verifiedAtMs: Long = 0L,
    val expiresAtMs: Long = 0L,
    val lastCheckedAtMs: Long = 0L,
    val cooldownUntilMs: Long = 0L,
    val lastFailureReason: String? = null,
    val interfaceName: String? = null,
    val isHotspot: Boolean = route == TransportRoute.HOTSPOT,
    val suitableForTransfer: Boolean = route != TransportRoute.REMOTE_RELAY,
    val generation: Long = 0L
) {
    fun isExpired(nowMs: Long = System.currentTimeMillis()): Boolean {
        if (!verified || expiresAtMs <= 0L) return false
        return nowMs >= expiresAtMs
    }

    fun isUsable(nowMs: Long = System.currentTimeMillis()): Boolean {
        if (state == RouteState.UNAVAILABLE) return false
        return verified && !isExpired(nowMs)
    }

    fun inCooldown(nowMs: Long = System.currentTimeMillis()): Boolean {
        return cooldownUntilMs > nowMs
    }
}

data class RoutePublicInfo(
    val route: TransportRoute,
    val state: RouteState,
    val verified: Boolean,
    val active: Boolean,
    val manuallySelected: Boolean,
    val suitableForTransfer: Boolean,
    val host: String,
    val port: Int,
    val transferPort: Int,
    val expired: Boolean,
    val lastFailureReason: String?
)

data class DeviceTransportSnapshot(
    val deviceId: String,
    val mode: TransportMode,
    val activeRoute: TransportRoute?,
    val activeBadge: String?,
    val switching: Boolean,
    val recommendedRoute: TransportRoute?,
    val lastSwitchReason: String?,
    val generation: Long,
    val routes: List<RoutePublicInfo>
)

data class PinnedTransferRoute(
    val transferId: String,
    val deviceId: String,
    val route: TransportRoute,
    val host: String,
    val port: Int,
    val pinnedAtMs: Long
)

/**
 * Pure classification & priority helpers mirroring Python `snow.network.transport`.
 */
object TransportClassifier {
    private val HOTSPOT_PREFIXES = listOf(
        "192.168.43.",
        "192.168.49.",
        "192.168.137.",
        "172.20.10."
    )
    private val HOTSPOT_IFACE_HINTS = listOf(
        "ap", "swlan", "softap", "wifi_ap", "uap", "sap",
        "hotspot", "wi-fi direct", "local area connection*"
    )

    fun stripHostPort(host: String?): String {
        var raw = host?.trim().orEmpty()
        if (raw.isEmpty()) return ""
        if ("://" in raw) raw = raw.substringAfter("://")
        raw = raw.substringBefore("/")
        if (raw.startsWith("[") && "]" in raw) {
            return raw.substring(1, raw.indexOf(']')).trim().lowercase(Locale.ROOT)
        }
        val colonCount = raw.count { it == ':' }
        if (colonCount == 1) {
            return raw.substringBefore(':').trim().lowercase(Locale.ROOT)
        }
        return raw.lowercase(Locale.ROOT)
    }

    fun isLoopbackHost(host: String?): Boolean {
        val clean = stripHostPort(host)
        return clean == "127.0.0.1" ||
            clean == "localhost" ||
            clean == "::1" ||
            clean.startsWith("127.")
    }

    fun isHotspotHostOrHint(
        host: String? = null,
        transport: String? = null,
        interfaceName: String? = null,
        isHotspot: Boolean = false
    ): Boolean {
        if (isHotspot) return true
        val t = transport?.trim()?.lowercase(Locale.ROOT).orEmpty()
        if ("hotspot" in t || "softap" in t || "ap_direct" in t) return true
        val iface = interfaceName?.trim()?.lowercase(Locale.ROOT).orEmpty()
        if (iface.isNotEmpty() && HOTSPOT_IFACE_HINTS.any { iface.startsWith(it) || it in iface }) {
            return true
        }
        val cleanIp = stripHostPort(host)
        if (cleanIp.isNotEmpty() && HOTSPOT_PREFIXES.any { cleanIp.startsWith(it) }) {
            return true
        }
        return false
    }

    fun classifyRoute(
        transport: String? = null,
        host: String? = null,
        mode: String? = null,
        interfaceName: String? = null,
        isHotspot: Boolean = false
    ): TransportRoute {
        val t = transport?.trim()?.lowercase(Locale.ROOT).orEmpty()
        val m = mode?.trim()?.lowercase(Locale.ROOT).orEmpty()
        val cleanHost = stripHostPort(host)

        if (
            "usb" in t ||
            t == "adb" ||
            m == "usb" ||
            (cleanHost.isNotEmpty() &&
                isLoopbackHost(cleanHost) &&
                "relay" !in t &&
                "remote" !in t &&
                m != "remote_only" &&
                m != "remote_relay")
        ) {
            return TransportRoute.USB
        }

        if (
            "relay" in t ||
            "remote" in t ||
            "hub" in t ||
            "federated" in t ||
            m == "remote_only" ||
            m == "remote_relay" ||
            "relay" in cleanHost ||
            "tunnel" in cleanHost ||
            "onrender.com" in cleanHost
        ) {
            return TransportRoute.REMOTE_RELAY
        }

        if (isHotspotHostOrHint(cleanHost, t, interfaceName, isHotspot) || m == "hotspot") {
            return TransportRoute.HOTSPOT
        }

        return TransportRoute.WIFI_LAN
    }

    fun classifyTransportBadge(
        transport: String? = null,
        host: String? = null,
        mode: String? = null,
        interfaceName: String? = null,
        isHotspot: Boolean = false
    ): String {
        return classifyRoute(transport, host, mode, interfaceName, isHotspot).badge
    }

    fun classifyRoutePriority(
        transport: String? = null,
        host: String? = null,
        mode: String? = null,
        interfaceName: String? = null,
        isHotspot: Boolean = false
    ): Int {
        return classifyRoute(transport, host, mode, interfaceName, isHotspot).priority
    }

    /**
     * Classify the actual transport socket carrying a file transfer.
     * Never labels USB unless actual socket is loopback AND SNOW USB ADB forward mapping is verified active.
     */
    fun classifyTransferSocketRoute(
        host: String? = null,
        peerIp: String? = null,
        usbMappingVerified: Boolean = false,
        transportHint: String? = null,
        interfaceName: String? = null,
        isHotspot: Boolean = false,
        isRelay: Boolean = false
    ): Pair<TransportRoute, String> {
        val hint = transportHint?.trim()?.lowercase(Locale.ROOT).orEmpty()
        if (isRelay || "relay" in hint || "remote" in hint || "hub" in hint) {
            return TransportRoute.REMOTE_RELAY to TransportRoute.REMOTE_RELAY.badge
        }
        val effectiveIp = stripHostPort(peerIp).ifEmpty { stripHostPort(host) }
        if (effectiveIp.isNotEmpty() && isLoopbackHost(effectiveIp)) {
            val route = if (usbMappingVerified) TransportRoute.USB else TransportRoute.WIFI_LAN
            return route to route.badge
        }
        if (isHotspotHostOrHint(effectiveIp, hint, interfaceName, isHotspot)) {
            return TransportRoute.HOTSPOT to TransportRoute.HOTSPOT.badge
        }
        return TransportRoute.WIFI_LAN to TransportRoute.WIFI_LAN.badge
    }

    fun sanitizeTransportError(raw: Any?): String {
        val text = raw?.toString()?.trim().orEmpty()
        if (text.isEmpty()) return "Route verification failed."
        val lower = text.lowercase(Locale.ROOT)
        if (
            "bearer " in lower ||
            "auth_token" in lower ||
            "handshake_token" in lower ||
            "bootstrap_token" in lower ||
            "hub_token" in lower ||
            "private key" in lower
        ) {
            return "Authentication or certificate validation failed."
        }
        return text.take(220)
    }
}

/**
 * Authoritative Android transport orchestrator maintaining verified route state,
 * strict priority ranking, Make-Before-Break generation locks, and transfer pinning.
 */
class TransportOrchestrator(
    private val verificationTtlMs: Long = 30_000L,
    private val probeCooldownMs: Long = 5_000L,
    private val clockMs: () -> Long = { System.currentTimeMillis() }
) {
    private val deviceLocks = ConcurrentHashMap<String, Any>()
    private val candidatesByDevice = ConcurrentHashMap<String, MutableMap<TransportRoute, RouteCandidateEntry>>()
    private val modesByDevice = ConcurrentHashMap<String, TransportMode>()
    private val activeRouteByDevice = ConcurrentHashMap<String, TransportRoute>()
    private val generationsByDevice = ConcurrentHashMap<String, Long>()
    private val switchingDevices = ConcurrentHashMap.newKeySet<String>()
    private val lastSwitchReasonByDevice = ConcurrentHashMap<String, String>()
    private val pinnedTransfers = ConcurrentHashMap<String, PinnedTransferRoute>()

    private val _snapshots = MutableStateFlow<Map<String, DeviceTransportSnapshot>>(emptyMap())
    val snapshots: StateFlow<Map<String, DeviceTransportSnapshot>> = _snapshots.asStateFlow()

    private fun lockFor(deviceId: String): Any =
        deviceLocks.computeIfAbsent(deviceId.trim()) { Any() }

    private fun ensureCandidateMap(deviceId: String): MutableMap<TransportRoute, RouteCandidateEntry> {
        val clean = deviceId.trim()
        return candidatesByDevice.computeIfAbsent(clean) {
            TransportRoute.values().associateWithTo(LinkedHashMap()) { route ->
                RouteCandidateEntry(deviceId = clean, route = route)
            }
        }
    }

    private fun publishSnapshot(deviceId: String) {
        val clean = deviceId.trim()
        val snap = snapshotFor(clean)
        _snapshots.value = _snapshots.value.toMutableMap().apply {
            this[clean] = snap
        }
    }

    fun getMode(deviceId: String): TransportMode =
        modesByDevice[deviceId.trim()] ?: TransportMode.AUTO

    fun currentGeneration(deviceId: String): Long =
        generationsByDevice[deviceId.trim()] ?: 0L

    fun nextGeneration(deviceId: String): Long {
        val clean = deviceId.trim()
        synchronized(lockFor(clean)) {
            val next = (generationsByDevice[clean] ?: 0L) + 1L
            generationsByDevice[clean] = next
            return next
        }
    }

    fun registerDiscovered(
        deviceId: String,
        route: TransportRoute,
        host: String = "",
        port: Int = 8765,
        transferPort: Int = 8766,
        interfaceName: String? = null,
        isHotspot: Boolean = false
    ): RouteCandidateEntry {
        val clean = deviceId.trim()
        synchronized(lockFor(clean)) {
            val cmap = ensureCandidateMap(clean)
            val prev = cmap[route] ?: RouteCandidateEntry(clean, route)
            val now = clockMs()
            val updated = prev.copy(
                host = host.trim().ifEmpty { prev.host },
                port = if (port > 0) port else prev.port,
                transferPort = if (transferPort > 0) transferPort else prev.transferPort,
                interfaceName = interfaceName ?: prev.interfaceName,
                isHotspot = isHotspot || route == TransportRoute.HOTSPOT,
                state = if (prev.isUsable(now)) prev.state else RouteState.DISCOVERED,
                verified = prev.isUsable(now)
            )
            cmap[route] = updated
            publishSnapshot(clean)
            return updated
        }
    }

    fun markProbing(deviceId: String, route: TransportRoute) {
        val clean = deviceId.trim()
        synchronized(lockFor(clean)) {
            val cmap = ensureCandidateMap(clean)
            val prev = cmap[route] ?: RouteCandidateEntry(clean, route)
            if (!prev.isUsable(clockMs())) {
                cmap[route] = prev.copy(state = RouteState.PROBING, lastCheckedAtMs = clockMs())
                publishSnapshot(clean)
            }
        }
    }

    fun markVerified(
        deviceId: String,
        route: TransportRoute,
        host: String = "",
        port: Int = 8765,
        transferPort: Int = 8766,
        isActive: Boolean = false,
        interfaceName: String? = null,
        isHotspot: Boolean = false,
        expectedGeneration: Long? = null
    ): Boolean {
        val clean = deviceId.trim()
        synchronized(lockFor(clean)) {
            val curGen = generationsByDevice[clean] ?: 0L
            if (expectedGeneration != null && expectedGeneration != curGen) {
                return false
            }
            val now = clockMs()
            val cmap = ensureCandidateMap(clean)
            val nextGen = if (isActive) {
                (curGen + 1L).also { generationsByDevice[clean] = it }
            } else {
                curGen
            }
            if (isActive) {
                for (otherRoute in TransportRoute.values()) {
                    if (otherRoute != route) {
                        val other = cmap[otherRoute] ?: continue
                        if (other.state == RouteState.ACTIVE) {
                            cmap[otherRoute] = other.copy(
                                state = if (other.isUsable(now)) RouteState.VERIFIED_AVAILABLE else RouteState.CANDIDATE
                            )
                        }
                    }
                }
                activeRouteByDevice[clean] = route
                switchingDevices.remove(clean)
            }
            val prev = cmap[route] ?: RouteCandidateEntry(clean, route)
            cmap[route] = prev.copy(
                host = host.trim().ifEmpty { prev.host },
                port = if (port > 0) port else prev.port,
                transferPort = if (transferPort > 0) transferPort else prev.transferPort,
                interfaceName = interfaceName ?: prev.interfaceName,
                isHotspot = isHotspot || route == TransportRoute.HOTSPOT,
                state = if (isActive) RouteState.ACTIVE else RouteState.VERIFIED_AVAILABLE,
                verified = true,
                verifiedAtMs = now,
                lastCheckedAtMs = now,
                expiresAtMs = now + verificationTtlMs,
                cooldownUntilMs = 0L,
                lastFailureReason = null,
                generation = nextGen
            )
            publishSnapshot(clean)
            return true
        }
    }

    fun markUnavailable(
        deviceId: String,
        route: TransportRoute,
        reason: String,
        cooldownOverrideMs: Long = probeCooldownMs
    ) {
        val clean = deviceId.trim()
        synchronized(lockFor(clean)) {
            val now = clockMs()
            val cmap = ensureCandidateMap(clean)
            val prev = cmap[route] ?: RouteCandidateEntry(clean, route)
            cmap[route] = prev.copy(
                state = RouteState.UNAVAILABLE,
                verified = false,
                expiresAtMs = 0L,
                lastCheckedAtMs = now,
                cooldownUntilMs = now + cooldownOverrideMs.coerceAtLeast(0L),
                lastFailureReason = TransportClassifier.sanitizeTransportError(reason)
            )
            if (activeRouteByDevice[clean] == route) {
                activeRouteByDevice.remove(clean)
            }
            publishSnapshot(clean)
        }
    }

    fun setSwitching(deviceId: String, switching: Boolean, reason: String? = null) {
        val clean = deviceId.trim()
        if (switching) switchingDevices.add(clean) else switchingDevices.remove(clean)
        if (!reason.isNullOrBlank()) {
            lastSwitchReasonByDevice[clean] = reason
        }
        publishSnapshot(clean)
    }

    /**
     * Request a mode change. Single-route manual modes FAIL CLOSED unless that route
     * is currently verified (or [allowVerified] is true). Never mutates active connection on rejection.
     */
    fun setMode(
        deviceId: String,
        mode: TransportMode,
        reason: String? = null
    ): Pair<Boolean, String> {
        val clean = deviceId.trim()
        synchronized(lockFor(clean)) {
            val now = clockMs()
            val cmap = ensureCandidateMap(clean)
            val targetRoute = mode.targetRouteOrNull()
            if (targetRoute != null) {
                val cand = cmap[targetRoute]
                if (cand == null || !cand.isUsable(now)) {
                    val err = cand?.lastFailureReason ?: "Route '${targetRoute.badge}' is not verified."
                    return false to err
                }
            } else if (mode == TransportMode.LOCAL_ONLY) {
                val hasLocal = listOf(TransportRoute.USB, TransportRoute.HOTSPOT, TransportRoute.WIFI_LAN)
                    .any { r -> cmap[r]?.let { it.isUsable(now) || it.host.isNotBlank() } == true }
                if (!hasLocal && activeRouteByDevice[clean] == TransportRoute.REMOTE_RELAY) {
                    return false to "No verified local route available for Local Only mode."
                }
            } else if (mode == TransportMode.REMOTE_ONLY) {
                val relay = cmap[TransportRoute.REMOTE_RELAY]
                if (relay == null || !relay.isUsable(now)) {
                    return false to (relay?.lastFailureReason ?: "Remote relay is not connected.")
                }
            }
            modesByDevice[clean] = mode
            if (!reason.isNullOrBlank()) {
                lastSwitchReasonByDevice[clean] = reason
            }
            publishSnapshot(clean)
            return true to "Updated mode to ${mode.wireName}"
        }
    }

    fun handleTransportLoss(
        deviceId: String,
        lostRoute: TransportRoute,
        reason: String
    ): RouteCandidateEntry? {
        val clean = deviceId.trim()
        synchronized(lockFor(clean)) {
            markUnavailable(clean, lostRoute, reason)
            val mode = getMode(clean)
            if (mode.isSingleRouteOverride() && mode.targetRouteOrNull() == lostRoute) {
                lastSwitchReasonByDevice[clean] = "Manual ${lostRoute.badge} lost (pinned fail-closed)"
                publishSnapshot(clean)
                return null
            }
            val now = clockMs()
            val cmap = ensureCandidateMap(clean)
            val next = TransportRoute.values()
                .filter { it != lostRoute }
                .filter { r ->
                    when (mode) {
                        TransportMode.LOCAL_ONLY -> r != TransportRoute.REMOTE_RELAY
                        TransportMode.REMOTE_ONLY, TransportMode.REMOTE_RELAY -> r == TransportRoute.REMOTE_RELAY
                        TransportMode.USB -> r == TransportRoute.USB
                        TransportMode.HOTSPOT -> r == TransportRoute.HOTSPOT
                        TransportMode.WIFI_LAN -> r == TransportRoute.WIFI_LAN
                        TransportMode.AUTO -> true
                    }
                }
                .mapNotNull { cmap[it] }
                .firstOrNull { it.isUsable(now) || (it.host.isNotBlank() && !it.inCooldown(now) && it.state != RouteState.UNAVAILABLE) }

            lastSwitchReasonByDevice[clean] = if (next != null) {
                "Failover ${lostRoute.shortLabel} -> ${next.route.shortLabel}"
            } else {
                "No fallback after ${lostRoute.shortLabel} loss"
            }
            publishSnapshot(clean)
            return next
        }
    }

    fun pinTransfer(transferId: String, deviceId: String, route: TransportRoute, host: String, port: Int) {
        pinnedTransfers[transferId] = PinnedTransferRoute(
            transferId = transferId,
            deviceId = deviceId.trim(),
            route = route,
            host = host,
            port = port,
            pinnedAtMs = clockMs()
        )
    }

    fun getPinnedTransfer(transferId: String): PinnedTransferRoute? = pinnedTransfers[transferId]

    fun unpinTransfer(transferId: String) {
        pinnedTransfers.remove(transferId)
    }

    fun hasActivePinnedTransfer(deviceId: String): Boolean {
        val clean = deviceId.trim()
        return pinnedTransfers.values.any { it.deviceId == clean }
    }

    /**
     * Select the highest-priority fallback HTTP transfer target `(host, transferPort)` for [deviceId]
     * when [failedRoute] at [failedHost] fails, honoring single-route manual pins fail-closed.
     */
    fun selectTransferFallbackTarget(
        deviceId: String,
        failedHost: String,
        failedRoute: TransportRoute,
        failedPort: Int = -1
    ): Pair<String, Int>? {
        val clean = deviceId.trim()
        if (clean.isEmpty()) return null
        synchronized(lockFor(clean)) {
            val mode = getMode(clean)
            if (mode.isSingleRouteOverride() && mode.targetRouteOrNull() == failedRoute) {
                return null
            }
            val now = clockMs()
            val cmap = ensureCandidateMap(clean)
            val candidate = TransportRoute.values()
                .filter { it != failedRoute && it != TransportRoute.REMOTE_RELAY }
                .filter { r ->
                    when (mode) {
                        TransportMode.AUTO, TransportMode.LOCAL_ONLY -> true
                        TransportMode.REMOTE_ONLY, TransportMode.REMOTE_RELAY -> false
                        TransportMode.USB -> r == TransportRoute.USB
                        TransportMode.HOTSPOT -> r == TransportRoute.HOTSPOT
                        TransportMode.WIFI_LAN -> r == TransportRoute.WIFI_LAN
                    }
                }
                .mapNotNull { cmap[it] }
                .firstOrNull { cand ->
                    val validHost = cand.host.trim()
                    validHost.isNotEmpty() &&
                        !validHost.equals("relay", ignoreCase = true) &&
                        !(validHost == failedHost.trim() && (failedPort <= 0 || cand.transferPort == failedPort)) &&
                        !cand.inCooldown(now) &&
                        cand.state != RouteState.UNAVAILABLE
                }
            return candidate?.let { cand ->
                cand.host.trim() to (if (cand.transferPort in 1..65535) cand.transferPort else 8766)
            }
        }
    }

    /**
     * Evaluate whether a higher-priority route candidate should be probed/promoted right now.
     * Respects mode pins, sticky active multi-GB transfer pins, TTLs, and cooldowns.
     */
    fun selectHigherPriorityCandidate(deviceId: String): RouteCandidateEntry? {
        val clean = deviceId.trim()
        synchronized(lockFor(clean)) {
            if (hasActivePinnedTransfer(clean)) {
                return null
            }
            val now = clockMs()
            val mode = getMode(clean)
            val active = activeRouteByDevice[clean]
            val cmap = ensureCandidateMap(clean)

            return TransportRoute.values()
                .filter { r ->
                    when (mode) {
                        TransportMode.AUTO -> active == null || r.priority < active.priority
                        TransportMode.LOCAL_ONLY -> r != TransportRoute.REMOTE_RELAY && (active == null || active == TransportRoute.REMOTE_RELAY || r.priority < active.priority)
                        TransportMode.REMOTE_ONLY, TransportMode.REMOTE_RELAY -> r == TransportRoute.REMOTE_RELAY && active != TransportRoute.REMOTE_RELAY
                        TransportMode.USB -> r == TransportRoute.USB && active != TransportRoute.USB
                        TransportMode.HOTSPOT -> r == TransportRoute.HOTSPOT && active != TransportRoute.HOTSPOT
                        TransportMode.WIFI_LAN -> r == TransportRoute.WIFI_LAN && active != TransportRoute.WIFI_LAN
                    }
                }
                .mapNotNull { cmap[it] }
                .firstOrNull { cand ->
                    (cand.host.isNotBlank() || cand.route == TransportRoute.REMOTE_RELAY) &&
                        !cand.inCooldown(now) &&
                        cand.state != RouteState.UNAVAILABLE
                }
        }
    }

    fun snapshotFor(deviceId: String): DeviceTransportSnapshot {
        val clean = deviceId.trim()
        val now = clockMs()
        val cmap = ensureCandidateMap(clean)
        val mode = getMode(clean)
        val active = activeRouteByDevice[clean]
        val list = TransportRoute.values().map { route ->
            val cand = cmap[route] ?: RouteCandidateEntry(clean, route)
            val usable = cand.isUsable(now)
            val isAct = (active == route) && usable
            val expired = cand.verified && cand.isExpired(now)
            val effState = when {
                isAct -> RouteState.ACTIVE
                expired -> RouteState.UNAVAILABLE
                else -> cand.state
            }
            RoutePublicInfo(
                route = route,
                state = effState,
                verified = usable,
                active = isAct,
                manuallySelected = (mode.targetRouteOrNull() == route),
                suitableForTransfer = cand.suitableForTransfer && (usable || isAct),
                host = if (route.isLocal) cand.host else "",
                port = cand.port,
                transferPort = cand.transferPort,
                expired = expired,
                lastFailureReason = cand.lastFailureReason
            )
        }
        val recommended = list.firstOrNull { it.verified }?.route
        return DeviceTransportSnapshot(
            deviceId = clean,
            mode = mode,
            activeRoute = if (active != null && list.any { it.route == active && it.active }) active else null,
            activeBadge = active?.takeIf { a -> list.any { it.route == a && it.active } }?.badge,
            switching = clean in switchingDevices,
            recommendedRoute = recommended,
            lastSwitchReason = lastSwitchReasonByDevice[clean],
            generation = generationsByDevice[clean] ?: 0L,
            routes = list
        )
    }

    companion object {
        /**
         * Pure evaluation helper mirroring Python `evaluate_preferred_route`.
         */
        fun evaluatePreferredCandidate(
            candidates: List<RouteCandidateEntry>,
            mode: TransportMode = TransportMode.AUTO,
            nowMs: Long = System.currentTimeMillis()
        ): RouteCandidateEntry? {
            return candidates
                .filter { it.state != RouteState.UNAVAILABLE && (!it.verified || !it.isExpired(nowMs)) }
                .filter { cand ->
                    when (mode) {
                        TransportMode.AUTO -> true
                        TransportMode.LOCAL_ONLY -> cand.route != TransportRoute.REMOTE_RELAY
                        TransportMode.REMOTE_ONLY, TransportMode.REMOTE_RELAY -> cand.route == TransportRoute.REMOTE_RELAY
                        TransportMode.USB -> cand.route == TransportRoute.USB
                        TransportMode.HOTSPOT -> cand.route == TransportRoute.HOTSPOT
                        TransportMode.WIFI_LAN -> cand.route == TransportRoute.WIFI_LAN
                    }
                }
                .minByOrNull { it.route.priority }
        }
    }
}
