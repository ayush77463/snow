package org.snow.network

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat

/**
 * Standard execution and availability profile for participating devices.
 */
enum class ReachabilityProfile {
    PERSISTENT_DAEMON,
    ACTIVE_SESSION_PEER,
    FOREGROUND_HOST
}

/**
 * Reachability state governing connectivity within the SNOW mesh.
 */
enum class ReachabilityState {
    CONNECTED_SESSION,
    LAN_DISCOVERABLE,
    LAST_KNOWN_IP_DIRECT,
    ONLINE_ROUTED,
    ONLINE_RELAYED,
    DORMANT_RELAY,
    UNREACHABLE_OFFLINE
}

/**
 * Execution classifications reflecting OS and user-interaction constraints.
 */
object CapabilityClassification {
    const val BACKGROUND_SAFE = "BACKGROUND_SAFE"
    const val RUNTIME_PERMISSION_REQUIRED = "RUNTIME_PERMISSION_REQUIRED"
    const val FOREGROUND_USER_INTERACTION_REQUIRED = "FOREGROUND_USER_INTERACTION_REQUIRED"
}

/**
 * Platform-independent capability advertisement and permission manifest.
 */
data class CapabilityManifest(
    val manifestVersion: String = "2.0",
    val supportedCapabilities: List<String> = emptyList(),
    val permissionStates: Map<String, String> = emptyMap(),
    val classifications: Map<String, String> = emptyMap()
) {
    fun supportsCapability(capability: String): Boolean {
        return supportedCapabilities.contains(capability.trim())
    }

    fun isBackgroundSafe(capability: String): Boolean {
        return classifications[capability] == CapabilityClassification.BACKGROUND_SAFE
    }

    fun toMap(): Map<String, Any> {
        return mapOf(
            "manifest_version" to manifestVersion,
            "supported_capabilities" to supportedCapabilities,
            "permission_states" to permissionStates,
            "classifications" to classifications
        )
    }

    companion object {
        fun fromMap(data: Map<String, Any?>?): CapabilityManifest {
            if (data == null) return CapabilityManifest()

            val version = data["manifest_version"] as? String ?: "2.0"

            val caps = mutableListOf<String>()
            val rawCaps = data["supported_capabilities"] as? List<*>
            rawCaps?.forEach { item ->
                if (item is String && item.isNotBlank()) {
                    caps.add(item.trim())
                }
            }

            val perms = mutableMapOf<String, String>()
            val rawPerms = data["permission_states"] as? Map<*, *>
            rawPerms?.forEach { (k, v) ->
                if (k is String && v is String) {
                    perms[k.trim()] = v.trim()
                }
            }

            val classes = mutableMapOf<String, String>()
            val rawClasses = data["classifications"] as? Map<*, *>
            rawClasses?.forEach { (k, v) ->
                if (k is String && v is String) {
                    classes[k.trim()] = v.trim()
                }
            }

            return CapabilityManifest(
                manifestVersion = version,
                supportedCapabilities = caps,
                permissionStates = perms,
                classifications = classes
            )
        }
    }
}

/**
 * Logical representation of a participating node in the SNOW platform.
 */
data class DeviceNode(
    val deviceId: String,
    val deviceName: String,
    val platform: String = "android",
    val protocolVersion: Int = 1,
    val reachabilityProfile: ReachabilityProfile = ReachabilityProfile.ACTIVE_SESSION_PEER,
    val reachabilityState: ReachabilityState = ReachabilityState.UNREACHABLE_OFFLINE,
    val host: String? = null,
    val wssPort: Int = 8765,
    val transferPort: Int = 8766,
    val supportedCapabilities: List<String> = emptyList(),
    val permissionStates: Map<String, String> = emptyMap(),
    val lastSeenTimestamp: Double = 0.0,
    val trustTier: String? = null,
    val capabilities: CapabilityManifest? = null,
    val isAuthenticated: Boolean = false,
    val isConnected: Boolean = false,
    val isPaired: Boolean = false
) {
    fun supportsCapability(capability: String): Boolean {
        if (capabilities != null) {
            return capabilities.supportsCapability(capability)
        }
        return supportedCapabilities.contains(capability.trim())
    }

    fun toMap(): Map<String, Any?> {
        val map = mutableMapOf<String, Any?>(
            "device_id" to deviceId,
            "device_name" to deviceName,
            "platform" to platform,
            "protocol_version" to protocolVersion,
            "reachability_profile" to reachabilityProfile.name,
            "reachability_state" to reachabilityState.name,
            "host" to host,
            "wss_port" to wssPort,
            "transfer_port" to transferPort,
            "supported_capabilities" to supportedCapabilities,
            "permission_states" to permissionStates,
            "last_seen_timestamp" to lastSeenTimestamp,
            "trust_tier" to trustTier,
            "is_authenticated" to isAuthenticated,
            "is_connected" to isConnected,
            "is_paired" to isPaired
        )
        if (capabilities != null) {
            map["capabilities"] = capabilities.toMap()
        }
        return map
    }

    companion object {
        fun fromMap(data: Map<String, Any?>?): DeviceNode? {
            if (data == null) return null
            val id = data["device_id"] as? String ?: return null
            val name = data["device_name"] as? String ?: return null
            val platform = data["platform"] as? String ?: "android"
            val protoVer = (data["protocol_version"] as? Number)?.toInt() ?: 1
            val reachProfStr = data["reachability_profile"] as? String ?: ReachabilityProfile.ACTIVE_SESSION_PEER.name
            val reachProf = try { ReachabilityProfile.valueOf(reachProfStr) } catch (_: Exception) { ReachabilityProfile.ACTIVE_SESSION_PEER }
            val reachStateStr = data["reachability_state"] as? String ?: ReachabilityState.UNREACHABLE_OFFLINE.name
            val reachState = try { ReachabilityState.valueOf(reachStateStr) } catch (_: Exception) { ReachabilityState.UNREACHABLE_OFFLINE }
            val host = data["host"] as? String
            val wssPort = (data["wss_port"] as? Number)?.toInt() ?: 8765
            val transferPort = (data["transfer_port"] as? Number)?.toInt() ?: 8766
            val capsManifest = (data["capabilities"] as? Map<*, *>)?.let {
                @Suppress("UNCHECKED_CAST")
                CapabilityManifest.fromMap(it as Map<String, Any?>)
            }
            val suppCaps = (data["supported_capabilities"] as? List<*>)?.filterIsInstance<String>() ?: emptyList()
            val permStates = (data["permission_states"] as? Map<*, *>)?.let { raw ->
                raw.entries.mapNotNull { (k, v) -> if (k is String && v is String) k to v else null }.toMap()
            } ?: emptyMap()
            val rawTs = data["last_seen_timestamp"]
            val lastSeen = when (rawTs) {
                is Number -> {
                    val d = rawTs.toDouble()
                    // Safe migration: if > 1e11, it is epoch millis -> convert to seconds
                    if (d > 1e11) d / 1000.0 else d
                }
                else -> 0.0
            }
            val trustTier = data["trust_tier"] as? String
            val isAuth = (data["is_authenticated"] as? Boolean) ?: false
            val isConn = (data["is_connected"] as? Boolean) ?: false
            val isPaired = (data["is_paired"] as? Boolean) ?: false

            return DeviceNode(
                deviceId = id,
                deviceName = name,
                platform = platform,
                protocolVersion = protoVer,
                reachabilityProfile = reachProf,
                reachabilityState = reachState,
                host = host,
                wssPort = wssPort,
                transferPort = transferPort,
                supportedCapabilities = suppCaps,
                permissionStates = permStates,
                lastSeenTimestamp = lastSeen,
                trustTier = trustTier,
                capabilities = capsManifest,
                isAuthenticated = isAuth,
                isConnected = isConn,
                isPaired = isPaired
            )
        }

        /**
         * Construct the authoritative Android capability manifest.
         * Reflects Android 17 permission matrix and actual runtime state.
         */
        fun buildAndroidManifest(context: Context? = null): CapabilityManifest {
            val supported = listOf(
                "android.telemetry.get",
                "android.notifications.push",
                "android.clipboard.set",
                "android.clipboard.get",
                "android.apps.list",
                "android.apps.launch",
                "android.messaging.send_intent",
                "android.files.transfer",
                "android.ringer.ring"
            )

            val classifications = mapOf(
                "android.telemetry.get" to CapabilityClassification.BACKGROUND_SAFE,
                "android.notifications.push" to CapabilityClassification.RUNTIME_PERMISSION_REQUIRED,
                "android.clipboard.set" to CapabilityClassification.BACKGROUND_SAFE,
                "android.clipboard.get" to CapabilityClassification.FOREGROUND_USER_INTERACTION_REQUIRED,
                "android.apps.list" to CapabilityClassification.BACKGROUND_SAFE,
                "android.apps.launch" to CapabilityClassification.FOREGROUND_USER_INTERACTION_REQUIRED,
                "android.messaging.send_intent" to CapabilityClassification.FOREGROUND_USER_INTERACTION_REQUIRED,
                "android.files.transfer" to CapabilityClassification.RUNTIME_PERMISSION_REQUIRED,
                "android.ringer.ring" to CapabilityClassification.BACKGROUND_SAFE
            )

            val perms = mutableMapOf<String, String>()
            perms["android.telemetry.get"] = "GRANTED"
            perms["android.clipboard.set"] = "GRANTED"
            perms["android.clipboard.get"] = "GRANTED"
            perms["android.apps.launch"] = "GRANTED"
            perms["android.messaging.send_intent"] = "GRANTED"
            perms["android.files.transfer"] = "GRANTED"
            perms["android.apps.list"] = "GRANTED"
            perms["android.ringer.ring"] = "GRANTED"

            // Check POST_NOTIFICATIONS permission for Android 13+ (API 33+) if context available
            if (context != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val hasNotif = ContextCompat.checkSelfPermission(
                    context,
                    android.Manifest.permission.POST_NOTIFICATIONS
                ) == PackageManager.PERMISSION_GRANTED
                perms["android.notifications.push"] = if (hasNotif) "GRANTED" else "DENIED"
            } else {
                perms["android.notifications.push"] = "GRANTED"
            }

            return CapabilityManifest(
                manifestVersion = "2.0",
                supportedCapabilities = supported,
                permissionStates = perms,
                classifications = classifications
            )
        }
    }
}
