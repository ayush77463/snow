package org.snow.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.BatteryManager
import android.os.Build
import android.provider.MediaStore
import android.widget.Toast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.snow.capabilities.CameraCaptureHandler
import org.snow.capabilities.ClipboardHandler
import org.snow.capabilities.LiveScreenStreamHandler
import org.snow.capabilities.RingerHandler
import org.snow.capabilities.ScreenshotObserver
import org.snow.network.AuthState
import org.snow.network.ConnectionState
import org.snow.network.DiscoveredPeer
import org.snow.network.SnowWebSocketClient
import org.snow.security.DeviceIdentity
import org.snow.security.EncryptedCertPinStorage
import org.snow.security.PairingFlow
import org.snow.security.PairingState
import org.snow.security.SafeLog
import org.snow.security.SharedPreferencesTokenStorage
import org.snow.service.SnowForegroundService
import org.snow.transfer.FileTransferClient
import org.snow.ui.files.SafFolderManager
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

fun formatApplyClipboardFeedback(success: Boolean, msg: String?): String {
    return if (success) {
        msg?.trim()?.takeIf { it.isNotEmpty() } ?: "Applied to clipboard!"
    } else {
        "Failed: ${msg?.trim()?.takeIf { it.isNotEmpty() } ?: "Unknown error"}"
    }
}

/**
 * Central state and capability repository for the SNOW UI layer.
 *
 * Exposes observable StateFlows for connection, discovery, telemetry, transfers,
 * and terminal state while isolating the UI from raw WebSocket lifecycle details.
 */
class SnowUiRepository private constructor(private val appContext: Context) {

    companion object {
        private const val TAG = "SnowUiRepository"
        const val MAX_CONNECT_RETRIES = 3
        const val PREFS_SETTINGS = "snow_settings"
        const val PREF_KEY_INSTANT_SYNC = "instant_clipboard_sync"
        const val PREF_KEY_AUTO_SYNC_SCREENSHOTS = "auto_sync_screenshots"
        const val PREF_KEY_AUTO_CONNECT_ENABLED = "auto_connect_nearby"
        const val PREF_KEY_REMOTE_RELAY_ENABLED = "remote_relay_enabled"
        const val PREF_KEY_REMOTE_RELAY_ENDPOINT = "remote_relay_endpoint"
        const val PREF_KEY_ADOPTED_NETWORK_ID = "adopted_network_id"
        const val PREF_KEY_PERMISSION_PROFILE = "permission_profile"
        const val PREFS_CLIPBOARD_ACK = "snow_clipboard_ack_prefs"
        const val PREF_KEY_CLIP_LAST_ACKED_SEQ = "clip_last_acked_seq"
        const val PREF_KEY_CLIP_LAST_COMMITTED_EVENT = "clip_last_committed_event_id"
        const val PREF_KEY_CLIP_LAST_COMMITTED_SEQ = "clip_last_committed_seq"
        const val MAX_CLIPBOARD_ITEMS = 15
        const val MAX_CLIPBOARD_TEXT_BYTES = 64 * 1024
        const val MAX_CLIPBOARD_IMAGE_BYTES = 15L * 1024L * 1024L
        const val MAX_CLIPBOARD_FILE_BYTES = 15L * 1024L * 1024L
        const val MAX_CLIPBOARD_BUNDLE_BYTES = 15L * 1024L * 1024L
        const val MAX_CLIPBOARD_BUNDLE_FILES = 5
        private val SHA256_HEX_REGEX = Regex("^[0-9a-fA-F]{64}$")

        fun parseClipboardFileManifest(rawList: Any?): List<ClipboardFileEntryDto> {
            val list = rawList as? List<*> ?: return emptyList()
            val out = mutableListOf<ClipboardFileEntryDto>()
            for ((idx, item) in list.withIndex()) {
                val map = item as? Map<*, *> ?: continue
                val rawName = (map["name"] as? String) ?: (map["file_name"] as? String) ?: continue
                val safeName = try {
                    org.snow.capabilities.ClipboardHandler.sanitizeClipboardFileName(rawName)
                } catch (_: IllegalArgumentException) {
                    continue
                }
                val size = (map["size_bytes"] as? Number)?.toLong()
                    ?: (map["size"] as? Number)?.toLong() ?: 0L
                if (size < 0L || size > MAX_CLIPBOARD_FILE_BYTES) continue
                val sha = (map["sha256"] as? String)?.trim()?.lowercase() ?: ""
                if (!SHA256_HEX_REGEX.matches(sha)) continue
                val mime = (map["mime_type"] as? String)?.trim()?.takeIf { it.isNotBlank() }
                    ?: "application/octet-stream"
                val entryIdx = (map["index"] as? Number)?.toInt() ?: idx
                val transferId = (map["transfer_id"] as? String)?.trim()?.takeIf { it.isNotBlank() }
                val transferPort = (map["transfer_port"] as? Number)?.toInt() ?: 8766
                out.add(
                    ClipboardFileEntryDto(
                        index = entryIdx,
                        name = safeName,
                        sizeBytes = size,
                        mimeType = mime,
                        sha256 = sha,
                        transferId = transferId,
                        transferPort = transferPort
                    )
                )
            }
            return out
        }

        fun validateIncomingFileBundlePayload(rawList: Any?): Result<List<ClipboardFileEntryDto>> {
            val list = rawList as? List<*>
                ?: return Result.failure(IllegalArgumentException("Missing files manifest list."))
            if (list.isEmpty() || list.size > MAX_CLIPBOARD_BUNDLE_FILES) {
                return Result.failure(
                    IllegalArgumentException("Clipboard bundle must contain 1 to $MAX_CLIPBOARD_BUNDLE_FILES files.")
                )
            }
            val parsed = mutableListOf<ClipboardFileEntryDto>()
            var totalBytes = 0L
            for ((idx, rawEntry) in list.withIndex()) {
                val map = rawEntry as? Map<*, *>
                    ?: return Result.failure(IllegalArgumentException("Invalid file manifest entry at index $idx."))
                val rawName = (map["name"] as? String) ?: (map["file_name"] as? String)
                    ?: return Result.failure(IllegalArgumentException("Missing file name at index $idx."))
                val safeName = org.snow.capabilities.ClipboardHandler.sanitizeClipboardFileName(rawName)
                val size = (map["size_bytes"] as? Number)?.toLong()
                    ?: (map["size"] as? Number)?.toLong() ?: -1L
                if (size < 0L || size > MAX_CLIPBOARD_FILE_BYTES) {
                    return Result.failure(
                        IllegalArgumentException("File '$safeName' exceeds 15 MiB clipboard file limit.")
                    )
                }
                totalBytes += size
                if (totalBytes > MAX_CLIPBOARD_BUNDLE_BYTES) {
                    return Result.failure(
                        IllegalArgumentException("Clipboard bundle aggregate size exceeds 15 MiB limit.")
                    )
                }
                val sha = (map["sha256"] as? String)?.trim()?.lowercase() ?: ""
                if (!SHA256_HEX_REGEX.matches(sha)) {
                    return Result.failure(
                        IllegalArgumentException("File '$safeName' has invalid SHA-256 digest.")
                    )
                }
                val transferId = (map["transfer_id"] as? String)?.trim()
                if (transferId.isNullOrBlank()) {
                    return Result.failure(
                        IllegalArgumentException("File '$safeName' is missing transfer_id.")
                    )
                }
                val mime = (map["mime_type"] as? String)?.trim()?.takeIf { it.isNotBlank() }
                    ?: "application/octet-stream"
                val transferPort = (map["transfer_port"] as? Number)?.toInt() ?: 8766
                parsed.add(
                    ClipboardFileEntryDto(
                        index = (map["index"] as? Number)?.toInt() ?: idx,
                        name = safeName,
                        sizeBytes = size,
                        mimeType = mime,
                        sha256 = sha,
                        transferId = transferId,
                        transferPort = transferPort
                    )
                )
            }
            return Result.success(parsed)
        }

        fun parseClipboardBufferItems(rawItems: List<*>): List<ClipboardItemDto> {
            return rawItems.mapNotNull { itemMap ->
                (itemMap as? Map<*, *>)?.let { map ->
                    val contentType = (map["content_type"] as? String)
                        ?: (map["type"] as? String) ?: "text"
                    val originId = (map["origin_device_id"] as? String)
                        ?: (map["source_device_id"] as? String)
                        ?: (map["source_device"] as? String)
                        ?: "pc"
                    val manifest = if (contentType == "file" || contentType == "file_bundle") {
                        parseClipboardFileManifest(map["file_manifest"])
                    } else {
                        emptyList()
                    }
                    ClipboardItemDto(
                        itemId = map["item_id"] as? String ?: "",
                        type = contentType,
                        sourceDevice = map["source_device"] as? String ?: originId,
                        previewText = map["preview_text"] as? String
                            ?: (map["preview"] as? String ?: (map["text_content"] as? String ?: "")),
                        sizeBytes = (map["size_bytes"] as? Number)?.toLong() ?: 0L,
                        timestamp = (map["timestamp"] as? Number)?.toDouble() ?: 0.0,
                        isPinned = (map["is_pinned"] as? Boolean) ?: (map["pinned"] as? Boolean) ?: false,
                        eventId = map["event_id"] as? String ?: "",
                        seq = (map["seq"] as? Number)?.toLong() ?: 0L,
                        originDeviceId = originId,
                        sha256 = (map["sha256"] as? String) ?: "",
                        mimeType = (map["mime_type"] as? String) ?: "",
                        fileManifest = manifest
                    )
                }
            }.filter { it.itemId.isNotBlank() }
                .sortedWith(compareByDescending<ClipboardItemDto> { it.seq }.thenByDescending { it.timestamp })
                .take(MAX_CLIPBOARD_ITEMS)
        }

        fun shouldApplyRemoteClipboardEvent(
            originDeviceId: String?,
            selfDeviceId: String,
            eventId: String?,
            seq: Long,
            lastAckedSeq: Long
        ): Boolean {
            val cleanOrigin = originDeviceId?.trim()
            if (!cleanOrigin.isNullOrBlank() && cleanOrigin == selfDeviceId.trim()) {
                return false
            }
            if (seq > 0L && seq <= lastAckedSeq) {
                return false
            }
            return true
        }

        data class BatteryIntentSpec(
            val action: String,
            val dataUri: String? = null
        )

        data class ShareCodeAvailability(
            val allowed: Boolean,
            val reason: String? = null
        )

        fun createBatteryOptimizationIntentSpecs(packageName: String): List<BatteryIntentSpec> {
            val cleanPkg = packageName.trim()
            val specs = mutableListOf(
                BatteryIntentSpec(
                    action = android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS,
                    dataUri = null
                )
            )
            if (cleanPkg.isNotEmpty()) {
                specs.add(
                    BatteryIntentSpec(
                        action = android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        dataUri = "package:$cleanPkg"
                    )
                )
            }
            return specs
        }

        @Volatile
        internal var batteryIntentLauncherForTest: ((Context, BatteryIntentSpec, Intent) -> Unit)? = null

        fun openBatteryOptimizationSettings(context: Context): Boolean {
            val specs = createBatteryOptimizationIntentSpecs(context.packageName)
            val customLauncher = batteryIntentLauncherForTest
            for (spec in specs) {
                try {
                    val intent = Intent(spec.action).apply {
                        spec.dataUri?.let { data = Uri.parse(it) }
                        if (context !is android.app.Activity) {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                    }
                    if (customLauncher != null) {
                        customLauncher.invoke(context, spec, intent)
                    } else {
                        context.startActivity(intent)
                    }
                    return true
                } catch (_: Exception) {
                    // Fall through to safer App Info settings fallback
                }
            }
            try {
                Toast.makeText(
                    context,
                    "Open Settings -> Apps -> SNOW -> Battery to manage background battery usage.",
                    Toast.LENGTH_LONG
                ).show()
            } catch (_: Exception) {
            }
            return false
        }

        fun evaluateShareCodeEligibility(
            connectionState: ConnectionState,
            authState: AuthState,
            supportedCapabilities: Set<String>? = null
        ): ShareCodeAvailability {
            if (connectionState != ConnectionState.CONNECTED) {
                return ShareCodeAvailability(false, "Connect to your paired device before generating a Share Code.")
            }
            if (authState !is AuthState.Authenticated) {
                return ShareCodeAvailability(false, "Authenticate your session before generating a Share Code.")
            }
            val normTier = normalizeTrustTier(authState.trustTier)
            if (normTier != "owner") {
                return ShareCodeAvailability(false, "Owner trust is required to generate a Share Code.")
            }
            if (supportedCapabilities != null &&
                supportedCapabilities.isNotEmpty() &&
                "federation" !in supportedCapabilities &&
                "federation_create_invite" !in supportedCapabilities
            ) {
                return ShareCodeAvailability(false, "Connected peer does not support cross-network Share Codes.")
            }
            return ShareCodeAvailability(true, null)
        }

        fun normalizeTrustTier(raw: String?): String {
            return when (raw?.trim()?.lowercase()) {
                "owner", "owner_manual" -> "owner"
                else -> "peer"
            }
        }

        fun isExplicitPermissionProfileToken(raw: String?): Boolean {
            return when (raw?.trim()?.lowercase()) {
                "full_control", "full control", "full",
                "files_and_clipboard", "files & clipboard", "files & clip",
                "files_only", "files only",
                "clipboard_only", "clipboard only", "read_only", "clip only",
                "not_allowed", "not allowed", "none", "blocked", "deny" -> true
                else -> false
            }
        }

        /**
         * Migrate legacy SavedDevice trustTier/permissionProfile fields safely.
         * Never converts OWNER/PEER trust tiers or missing permission data into full_control.
         */
        fun resolveSeparatedTrustAndProfile(
            rawTrustTier: String?,
            rawPermissionProfile: String?
        ): Pair<String, String> {
            val cleanProfile = rawPermissionProfile?.trim().orEmpty()
            if (cleanProfile.isNotEmpty()) {
                return normalizeTrustTier(rawTrustTier) to normalizeAccessProfile(cleanProfile)
            }
            if (isExplicitPermissionProfileToken(rawTrustTier)) {
                return "peer" to normalizeAccessProfile(rawTrustTier!!)
            }
            return normalizeTrustTier(rawTrustTier) to "not_allowed"
        }

        fun normalizeAccessProfile(raw: String): String {
            return when (raw.trim().lowercase()) {
                "full_control", "full control", "full" -> "full_control"
                "files_and_clipboard", "files & clipboard", "files & clip" -> "files_and_clipboard"
                "files_only", "files only" -> "files_only"
                "clipboard_only", "clipboard only", "read_only", "clip only" -> "clipboard_only"
                "not_allowed", "not allowed", "none", "blocked", "deny" -> "not_allowed"
                else -> "not_allowed" // Trust tiers (OWNER/PEER) and unknown tokens fail closed
            }
        }

        internal fun normalizeCertFingerprint(fp: String?): String? {
            val cleaned = fp?.trim()?.replace(":", "")?.replace(" ", "")?.lowercase().orEmpty()
            return cleaned.takeIf { it.isNotEmpty() }
        }

        internal fun isWeakSyntheticDeviceId(deviceId: String?): Boolean {
            val clean = deviceId?.trim()?.lowercase().orEmpty()
            return clean.isEmpty() ||
                clean == "paired-desktop-legacy" ||
                clean.startsWith("peer-")
        }

        internal fun canMergeSavedDevices(a: SavedDevice, b: SavedDevice): Boolean {
            val aSnow = a.snowId?.trim()?.uppercase()?.takeIf { it.isNotEmpty() }
            val bSnow = b.snowId?.trim()?.uppercase()?.takeIf { it.isNotEmpty() }
            val aStrongId = a.deviceId.trim().takeIf { !isWeakSyntheticDeviceId(it) }
            val bStrongId = b.deviceId.trim().takeIf { !isWeakSyntheticDeviceId(it) }
            val aFp = normalizeCertFingerprint(a.certFingerprint)
            val bFp = normalizeCertFingerprint(b.certFingerprint)

            // Reject explicit identity conflicts first
            if (aSnow != null && bSnow != null && aSnow != bSnow) return false
            if (aStrongId != null && bStrongId != null && !aStrongId.equals(bStrongId, ignoreCase = true)) return false
            if (aFp != null && bFp != null && aFp != bFp) return false

            // 1. Canonical SNOW ID
            if (aSnow != null && bSnow != null && aSnow == bSnow) return true
            // 2. Canonical strong deviceId
            if (aStrongId != null && bStrongId != null && aStrongId.equals(bStrongId, ignoreCase = true)) return true
            // 3. Normalized certFingerprint
            if (aFp != null && bFp != null && aFp == bFp) return true

            // 4. Cautious host:port fallback ONLY when neither record has a stronger identifier
            val aHasStrong = aSnow != null || aStrongId != null || aFp != null
            val bHasStrong = bSnow != null || bStrongId != null || bFp != null
            if (!aHasStrong && !bHasStrong) {
                val hostA = a.host.trim().lowercase()
                val hostB = b.host.trim().lowercase()
                if (hostA.isNotEmpty() && hostA == hostB && a.port == b.port) {
                    return true
                }
                if (hostA.isEmpty() && hostB.isEmpty() &&
                    a.deviceId.trim().isNotEmpty() &&
                    a.deviceId.trim() == b.deviceId.trim()
                ) {
                    return true
                }
            }
            return false
        }

        internal fun mergeSavedDevices(primary: SavedDevice, duplicate: SavedDevice): SavedDevice {
            val preferredDeviceId = when {
                !isWeakSyntheticDeviceId(primary.deviceId) -> primary.deviceId.trim()
                !isWeakSyntheticDeviceId(duplicate.deviceId) -> duplicate.deviceId.trim()
                else -> primary.deviceId.trim().ifBlank { duplicate.deviceId.trim() }
            }
            val mergedSnowId = primary.snowId?.trim()?.uppercase()?.takeIf { it.isNotEmpty() }
                ?: duplicate.snowId?.trim()?.uppercase()?.takeIf { it.isNotEmpty() }
            val mergedFp = primary.certFingerprint?.trim()?.takeIf { it.isNotEmpty() }
                ?: duplicate.certFingerprint?.trim()?.takeIf { it.isNotEmpty() }
            val primaryHost = primary.host.trim()
            val dupHost = duplicate.host.trim()
            val mergedHost = when {
                primaryHost.isNotEmpty() && primaryHost != "127.0.0.1" -> primaryHost
                dupHost.isNotEmpty() && dupHost != "127.0.0.1" -> dupHost
                else -> primaryHost.ifEmpty { dupHost }
            }
            val mergedPort = if (primary.port in 1..65535) primary.port else duplicate.port
            val mergedName = primary.deviceName.trim().takeIf {
                it.isNotEmpty() && !it.equals("Desktop Core", ignoreCase = true)
            } ?: duplicate.deviceName.trim().ifEmpty { primary.deviceName }

            val combinedEps = mutableListOf<DeviceEndpoint>()
            for (ep in primary.recentEndpoints + duplicate.recentEndpoints) {
                val h = ep.host.trim()
                if (h.isEmpty()) continue
                val existingEpIdx = combinedEps.indexOfFirst { it.host == h && it.port == ep.port }
                if (existingEpIdx >= 0) {
                    val prev = combinedEps[existingEpIdx]
                    if (ep.lastSuccessTimestamp > prev.lastSuccessTimestamp) {
                        combinedEps[existingEpIdx] = ep
                    }
                } else {
                    combinedEps.add(DeviceEndpoint(h, ep.port, ep.lastSuccessTimestamp))
                }
            }
            val pProfile = normalizeAccessProfile(primary.permissionProfile)
            val dProfile = normalizeAccessProfile(duplicate.permissionProfile)
            val mergedProfile = if (pProfile != "not_allowed") pProfile else dProfile

            return primary.copy(
                deviceId = preferredDeviceId,
                deviceName = mergedName,
                host = mergedHost,
                port = mergedPort,
                lastSeen = primary.lastSeen?.takeIf { it.isNotBlank() } ?: duplicate.lastSeen,
                trustTier = normalizeTrustTier(primary.trustTier),
                certFingerprint = mergedFp,
                recentEndpoints = combinedEps.take(5),
                connectionMode = primary.connectionMode.ifBlank { duplicate.connectionMode },
                snowId = mergedSnowId,
                deviceType = primary.deviceType.ifBlank { duplicate.deviceType },
                permissionProfile = mergedProfile
            )
        }

        fun deduplicateSavedDevices(devices: List<SavedDevice>): List<SavedDevice> {
            val result = mutableListOf<SavedDevice>()
            for (raw in devices) {
                val (normTier, normProfile) = resolveSeparatedTrustAndProfile(
                    raw.trustTier,
                    raw.permissionProfile
                )
                val clean = raw.copy(
                    trustTier = normTier,
                    permissionProfile = normProfile
                )
                val matchIdx = result.indexOfFirst { canMergeSavedDevices(it, clean) }
                if (matchIdx >= 0) {
                    result[matchIdx] = mergeSavedDevices(result[matchIdx], clean)
                } else {
                    result.add(clean)
                }
            }
            return result
        }

        fun resolveUiConnectionState(transport: ConnectionState, auth: AuthState): ConnectionState {
            return when {
                transport == ConnectionState.CONNECTED && auth is AuthState.Authenticated -> ConnectionState.CONNECTED
                transport == ConnectionState.CONNECTED && (
                    auth is AuthState.ConnectedUnauthenticated || auth is AuthState.Connecting
                ) -> ConnectionState.CONNECTING
                transport == ConnectionState.CONNECTED -> ConnectionState.DISCONNECTED
                auth is AuthState.AuthFailed ||
                    auth is AuthState.FingerprintConfirmationRequired ||
                    auth is AuthState.FingerprintMismatch -> ConnectionState.DISCONNECTED
                else -> transport
            }
        }

        fun isSessionTrulyConnected(transport: ConnectionState, auth: AuthState): Boolean {
            return transport == ConnectionState.CONNECTED && auth is AuthState.Authenticated
        }

        fun parseSemverTuple(raw: String): Triple<Int, Int, Int>? {
            val cleaned = raw.trim().removePrefix("v").removePrefix("V")
            val m = Regex("^(\\d+)\\.(\\d+)\\.(\\d+)$").matchEntire(cleaned) ?: return null
            val major = m.groupValues[1].toIntOrNull() ?: return null
            val minor = m.groupValues[2].toIntOrNull() ?: return null
            val patch = m.groupValues[3].toIntOrNull() ?: return null
            return Triple(major, minor, patch)
        }

        fun compareSemver(a: Triple<Int, Int, Int>, b: Triple<Int, Int, Int>): Int {
            if (a.first != b.first) return a.first.compareTo(b.first)
            if (a.second != b.second) return a.second.compareTo(b.second)
            return a.third.compareTo(b.third)
        }

        fun isUpdateStrictlyNewer(
            remoteInfo: FileTransferClient.AppUpdateInfo?,
            installedVersionCode: Int,
            installedVersionName: String
        ): Boolean {
            if (remoteInfo == null || !remoteInfo.available) return false
            if (remoteInfo.versionCode <= 0 || remoteInfo.versionCode <= installedVersionCode) return false
            if (remoteInfo.sizeBytes <= 0L) return false
            val sha = remoteInfo.sha256.trim()
            if (sha.length != 64 || !sha.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return false
            val remoteVer = parseSemverTuple(remoteInfo.versionName) ?: return false
            val localVer = parseSemverTuple(installedVersionName)
            if (localVer != null && compareSemver(remoteVer, localVer) < 0) return false
            return true
        }

        @Volatile
        private var instance: SnowUiRepository? = null

        fun getInstance(context: Context): SnowUiRepository {
            return instance ?: synchronized(this) {
                instance ?: SnowUiRepository(context.applicationContext).also { instance = it }
            }
        }

        fun deriveCanonicalSnowId(seed: String): String {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(seed.toByteArray(Charsets.UTF_8))
            val hex = hash.joinToString("") { "%02X".format(it) }
            return "SNW-${hex.substring(0, 4)}-${hex.substring(4, 8)}"
        }

        const val DEFAULT_BUILTIN_HUB_URL = "https://snow-relay.onrender.com"

        /**
         * Validate a SNOW Hub HTTPS URL (or loopback HTTP under explicit dev mode).
         * Rejects embedded credentials, query strings, fragments, and unexpected paths.
         */
        fun validateHubUrl(raw: String, allowDevLoopback: Boolean = false): String {
            val clean = raw.trim()
            if (clean.isEmpty()) throw IllegalArgumentException("Hub URL cannot be empty.")
            if (clean.any { it.isWhitespace() || it.code < 32 }) {
                throw IllegalArgumentException("Hub URL contains invalid whitespace or control characters.")
            }
            val uri = java.net.URI(clean)
            val scheme = (uri.scheme ?: "").lowercase()
            if (uri.rawUserInfo != null || uri.rawAuthority?.contains("@") == true) {
                throw IllegalArgumentException("Hub URL must not contain embedded credentials.")
            }
            if (!uri.rawQuery.isNullOrEmpty() || !uri.rawFragment.isNullOrEmpty()) {
                throw IllegalArgumentException("Hub URL must not contain query parameters or fragments.")
            }
            val path = uri.path ?: ""
            if (path.isNotEmpty() && path != "/" && path != "/v1/tunnel") {
                throw IllegalArgumentException("Hub URL must be a root origin without unexpected paths.")
            }
            val host = (uri.host ?: "").trim().lowercase()
            val authority = uri.rawAuthority ?: ""
            if (host.isEmpty() || authority.isEmpty()) {
                throw IllegalArgumentException("Hub URL missing valid hostname.")
            }
            val isLoopback = host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]"
            when {
                scheme == "https" -> {}
                scheme == "http" && allowDevLoopback && isLoopback -> {}
                else -> throw IllegalArgumentException("Hub URL must use https://")
            }
            val portSuffix = if (uri.port != -1) ":${uri.port}" else ""
            val hostBracketed = if (host.contains(":") && !host.startsWith("[")) "[$host]" else host
            return "$scheme://$hostBracketed$portSuffix"
        }

        fun normalizeRelayUrl(raw: String): String {
            var s = raw.trim()
            if (s.isEmpty()) return ""
            if (s.startsWith("http://", ignoreCase = true)) {
                s = "ws://" + s.substring("http://".length)
            } else if (s.startsWith("https://", ignoreCase = true)) {
                s = "wss://" + s.substring("https://".length)
            } else if (!s.startsWith("ws://", ignoreCase = true) && !s.startsWith("wss://", ignoreCase = true)) {
                s = "wss://$s"
            }

            return try {
                val uri = java.net.URI(s)
                val scheme = uri.scheme ?: if (s.startsWith("ws://", ignoreCase = true)) "ws" else "wss"
                val host = uri.host ?: s.substringAfter("://").substringBefore("/").substringBefore(":")
                val port = uri.port
                val path = uri.path
                val hostPort = if (port != -1) "$host:$port" else host
                val cleanPath = if (path.isNullOrBlank() || path == "/") "/v1/tunnel" else path
                "$scheme://$hostPort$cleanPath"
            } catch (_: Exception) {
                val scheme = if (s.startsWith("ws://", ignoreCase = true)) "ws" else "wss"
                val body = s.substringAfter("://")
                val hostPort = body.substringBefore("/")
                val path = body.substringAfter("/", "")
                val cleanPath = if (path.isBlank()) "/v1/tunnel" else "/$path"
                "$scheme://$hostPort$cleanPath"
            }
        }
    }

    private val repoScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var serviceRef: SnowForegroundService? = null
    internal var clientForTest: SnowWebSocketClient? = null

    internal fun activeClient(): SnowWebSocketClient? = serviceRef?.client ?: clientForTest

    internal fun attachClientForTest(client: SnowWebSocketClient) {
        clientForTest = client
        observeClientFlows(client)
    }
    val screenshotObserver: ScreenshotObserver by lazy { ScreenshotObserver(appContext) }

    // Persistent storage helpers
    val identity: DeviceIdentity by lazy { DeviceIdentity.getOrCreate(appContext) }
    val canonicalSnowId: String
        get() {
            val livePerm = _permanentDeviceSnowId.value.trim().uppercase()
            if (org.snow.security.DeviceKeyIdentity.SNOW_ID_REGEX.matches(livePerm)) {
                return livePerm
            }
            return try {
                val dk = deviceKeyManager.getOrCreate()
                _permanentDeviceSnowId.value = dk.snowId
                dk.snowId
            } catch (_: Throwable) {
                deriveCanonicalSnowId(identity.deviceId)
            }
        }
    internal var deviceKeyProviderOverrideForTest: org.snow.security.SecretKeyProvider? = null
    val deviceKeyManager: org.snow.security.DeviceKeyManager by lazy {
        val kp = deviceKeyProviderOverrideForTest
            ?: org.snow.security.AndroidKeyStoreKeyProvider(org.snow.security.DeviceKeyManager.DEFAULT_KEYSTORE_ALIAS)
        org.snow.security.DeviceKeyManager(appContext, keyProvider = kp)
    }
    private val _permanentDeviceSnowId = MutableStateFlow("")
    val permanentDeviceSnowId: StateFlow<String> = _permanentDeviceSnowId.asStateFlow()
    private val _permanentDeviceMcpUrl = MutableStateFlow("")
    val permanentDeviceMcpUrl: StateFlow<String> = _permanentDeviceMcpUrl.asStateFlow()
    private val _identityError = MutableStateFlow<String?>(null)
    val identityError: StateFlow<String?> = _identityError.asStateFlow()

    private val _androidRemoteMcpEnabled = MutableStateFlow(
        appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
            .getBoolean(org.snow.mcp.AndroidRemoteMcpController.PREF_KEY_ANDROID_REMOTE_MCP_ENABLED, true)
    )
    val androidRemoteMcpEnabled: StateFlow<Boolean> = _androidRemoteMcpEnabled.asStateFlow()

    private val _androidMcpTunnelState = MutableStateFlow(
        org.snow.mcp.RelayMcpForwarderState(enabled = _androidRemoteMcpEnabled.value, connected = false)
    )
    val androidMcpTunnelState: StateFlow<org.snow.mcp.RelayMcpForwarderState> = _androidMcpTunnelState.asStateFlow()

    private val _authorizedOAuthClients = MutableStateFlow<List<org.snow.mcp.AuthorizedOAuthClientSummary>>(emptyList())
    val authorizedOAuthClients: StateFlow<List<org.snow.mcp.AuthorizedOAuthClientSummary>> = _authorizedOAuthClients.asStateFlow()

    @Volatile
    private var lastCorePendingApprovals: List<PendingApprovalItem> = emptyList()
    private var androidMcpSyncJob: kotlinx.coroutines.Job? = null
    val tokenStorage: SharedPreferencesTokenStorage by lazy { SharedPreferencesTokenStorage(appContext) }
    val certPinStorage: EncryptedCertPinStorage by lazy { EncryptedCertPinStorage(appContext) }
    internal var tokenStorageOverrideForTest: org.snow.security.TokenStorage? = null
    internal var certPinStorageOverrideForTest: org.snow.security.CertPinStorage? = null
    internal var peerHostCertStorageOverrideForTest: org.snow.security.PeerHostCertStorage? = null

    internal val activeTokenStorage: org.snow.security.TokenStorage
        get() = tokenStorageOverrideForTest ?: tokenStorage
    internal val activeCertPinStorage: org.snow.security.CertPinStorage
        get() = certPinStorageOverrideForTest ?: certPinStorage
    internal val activePeerHostCertStorage: org.snow.security.PeerHostCertStorage
        get() = peerHostCertStorageOverrideForTest ?: org.snow.security.EncryptedFilePeerHostCertStorage(appContext)

    val safFolderManager: SafFolderManager by lazy { SafFolderManager(appContext) }
    val pairingFlow: PairingFlow by lazy { PairingFlow(identity, activeTokenStorage) }

    // --- StateFlows ---

    private val _connectionState = MutableStateFlow(ConnectionState.DISCONNECTED)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _uiConnectionState = MutableStateFlow(ConnectionState.DISCONNECTED)
    val uiConnectionState: StateFlow<ConnectionState> = _uiConnectionState.asStateFlow()

    private val _connectedEndpoint = MutableStateFlow<String?>(null)
    val connectedEndpoint: StateFlow<String?> = _connectedEndpoint.asStateFlow()
    val currentTargetHost: String get() = connectedHost.ifBlank { serviceRef?.client?.currentTargetHost ?: "" }

    private val _authState = MutableStateFlow<AuthState>(AuthState.Disconnected)
    val authState: StateFlow<AuthState> = _authState.asStateFlow()

    private val _revocationNotice = MutableStateFlow<String?>(null)
    val revocationNotice: StateFlow<String?> = _revocationNotice.asStateFlow()

    fun clearRevocationNotice() {
        _revocationNotice.value = null
    }

    val pairingState: StateFlow<PairingState> get() = pairingFlow.state

    private val _discoveredPeers = MutableStateFlow<List<DiscoveredPeer>>(emptyList())
    val discoveredPeers: StateFlow<List<DiscoveredPeer>> = _discoveredPeers.asStateFlow()

    private val _savedDevices = MutableStateFlow<List<SavedDevice>>(emptyList())
    val savedDevices: StateFlow<List<SavedDevice>> = _savedDevices.asStateFlow()

    private val localTransportOrchestrator = org.snow.network.TransportOrchestrator()
    private val _transportSnapshots = MutableStateFlow<Map<String, org.snow.network.DeviceTransportSnapshot>>(emptyMap())
    val transportSnapshots: StateFlow<Map<String, org.snow.network.DeviceTransportSnapshot>> = _transportSnapshots.asStateFlow()
    private val _lastTransportError = MutableStateFlow<String?>(null)
    val lastTransportError: StateFlow<String?> = _lastTransportError.asStateFlow()

    @Volatile
    internal var relayActivationVerifierForTest: (suspend (endpoint: String, deviceId: String) -> Pair<Boolean, String>)? = null

    fun activeTransportOrchestrator(): org.snow.network.TransportOrchestrator =
        serviceRef?.transportOrchestrator ?: localTransportOrchestrator

    fun resolveTransferFallbackTarget(
        failedHost: String,
        failedRoute: org.snow.network.TransportRoute,
        targetDeviceId: String? = null
    ): Pair<String, Int>? {
        val svc = serviceRef
        if (svc != null) {
            return svc.buildTransferFallbackTargets(failedHost, failedRoute, targetDeviceId)
        }
        val peerId = targetDeviceId?.trim()?.takeIf { it.isNotBlank() } ?: failedHost
        val orch = activeTransportOrchestrator()
        orch.selectTransferFallbackTarget(peerId, failedHost, failedRoute)?.let { return it }
        val mode = orch.getMode(peerId)
        if (mode.isSingleRouteOverride() && mode.targetRouteOrNull() == failedRoute) {
            return null
        }
        val dev = _savedDevices.value.firstOrNull { it.deviceId.equals(peerId, ignoreCase = true) } ?: return null
        val fallbackPort = dev.transferPort.takeIf { it in 1..65535 } ?: 8766
        val altHost = (listOf(dev.host) + dev.recentEndpoints.map { it.host })
            .map { it.trim() }
            .firstOrNull { h ->
                h.isNotBlank() &&
                    !h.equals(failedHost.trim(), ignoreCase = true) &&
                    !h.equals("relay", ignoreCase = true) &&
                    (failedRoute != org.snow.network.TransportRoute.USB || !org.snow.network.TransportClassifier.isLoopbackHost(h))
            }
        return altHost?.let { it to fallbackPort }
    }

    internal fun createConfiguredTransferClient(
        targetDeviceIdProviderOverride: (() -> String?)? = null
    ): FileTransferClient {
        val clientRef = serviceRef?.client
        val devIdProvider: () -> String? = targetDeviceIdProviderOverride ?: {
            val c = serviceRef?.client
            c?.activeTargetDeviceId()
                ?: (_authState.value as? AuthState.Authenticated)?.peerDeviceId?.trim()?.takeIf { it.isNotBlank() }
        }
        return FileTransferClient(
            context = appContext,
            deviceId = identity.deviceId,
            certPinStorage = activeCertPinStorage,
            tokenStorage = activeTokenStorage,
            useTls = true,
            targetDeviceIdProvider = devIdProvider
        ).apply {
            transportOrchestrator = activeTransportOrchestrator()
            usbMappingVerifiedProvider = {
                val c = clientRef ?: serviceRef?.client
                c != null &&
                    org.snow.network.TransportClassifier.isLoopbackHost(c.currentTargetHost) &&
                    c.connectionState.value == ConnectionState.CONNECTED
            }
            fallbackTargetProvider = { failedHost, failedRoute ->
                resolveTransferFallbackTarget(failedHost, failedRoute, devIdProvider.invoke())
            }
        }
    }

    internal fun resolveOrCreateTransferClient(requireConnectedAuth: Boolean = true): FileTransferClient? {
        _fileTransferClient?.let { return it }
        serviceRef?.transferClient?.let { return it }
        if (requireConnectedAuth && !(_authState.value is AuthState.Authenticated && _connectionState.value == ConnectionState.CONNECTED)) {
            return null
        }
        return createConfiguredTransferClient().also { _fileTransferClient = it }
    }

    private val _activeTransfer = MutableStateFlow<ActiveTransferInfo?>(null)
    val activeTransfer: StateFlow<ActiveTransferInfo?> = _activeTransfer.asStateFlow()

    private val _pendingApprovals = MutableStateFlow<List<PendingApprovalItem>>(emptyList())
    val pendingApprovals: StateFlow<List<PendingApprovalItem>> = _pendingApprovals.asStateFlow()

    private val _pendingApprovalsCount = MutableStateFlow(0)
    val pendingApprovalsCount: StateFlow<Int> = _pendingApprovalsCount.asStateFlow()

    private val _pendingNetworkDecision = MutableStateFlow<PendingNetworkDecision?>(null)
    val pendingNetworkDecision: StateFlow<PendingNetworkDecision?> = _pendingNetworkDecision.asStateFlow()

    private val approvalsFetchInFlight = java.util.concurrent.atomic.AtomicBoolean(false)
    private val approvalsPendingQueued = java.util.concurrent.atomic.AtomicBoolean(false)
    private val approvalsEpoch = java.util.concurrent.atomic.AtomicLong(0L)

    private val _phoneTelemetry = MutableStateFlow(PhoneTelemetry.UNAVAILABLE)
    val phoneTelemetry: StateFlow<PhoneTelemetry> = _phoneTelemetry.asStateFlow()

    private val _pcTelemetry = MutableStateFlow(PcTelemetry.UNAVAILABLE)
    val pcTelemetry: StateFlow<PcTelemetry> = _pcTelemetry.asStateFlow()

    private val _terminalState = MutableStateFlow(TerminalExecutionState())
    val terminalState: StateFlow<TerminalExecutionState> = _terminalState.asStateFlow()

    private val _logs = MutableStateFlow<List<UiLogEntry>>(emptyList())
    val logs: StateFlow<List<UiLogEntry>> = _logs.asStateFlow()

    // Phase 26A & Stage 6C Live Screen Sharing state (outbound & multi-sender incoming viewer)
    data class IncomingScreenStream(
        val senderId: String,
        val senderName: String,
        val senderPlatform: String,
        val sessionId: String,
        val frameSeq: Long,
        val width: Int,
        val height: Int,
        val fps: Float,
        val routeBadge: String,
        val timestampMs: Long,
        val frameBytes: ByteArray
    )

    data class ScreenShareTarget(
        val deviceId: String,
        val deviceName: String,
        val platform: String,
        val routeBadge: String
    )

    private val _screenShareState = MutableStateFlow(LiveScreenStreamHandler.StreamState.IDLE)
    val screenShareState: StateFlow<LiveScreenStreamHandler.StreamState> = _screenShareState.asStateFlow()

    private val _incomingScreenStreams = MutableStateFlow<Map<String, IncomingScreenStream>>(emptyMap())
    val incomingScreenStreams: StateFlow<Map<String, IncomingScreenStream>> = _incomingScreenStreams.asStateFlow()

    private val _selectedIncomingSenderId = MutableStateFlow<String?>(null)
    val selectedIncomingSenderId: StateFlow<String?> = _selectedIncomingSenderId.asStateFlow()

    private val _pendingScreenShareTargets = MutableStateFlow<List<String>>(emptyList())
    val pendingScreenShareTargets: StateFlow<List<String>> = _pendingScreenShareTargets.asStateFlow()

    private var incomingStreamPollJob: Job? = null

    // Phase 26A Camera Delivery State Machine
    enum class CameraDeliveryStatus {
        IDLE,
        CAPTURING,
        UPLOADING,
        DELIVERED,
        FAILED
    }

    data class CameraDeliveryInfo(
        val status: CameraDeliveryStatus = CameraDeliveryStatus.IDLE,
        val fileName: String? = null,
        val error: String? = null
    )

    private val _cameraDelivery = MutableStateFlow(CameraDeliveryInfo())
    val cameraDelivery: StateFlow<CameraDeliveryInfo> = _cameraDelivery.asStateFlow()

    // Phase 26B / V7 Shared Clipboard Buffer DTO & State
    data class ClipboardFileEntryDto(
        val index: Int = 0,
        val name: String,
        val sizeBytes: Long,
        val mimeType: String,
        val sha256: String,
        val transferId: String? = null,
        val transferPort: Int = 8766
    )

    data class ClipboardItemDto(
        val itemId: String,
        val type: String,
        val sourceDevice: String,
        val previewText: String,
        val sizeBytes: Long,
        val timestamp: Double,
        val isPinned: Boolean,
        val eventId: String = "",
        val seq: Long = 0L,
        val originDeviceId: String = "",
        val sha256: String = "",
        val mimeType: String = "",
        val fileManifest: List<ClipboardFileEntryDto> = emptyList()
    )

    private val _clipboardBufferItems = MutableStateFlow<List<ClipboardItemDto>>(emptyList())
    val clipboardBufferItems: StateFlow<List<ClipboardItemDto>> = _clipboardBufferItems.asStateFlow()

    // Desktop Wallpaper Preview StateFlow
    private val _desktopWallpaper = MutableStateFlow<android.graphics.Bitmap?>(null)
    val desktopWallpaper: StateFlow<android.graphics.Bitmap?> = _desktopWallpaper.asStateFlow()

    // Phase 27 Direct Phone-to-Phone Peer Host state
    private val _peerHostState = MutableStateFlow(org.snow.network.PeerHostState())
    val peerHostState: StateFlow<org.snow.network.PeerHostState> = _peerHostState.asStateFlow()
    private val _adoptedNetworkId = MutableStateFlow(
        appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
            .getString(PREF_KEY_ADOPTED_NETWORK_ID, null)
            ?.trim()?.uppercase()?.takeIf { it.isNotBlank() }
    )
    val adoptedNetworkId: StateFlow<String?> = _adoptedNetworkId.asStateFlow()
    private val _permissionProfileState = MutableStateFlow("full_control")
    val permissionProfileState: StateFlow<String> = _permissionProfileState.asStateFlow()
    private var peerHostJob: Job? = null
    private var snowIdResolveJob: Job? = null

    fun adoptNetworkId(networkId: String?) {
        val clean = networkId?.trim()?.uppercase()?.takeIf {
            it.matches(Regex("^SNW-NET-[A-Z0-9]{8}$"))
        } ?: return
        appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
            .edit().putString(PREF_KEY_ADOPTED_NETWORK_ID, clean).apply()
        _adoptedNetworkId.value = clean
        serviceRef?.peerHostManager?.setConfiguredNetworkId(clean)
    }

    fun getEffectiveNetworkId(): String? = _adoptedNetworkId.value

    internal fun applyNonConflictingNetworkAdoption(networkId: String?) {
        val clean = networkId?.trim()?.uppercase()?.takeIf {
            it.matches(Regex("^SNW-NET-[A-Z0-9]{8}$"))
        } ?: return
        val current = _adoptedNetworkId.value
        if (current == null || current.equals(clean, ignoreCase = true)) {
            adoptNetworkId(clean)
        }
    }

    fun applyHostNegotiatedNetworkId(networkId: String?) {
        val clean = networkId?.trim()?.uppercase()?.takeIf {
            it.matches(Regex("^SNW-NET-[A-Z0-9]{8}$"))
        }
        if (clean == null) {
            appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
                .edit().remove(PREF_KEY_ADOPTED_NETWORK_ID).apply()
            _adoptedNetworkId.value = null
            serviceRef?.peerHostManager?.setConfiguredNetworkId(null)
            return
        }
        adoptNetworkId(clean)
    }

    fun clearNetworkMembershipIfEmpty() {
        if (_savedDevices.value.none { it.relationship.equals("member", ignoreCase = true) }) {
            appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
                .edit().remove(PREF_KEY_ADOPTED_NETWORK_ID).apply()
            _adoptedNetworkId.value = null
            serviceRef?.peerHostManager?.setConfiguredNetworkId(null)
        }
    }

    internal fun applyNegotiatedNetworkOutcome(state: PairingState.Paired, fallbackNetworkId: String? = null) {
        val cleanRel = state.relationship.trim().lowercase().ifBlank { "member" }
        val conflict = state.networkConflict ||
            state.networkAction == "DECISION_REQUIRED" ||
            state.networkAction == "MERGE_APPROVAL_REQUIRED"
        if (cleanRel == "external_network" || conflict) {
            val remoteNet = state.hostNetworkId ?: state.peerNetworkId ?: fallbackNetworkId
            val localNet = _adoptedNetworkId.value ?: state.clientNetworkId
            if (conflict && !state.mergeTxId.isNullOrBlank() && !localNet.isNullOrBlank() && !remoteNet.isNullOrBlank()) {
                _pendingNetworkDecision.value = PendingNetworkDecision(
                    txId = state.mergeTxId,
                    peerDeviceId = state.desktopId,
                    peerDeviceName = state.desktopName,
                    localNetworkId = localNet,
                    remoteNetworkId = remoteNet,
                    networkAction = state.networkAction ?: "DECISION_REQUIRED",
                    localApproved = state.networkAction == "MERGE_APPROVAL_REQUIRED"
                )
            }
            return
        }
        val negotiatedNet = (state.peerNetworkId ?: fallbackNetworkId)?.trim()?.uppercase()
        if (!negotiatedNet.isNullOrBlank()) {
            adoptNetworkId(negotiatedNet)
        }
    }

    fun resolvePendingNetworkDecision(
        merge: Boolean,
        onComplete: ((Boolean, String?) -> Unit)? = null
    ) {
        val pending = _pendingNetworkDecision.value
        if (pending == null) {
            onComplete?.invoke(false, "No pending network merge decision.")
            return
        }
        val client = activeClient()
        if (client == null || client.connectionState.value != ConnectionState.CONNECTED) {
            onComplete?.invoke(false, "Not connected to peer host.")
            return
        }
        val decision = if (merge) "merge" else "keep_separate"
        pairingFlow.sendNetworkMergeDecision(pending.txId, decision, client) { ok, data, err ->
            if (!ok) {
                onComplete?.invoke(false, err ?: "Failed updating network decision.")
                return@sendNetworkMergeDecision
            }
            val action = (data?.get("network_action") as? String)?.trim()?.uppercase()
            val committed = (data?.get("committed") as? Boolean) == true || action == "MERGED"
            val resultNetId = (data?.get("network_id") as? String)?.trim()?.uppercase()
            if (!merge || action == "KEEP_SEPARATE") {
                _pendingNetworkDecision.value = null
                onComplete?.invoke(true, "Kept networks separate.")
            } else if (committed && !resultNetId.isNullOrBlank()) {
                adoptNetworkId(resultNetId)
                val updatedList = _savedDevices.value.map { dev ->
                    if (dev.deviceId.equals(pending.peerDeviceId, ignoreCase = true) ||
                        dev.networkId.equals(pending.remoteNetworkId, ignoreCase = true)
                    ) {
                        dev.copy(relationship = "member", networkId = resultNetId)
                    } else {
                        dev
                    }
                }
                _savedDevices.value = updatedList
                appContext.getSharedPreferences("snow_paired_devices_v2", Context.MODE_PRIVATE)
                    .edit().putString("devices_json", serializeSavedDevices(updatedList)).apply()
                _pendingNetworkDecision.value = null
                onComplete?.invoke(true, "Networks merged into $resultNetId.")
            } else {
                _pendingNetworkDecision.value = pending.copy(
                    networkAction = action ?: "MERGE_APPROVAL_REQUIRED",
                    localApproved = true
                )
                onComplete?.invoke(true, "Merge approval recorded; waiting for peer owner approval.")
            }
        }
    }

    fun getPermanentDeviceKeyIdentity(): org.snow.security.DeviceKeyIdentity =
        deviceKeyManager.getOrCreate()

    fun refreshPermanentIdentityState() {
        try {
            val dk = deviceKeyManager.getOrCreate()
            _permanentDeviceSnowId.value = dk.snowId
            val hubBase = getDefaultHubUrl(allowDevLoopback = false).trimEnd('/')
            _permanentDeviceMcpUrl.value = org.snow.security.DeviceKeyManager.formatPermanentMcpUrl(hubBase, dk.snowId)
            _identityError.value = null
        } catch (e: org.snow.security.DeviceKeyCorruptException) {
            _identityError.value = e.message ?: "Device cryptographic identity is corrupted; explicit recovery required."
        } catch (e: Throwable) {
            _identityError.value = e.message ?: "Unable to initialize permanent device identity."
        }
    }

    fun getPermanentDeviceMcpUrl(): String {
        val cached = _permanentDeviceMcpUrl.value
        if (cached.isNotBlank()) return cached
        return try {
            val dk = deviceKeyManager.getOrCreate()
            val url = org.snow.security.DeviceKeyManager.formatPermanentMcpUrl(getDefaultHubUrl(allowDevLoopback = false), dk.snowId)
            _permanentDeviceSnowId.value = dk.snowId
            _permanentDeviceMcpUrl.value = url
            url
        } catch (_: Throwable) {
            ""
        }
    }

    fun exportDeviceRecoveryKeyWithConsent(confirmed: Boolean): Pair<Boolean, String> {
        if (!confirmed) {
            return false to "Explicit owner confirmation is required to reveal your device recovery key."
        }
        return try {
            val dk = deviceKeyManager.getOrCreate()
            val keyStr = org.snow.security.DeviceKeyManager.exportRecoveryKey(dk)
            appendLog("INFO", TAG, "Owner exported device recovery key reference for [${dk.snowId}]")
            true to keyStr
        } catch (e: Exception) {
            false to (e.message ?: "Unable to export device recovery key.")
        }
    }

    fun exportEncryptedIdentityBackupToSaf(uri: android.net.Uri, passphrase: String): Pair<Boolean, String> {
        return try {
            val dk = deviceKeyManager.getOrCreate()
            val jsonPayload = org.snow.security.DeviceKeyManager.exportEncryptedBackup(dk, passphrase)
            val stream = appContext.contentResolver.openOutputStream(uri)
                ?: return false to "Could not open selected Transfer Folder for writing."
            stream.use { out ->
                out.write((jsonPayload + "\n").toByteArray(Charsets.UTF_8))
                out.flush()
            }
            appendLog("INFO", TAG, "Saved AES-GCM encrypted identity backup for [${dk.snowId}] to Transfer Folder")
            true to "Encrypted backup saved (${dk.snowId})."
        } catch (e: Exception) {
            false to (e.message ?: "Failed saving encrypted backup.")
        }
    }

    fun restoreDeviceIdentityFromRecovery(
        recoveryOrBackupInput: String,
        passphrase: String? = null,
        confirmReplace: Boolean = true
    ): Pair<Boolean, String> {
        if (!confirmReplace) {
            return false to "Explicit confirmation is required to restore identity and wipe prior trust."
        }
        return try {
            val trimmed = recoveryOrBackupInput.trim()
            var partialResetError: String? = null
            val restored = try {
                if (trimmed.startsWith("{")) {
                    deviceKeyManager.restoreFromEncryptedBackup(trimmed, passphrase.orEmpty())
                } else {
                    deviceKeyManager.restoreFromRecoveryKey(trimmed)
                }
            } catch (resetErr: org.snow.security.DeviceRecoveryTrustResetException) {
                partialResetError = resetErr.message ?: "Post-recovery trust cleanup failed."
                deviceKeyManager.getOrCreate()
            }
            // Disengage any active sessions & clear in-memory trust without re-pairing automatically
            disconnectAll()
            _savedDevices.value = emptyList()
            _adoptedNetworkId.value = null
            _pendingNetworkDecision.value = null
            _permanentDeviceSnowId.value = restored.snowId
            val url = org.snow.security.DeviceKeyManager.formatPermanentMcpUrl(
                getDefaultHubUrl(allowDevLoopback = false),
                restored.snowId
            )
            _permanentDeviceMcpUrl.value = url
            _identityError.value = null
            serviceRef?.androidRemoteMcpController?.onDeviceIdentityRecovered()
            if (partialResetError != null) {
                appendLog("ERROR", TAG, "Restored [${restored.snowId}], but trust reset reported errors: $partialResetError")
                false to partialResetError
            } else {
                appendLog("WARN", TAG, "Device identity restored as [${restored.snowId}]; prior peer trust & OAuth sessions wiped.")
                true to "Restored identity ${restored.snowId}. Re-pair peers and re-approve AI clients explicitly."
            }
        } catch (e: Exception) {
            false to (e.message ?: "Recovery failed.")
        }
    }

    fun getRemoteAiLinkDiagnostics(): Pair<String?, String> {
        val netId = _adoptedNetworkId.value?.trim()?.takeIf { it.isNotBlank() }
        if (netId != null) {
            val hubBase = getDefaultHubUrl().trimEnd('/')
            return "$hubBase/u/$netId/mcp" to "Linked PC network MCP endpoint (active when PC host is online)"
        }
        return if (isPeerHostEnabled() || isPeerHostActive()) {
            null to "Not linked to a PC host yet (Peer Host mode only)"
        } else {
            null to "Not linked to a PC host yet"
        }
    }

    // Bounded retries tracking
    private var connectionAttemptCount = 0
    private var activeDownloadJob: Job? = null
    private var clientConnectionJob: Job? = null
    private var clientAuthJob: Job? = null
    private var discoveryJob: Job? = null
    private var screenShareJob: Job? = null
    private var _fileTransferClient: FileTransferClient? = null
    private val _clipboardThumbnailVersion = MutableStateFlow(0)
    val clipboardThumbnailVersion: StateFlow<Int> = _clipboardThumbnailVersion.asStateFlow()
    private val inFlightThumbnails = java.util.Collections.synchronizedSet(mutableSetOf<String>())
    var connectedHost: String = ""
        private set

    init {
        pairingFlow.localNetworkIdProvider = { getEffectiveNetworkId() }
        loadSavedDevices()
        refreshPhoneTelemetry()
        refreshPermanentIdentityState()
        _permissionProfileState.value = activePermissionProfile
    }

    /**
     * Bind active background service instance to this repository.
     */
    fun bindService(service: SnowForegroundService) {
        serviceRef = service
        observeClientFlows(service.client)
        observeDiscoveryFlow(service.discoveryManager)
        androidMcpSyncJob?.cancel()
        androidMcpSyncJob = repoScope.launch {
            val ctrl = service.androidRemoteMcpController
            launch { ctrl.enabled.collect { _androidRemoteMcpEnabled.value = it } }
            launch { ctrl.tunnelState.collect { _androidMcpTunnelState.value = it } }
            launch { ctrl.authorizedClients.collect { _authorizedOAuthClients.value = it } }
        }
        syncMergedPendingApprovals()

        screenShareJob?.cancel()
        screenShareJob = repoScope.launch {
            service.liveScreenHandler.streamState.collectLatest { s ->
                _screenShareState.value = s
            }
        }

        peerHostJob?.cancel()
        peerHostJob = repoScope.launch {
            service.peerHostManager.hostState.collectLatest { s ->
                _peerHostState.value = s
            }
        }
    }

    fun unbindService() {
        clientConnectionJob?.cancel()
        clientConnectionJob = null
        clientAuthJob?.cancel()
        clientAuthJob = null
        discoveryJob?.cancel()
        discoveryJob = null
        screenShareJob?.cancel()
        screenShareJob = null
        peerHostJob?.cancel()
        peerHostJob = null
        closeIncomingViewer()
        _screenShareState.value = LiveScreenStreamHandler.StreamState.IDLE
        _peerHostState.value = org.snow.network.PeerHostState()
        serviceRef = null
    }

    private fun observeClientFlows(client: SnowWebSocketClient) {
        val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
        client.autoReconnectEnabled = prefs.getBoolean(PREF_KEY_AUTO_CONNECT_ENABLED, true)
        client.targetDeviceLookupByEndpoint = { h, p ->
            val clean = h.trim()
            if (clean == "127.0.0.1" || clean == "localhost" || clean == "::1") {
                null
            } else {
                _savedDevices.value.firstOrNull { dev ->
                    (dev.host == clean && dev.port == p) ||
                        dev.recentEndpoints.any { ep -> ep.host == clean && ep.port == p }
                }?.deviceId
            }
        }
        client.onDeviceRevoked = { reason ->
            onDeviceRevokedReceived(reason)
        }

        clientConnectionJob?.cancel()
        clientConnectionJob = repoScope.launch {
            client.connectionState.collectLatest { state ->
                _connectionState.value = state
                val currentAuth = client.authState.value
                _uiConnectionState.value = resolveUiConnectionState(state, currentAuth)
                if (state == ConnectionState.CONNECTED && currentAuth is AuthState.Authenticated) {
                    connectionAttemptCount = 0
                    if (client.currentTargetHost.isNotBlank()) {
                        connectedHost = client.currentTargetHost
                        _connectedEndpoint.value = "${client.currentTargetHost}:${client.currentTargetPort}"
                    }
                    queryPcStatus()
                } else if (state == ConnectionState.DISCONNECTED) {
                    _pcTelemetry.value = PcTelemetry.UNAVAILABLE
                    _fileTransferClient = null
                    _connectedEndpoint.value = null
                    connectedHost = ""
                    closeIncomingViewer()
                    invalidateWallpaperCache()
                }
            }
        }

        clientAuthJob?.cancel()
        clientAuthJob = repoScope.launch {
            client.authState.collectLatest { auth ->
                _authState.value = auth
                val currentConn = client.connectionState.value
                _uiConnectionState.value = resolveUiConnectionState(currentConn, auth)
                if (auth is AuthState.Authenticated && currentConn == ConnectionState.CONNECTED) {
                    connectionAttemptCount = 0
                    val host = client.currentTargetHost.takeIf { it.isNotBlank() } ?: connectedHost
                    val port = client.currentTargetPort
                    if (host.isNotBlank()) {
                        connectedHost = host
                        _connectedEndpoint.value = "$host:$port"
                    }
                    // Initialize dedicated FileTransferClient tied to this authenticated session
                    _fileTransferClient = createConfiguredTransferClient {
                        client.activeTargetDeviceId()
                            ?: auth.peerDeviceId?.trim()?.takeIf { it.isNotBlank() }
                    }
                    val existingDev = _savedDevices.value.find {
                        (!auth.peerDeviceId.isNullOrBlank() && it.deviceId.equals(auth.peerDeviceId, ignoreCase = true)) ||
                            (!auth.peerSnowId.isNullOrBlank() && it.snowId.equals(auth.peerSnowId, ignoreCase = true))
                    }
                    val existingRel = existingDev?.relationship?.trim()?.lowercase() ?: "member"
                    if (existingRel == "member") {
                        applyNonConflictingNetworkAdoption(auth.peerNetworkId)
                    }
                    // Auto-restore Instant Sync (enabled by default unless user explicitly disabled)
                    val sPrefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
                    if (sPrefs.getBoolean(PREF_KEY_INSTANT_SYNC, true)) {
                        toggleInstantClipboardSync(true)
                    }
                    if (sPrefs.getBoolean(PREF_KEY_AUTO_SYNC_SCREENSHOTS, false)) {
                        screenshotObserver.register()
                    }
                    queryPcStatus()
                    // Fetch latest shared clipboard buffer items and pending approvals immediately on auth
                    fetchClipboardBuffer()
                    refreshPendingApprovals(force = true)
                    // Update identity-first saved device history and endpoint ring buffer
                    recordSuccessfulConnection(
                        host = host,
                        port = port,
                        sessionId = auth.sessionId,
                        tier = auth.trustTier,
                        peerDeviceName = auth.peerDeviceName,
                        peerDeviceType = auth.peerDeviceType,
                        peerDeviceId = auth.peerDeviceId,
                        peerSnowId = auth.peerSnowId,
                        peerPermissionProfile = auth.permissionProfile,
                        peerNetworkId = auth.peerNetworkId,
                        peerRelationship = existingRel
                    )
                } else {
                    _fileTransferClient = null
                    _connectedEndpoint.value = null
                    if (auth !is AuthState.Connecting && auth !is AuthState.ConnectedUnauthenticated) {
                        _pcTelemetry.value = PcTelemetry.UNAVAILABLE
                        connectedHost = ""
                    }
                    screenshotObserver.unregister()
                    approvalsEpoch.incrementAndGet()
                    approvalsFetchInFlight.set(false)
                    approvalsPendingQueued.set(false)
                    _pendingApprovals.value = emptyList()
                    _pendingApprovalsCount.value = 0
                }
            }
        }
    }

    private fun observeDiscoveryFlow(discoveryManager: org.snow.network.DiscoveryManager) {
        discoveryJob?.cancel()
        discoveryJob = repoScope.launch {
            discoveryManager.peers.collectLatest { peersList ->
                _discoveredPeers.value = peersList
            }
        }
    }

    // --- Device Connection & Discovery Actions ---

    @Volatile
    internal var lastConnectRequestForTest: Triple<String, Int, String?>? = null
    internal val connectRequestsForTest = java.util.concurrent.CopyOnWriteArrayList<Triple<String, Int, String?>>()
    internal var connectLauncherForTest: ((String, Int, String?, org.snow.network.ConnectionHandshakeMode) -> Unit)? = null
    internal var allowLoopbackCandidateIpsForTest: Boolean = false
    internal var qrCandidateTimeoutMs: Long = 2500L

    @JvmOverloads
    fun connect(
        host: String,
        port: Int,
        targetDeviceId: String? = null,
        handshakeMode: org.snow.network.ConnectionHandshakeMode = org.snow.network.ConnectionHandshakeMode.STANDARD_OR_AUTO
    ) {
        val cleanHost = host.trim()
        if (cleanHost.isEmpty() || port !in 1..65535) {
            appendLog("ERROR", TAG, "Invalid host or port: $cleanHost:$port")
            return
        }

        val matchingDevice = _savedDevices.value.find {
            (targetDeviceId != null && it.deviceId == targetDeviceId) || (it.host == cleanHost && it.port == port)
        }
        val resolvedTargetId = targetDeviceId?.trim()?.takeIf { it.isNotBlank() } ?: matchingDevice?.deviceId
        if (matchingDevice?.connectionMode == "remote_only") {
            appendLog("WARNING", TAG, "Cannot connect locally: Policy for '${matchingDevice.deviceName}' is set to remote_only.")
            _connectionState.value = ConnectionState.DISCONNECTED
            return
        }

        val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
        prefs.edit().putString("last_connected_host", cleanHost).putInt("last_connected_port", port).apply()

        // Reset retry counter and manual-disconnect lock on explicit manual connection attempt
        SnowForegroundService.setDisconnectedByUser(appContext, false)
        serviceRef?.client?.autoReconnectEnabled = prefs.getBoolean(PREF_KEY_AUTO_CONNECT_ENABLED, true)
        connectionAttemptCount = 0
        connectedHost = cleanHost
        Triple(cleanHost, port, resolvedTargetId).also {
            lastConnectRequestForTest = it
            connectRequestsForTest.add(it)
        }
        _connectedEndpoint.value = null
        _connectionState.value = ConnectionState.CONNECTING
        _uiConnectionState.value = ConnectionState.CONNECTING
        appendLog("INFO", TAG, "Connecting to $cleanHost:$port...")

        val testLauncher = connectLauncherForTest
        if (testLauncher != null) {
            testLauncher.invoke(cleanHost, port, resolvedTargetId, handshakeMode)
            return
        }

        val intent = Intent(appContext, SnowForegroundService::class.java).apply {
            action = SnowForegroundService.ACTION_CONNECT
            putExtra(SnowForegroundService.EXTRA_HOST, cleanHost)
            putExtra(SnowForegroundService.EXTRA_PORT, port)
            if (!resolvedTargetId.isNullOrBlank()) {
                putExtra(SnowForegroundService.EXTRA_DEVICE_ID, resolvedTargetId)
            }
            putExtra(SnowForegroundService.EXTRA_HANDSHAKE_MODE, handshakeMode.name)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            appContext.startForegroundService(intent)
        } else {
            appContext.startService(intent)
        }
    }

    fun confirmAndPinCertificate(fingerprint: String) {
        connectionAttemptCount = 0
        serviceRef?.client?.confirmAndPinCertificate(fingerprint)
        appendLog("INFO", TAG, "Certificate confirmed and pinned by user: $fingerprint")
    }

    fun cancelConnection() {
        appendLog("INFO", TAG, "User cancelled connection attempt.")
        connectionAttemptCount = 0
        val intent = Intent(appContext, SnowForegroundService::class.java).apply {
            action = SnowForegroundService.ACTION_DISCONNECT
        }
        appContext.startService(intent)
        serviceRef?.client?.disconnect()
        _connectedEndpoint.value = null
        connectedHost = ""
        invalidateWallpaperCache()
        _connectionState.value = ConnectionState.DISCONNECTED
        _authState.value = AuthState.Disconnected
    }

    fun disconnect() {
        appendLog("INFO", TAG, "Disconnecting from desktop.")
        cancelActiveTransfer()
        SnowForegroundService.setDisconnectedByUser(appContext, true)
        serviceRef?.cancelAutoConnect()
        serviceRef?.client?.disconnect()
        val intent = Intent(appContext, SnowForegroundService::class.java).apply {
            action = SnowForegroundService.ACTION_DISCONNECT
        }
        try {
            appContext.startService(intent)
        } catch (_: Exception) {}
        approvalsEpoch.incrementAndGet()
        approvalsPendingQueued.set(false)
        _pendingApprovals.value = emptyList()
        _pendingApprovalsCount.value = 0
        _connectedEndpoint.value = null
        connectedHost = ""
        _pcTelemetry.value = PcTelemetry.UNAVAILABLE
        invalidateWallpaperCache()
        _authState.value = AuthState.Disconnected
        _connectionState.value = ConnectionState.DISCONNECTED
        _uiConnectionState.value = ConnectionState.DISCONNECTED
    }

    fun disconnectAll() {
        appendLog("INFO", TAG, "Disconnect All requested by user.")
        cancelActiveTransfer()
        SnowForegroundService.setDisconnectedByUser(appContext, true)
        serviceRef?.cancelAutoConnect()
        serviceRef?.stopRelay()
        stopPeerHost()
        serviceRef?.client?.disconnect()
        val intent = Intent(appContext, SnowForegroundService::class.java).apply {
            action = SnowForegroundService.ACTION_DISCONNECT
        }
        try {
            appContext.startService(intent)
        } catch (_: Exception) {}
        approvalsEpoch.incrementAndGet()
        approvalsPendingQueued.set(false)
        _pendingApprovals.value = emptyList()
        _pendingApprovalsCount.value = 0
        _connectedEndpoint.value = null
        connectedHost = ""
        _pcTelemetry.value = PcTelemetry.UNAVAILABLE
        invalidateWallpaperCache()
        _authState.value = AuthState.Disconnected
        _connectionState.value = ConnectionState.DISCONNECTED
        _uiConnectionState.value = ConnectionState.DISCONNECTED
    }

    fun setAutoReconnectEnabled(enabled: Boolean) {
        appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(PREF_KEY_AUTO_CONNECT_ENABLED, enabled)
            .apply()
        serviceRef?.client?.autoReconnectEnabled = enabled
        if (enabled) {
            SnowForegroundService.setDisconnectedByUser(appContext, false)
        } else {
            serviceRef?.cancelAutoConnect()
        }
    }

    fun onDeviceRevokedReceived(reason: String? = null) {
        appendLog("WARN", TAG, "Remote device revocation processed: ${reason ?: "revoked by host"}")
        tokenStorage.clearToken()
        SnowForegroundService.setDisconnectedByUser(appContext, true)
        serviceRef?.cancelAutoConnect()
        cancelActiveTransfer()
        val auth = _authState.value as? AuthState.Authenticated
        val currentHostSnapshot = connectedHost.ifBlank { _connectedEndpoint.value?.substringBeforeLast(":") ?: "" }
        val updated = _savedDevices.value.filterNot { dev ->
            (auth?.peerSnowId != null && dev.snowId == auth.peerSnowId) ||
                (auth?.peerDeviceId != null && dev.deviceId == auth.peerDeviceId) ||
                (currentHostSnapshot.isNotBlank() && dev.host == currentHostSnapshot)
        }
        _savedDevices.value = updated
        val prefsV2 = appContext.getSharedPreferences("snow_paired_devices_v2", Context.MODE_PRIVATE)
        prefsV2.edit().putString("devices_json", serializeSavedDevices(updated)).apply()

        _connectedEndpoint.value = null
        connectedHost = ""
        _pcTelemetry.value = PcTelemetry.UNAVAILABLE
        invalidateWallpaperCache()
        _authState.value = AuthState.Disconnected
        _connectionState.value = ConnectionState.DISCONNECTED
        _uiConnectionState.value = ConnectionState.DISCONNECTED
        _revocationNotice.value = reason?.takeIf { it.isNotBlank() } ?: "Device access revoked by PC host."
    }

    fun pairDeviceWithHandshakeToken(
        handshakeToken: String,
        networkId: String? = null,
        targetDeviceId: String? = null,
        onStateChanged: ((PairingState) -> Unit)? = null
    ) {
        val client = activeClient()
        if (client == null) {
            appendLog("WARN", TAG, "Cannot complete QR handshake pairing: WebSocket client not connected.")
            onStateChanged?.invoke(PairingState.Error("WebSocket client not connected."))
            return
        }
        val activeTarget = targetDeviceId?.trim()?.takeIf { it.isNotBlank() } ?: client.activeTargetDeviceId()
        appendLog("INFO", TAG, "Submitting single-use QR handshake token...")
        pairingFlow.submitHandshakeToken(handshakeToken, networkId, client, activeTarget) { state ->
            appendLog("INFO", TAG, "QR handshake pairing state changed: $state")
            if (state is PairingState.Paired) {
                applyNegotiatedNetworkOutcome(state, networkId)
                val effectiveNet = if (state.relationship == "external_network" || state.networkConflict) {
                    getEffectiveNetworkId()
                } else {
                    state.peerNetworkId ?: networkId
                }
                client.setAuthenticated(
                    sessionId = state.sessionId,
                    trustTier = state.trustTier,
                    peerDeviceName = state.desktopName,
                    peerDeviceType = state.deviceType,
                    peerDeviceId = state.desktopId,
                    peerSnowId = state.peerSnowId,
                    permissionProfile = state.permissionProfile,
                    peerNetworkId = effectiveNet
                )
                _authState.value = AuthState.Authenticated(
                    sessionId = state.sessionId,
                    trustTier = state.trustTier,
                    peerDeviceName = state.desktopName,
                    peerDeviceType = state.deviceType,
                    peerDeviceId = state.desktopId,
                    peerSnowId = state.peerSnowId,
                    permissionProfile = state.permissionProfile,
                    peerNetworkId = effectiveNet
                )
            }
            onStateChanged?.invoke(state)
        }
    }

    fun pairDevice(pin: String, onStateChanged: ((PairingState) -> Unit)? = null) {
        val client = activeClient()
        if (client == null) {
            appendLog("WARN", TAG, "Cannot pair: WebSocket client not connected.")
            onStateChanged?.invoke(PairingState.ConnectionLost("Cannot pair: WebSocket client not connected."))
            return
        }
        val cleanPin = pin.trim()
        if (!pairingFlow.validatePin(cleanPin)) {
            appendLog("WARN", TAG, "PIN must be exactly 6 numeric digits.")
            onStateChanged?.invoke(PairingState.Error("PIN must be exactly 6 numeric digits."))
            return
        }
        val activeTarget = client.activeTargetDeviceId()
        appendLog("INFO", TAG, "Submitting pairing request...")
        pairingFlow.submitPin(cleanPin, client, activeTarget) { state ->
            appendLog("INFO", TAG, "Pairing state changed: $state")
            if (state is PairingState.Paired) {
                applyNegotiatedNetworkOutcome(state)
                val effectiveNet = if (state.relationship == "external_network" || state.networkConflict) {
                    getEffectiveNetworkId()
                } else {
                    state.peerNetworkId
                }
                client.setAuthenticated(
                    sessionId = state.sessionId,
                    trustTier = state.trustTier,
                    peerDeviceName = state.desktopName,
                    peerDeviceType = state.deviceType,
                    peerDeviceId = state.desktopId,
                    peerSnowId = state.peerSnowId,
                    permissionProfile = state.permissionProfile,
                    peerNetworkId = effectiveNet
                )
                _authState.value = AuthState.Authenticated(
                    sessionId = state.sessionId,
                    trustTier = state.trustTier,
                    peerDeviceName = state.desktopName,
                    peerDeviceType = state.deviceType,
                    peerDeviceId = state.desktopId,
                    peerSnowId = state.peerSnowId,
                    permissionProfile = state.permissionProfile,
                    peerNetworkId = effectiveNet
                )
            }
            onStateChanged?.invoke(state)
        }
    }

    fun unpairDevice(targetDevice: SavedDevice? = null) {
        appendLog("INFO", TAG, "Unpairing device${targetDevice?.let { " [${it.deviceId}]" } ?: ""} and clearing auth token.")
        val client = serviceRef?.client
        val devId = identity.deviceId
        val activeAuth = _authState.value as? AuthState.Authenticated
        val currentToken = targetDevice?.let {
            tokenStorage.getTokenForDevice(it.deviceId)
                ?: it.snowId?.let { sid -> tokenStorage.getTokenForDevice(sid) }
                ?: if (tokenStorage.listStoredDeviceIds().isEmpty()) tokenStorage.getToken() else null
        } ?: tokenStorage.getToken()
        val shouldDisconnectCurrent = targetDevice == null ||
            (activeAuth?.peerSnowId != null && targetDevice.snowId == activeAuth.peerSnowId) ||
            (activeAuth?.peerDeviceId != null && targetDevice.deviceId == activeAuth.peerDeviceId) ||
            (connectedHost.isNotBlank() && targetDevice.host == connectedHost)

        if (client != null && client.connectionState.value == ConnectionState.CONNECTED && !currentToken.isNullOrBlank() && shouldDisconnectCurrent) {
            client.sendRequest(
                action = "unpair_request",
                data = mapOf(
                    "device_id" to devId,
                    "auth_token" to currentToken
                )
            ) { _ -> }
        }

        if (targetDevice != null) {
            removeSavedDevice(targetDevice.deviceId)
            tokenStorage.clearTokenForDevice(targetDevice.deviceId)
            certPinStorage.clearPinnedFingerprintForDevice(targetDevice.deviceId)
            targetDevice.snowId?.let {
                tokenStorage.clearTokenForDevice(it)
                certPinStorage.clearPinnedFingerprintForDevice(it)
            }
            if (_pendingNetworkDecision.value?.peerDeviceId.equals(targetDevice.deviceId, ignoreCase = true)) {
                _pendingNetworkDecision.value = null
            }
            clearNetworkMembershipIfEmpty()
        } else {
            clearSavedDevices()
            tokenStorage.clearAllTokens()
            certPinStorage.clearAllPinnedFingerprints()
            appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
                .edit().remove(PREF_KEY_ADOPTED_NETWORK_ID).apply()
            _adoptedNetworkId.value = null
            _pendingNetworkDecision.value = null
            serviceRef?.peerHostManager?.setConfiguredNetworkId(null)
        }

        if (shouldDisconnectCurrent) {
            SnowForegroundService.setDisconnectedByUser(appContext, true)
            serviceRef?.cancelAutoConnect()
            if (targetDevice == null) {
                tokenStorage.clearAllTokens()
            }
            _connectedEndpoint.value = null
            connectedHost = ""
            _pcTelemetry.value = PcTelemetry.UNAVAILABLE
            _authState.value = AuthState.Disconnected
            client?.disconnect()
            _connectionState.value = ConnectionState.DISCONNECTED
            _uiConnectionState.value = ConnectionState.DISCONNECTED
        }
    }

    fun resetTrust() {
        appendLog("INFO", TAG, "Resetting all cryptographic trust (clearing certificates, keys, and auth tokens).")
        SnowForegroundService.setDisconnectedByUser(appContext, true)
        serviceRef?.cancelAutoConnect()
        certPinStorage.clearAllPinnedFingerprints()
        tokenStorage.clearAllTokens()
        serviceRef?.peerHostManager?.resetPersistedIdentity()
        appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
            .edit().remove(PREF_KEY_ADOPTED_NETWORK_ID).apply()
        _adoptedNetworkId.value = null
        _pendingNetworkDecision.value = null
        _connectedEndpoint.value = null
        connectedHost = ""
        _authState.value = AuthState.Disconnected
        serviceRef?.client?.disconnect()
        _connectionState.value = ConnectionState.DISCONNECTED
        _uiConnectionState.value = ConnectionState.DISCONNECTED
        clearSavedDevices()
    }

    // --- Saved Devices (Phase 20 Identity-First Mesh & Endpoint History) ---

    fun loadSavedDevices() {
        val prefsV2 = appContext.getSharedPreferences("snow_paired_devices_v2", Context.MODE_PRIVATE)
        val rawJson = prefsV2.getString("devices_json", null)
        if (!rawJson.isNullOrBlank()) {
            val loaded = deserializeSavedDevices(rawJson)
            _savedDevices.value = loaded
            val normalizedJson = serializeSavedDevices(loaded)
            if (normalizedJson != rawJson) {
                prefsV2.edit().putString("devices_json", normalizedJson).apply()
            }
        } else {
            // Safe migration from legacy snow_settings: discard placeholder 127.0.0.1 and never key by token prefix
            val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
            val savedHost = (prefs.getString("last_connected_host", "") ?: "").trim()
            val savedPort = prefs.getInt("last_connected_port", 8765)
            val token = tokenStorage.getToken()
            val pinnedFp = certPinStorage.getPinnedFingerprint()
            if (token != null) {
                val validHost = if (savedHost.isNotBlank() && savedHost != "127.0.0.1") savedHost else ""
                val endpoints = if (validHost.isNotBlank()) listOf(DeviceEndpoint(validHost, savedPort)) else emptyList()
                val canonicalId = when {
                    validHost.isNotBlank() -> "peer-$validHost:$savedPort"
                    else -> "paired-desktop-legacy"
                }
                val migrated = SavedDevice(
                    deviceId = canonicalId,
                    deviceName = if (validHost.isNotBlank()) "Paired Desktop ($validHost)" else "Paired Desktop Core",
                    host = validHost,
                    port = savedPort,
                    lastSeen = "Active",
                    trustTier = "owner",
                    certFingerprint = pinnedFp,
                    recentEndpoints = endpoints,
                    snowId = null,
                    permissionProfile = "not_allowed"
                )
                val list = listOf(migrated)
                _savedDevices.value = list
                prefsV2.edit().putString("devices_json", serializeSavedDevices(list)).apply()
            } else {
                _savedDevices.value = emptyList()
            }
        }
    }

    @JvmOverloads
    fun recordSuccessfulConnection(
        host: String,
        port: Int,
        sessionId: String,
        tier: String = "PEER",
        peerDeviceName: String? = null,
        peerDeviceType: String? = null,
        peerDeviceId: String? = null,
        peerSnowId: String? = null,
        peerPermissionProfile: String? = null,
        peerNetworkId: String? = null,
        peerTransferPort: Int? = null,
        peerRelationship: String? = null,
        networkConflict: Boolean = false
    ) {
        val cleanHost = host.trim()
        val cleanSnowId = peerSnowId?.trim()?.uppercase()?.takeIf { it.isNotBlank() }
        val cleanPeerId = peerDeviceId?.trim()?.takeIf { it.isNotBlank() }
        val cleanPeerNet = peerNetworkId?.trim()?.uppercase()?.takeIf {
            it.matches(Regex("^SNW-NET-[A-Z0-9]{8}$"))
        }
        val explicitRel = peerRelationship?.trim()?.lowercase()?.takeIf {
            it == "member" || it == "external_network"
        }
        if ((explicitRel == null || explicitRel == "member") && !networkConflict) {
            applyNonConflictingNetworkAdoption(cleanPeerNet)
        }

        val matchedDiscovered = _discoveredPeers.value.find {
            (!cleanPeerId.isNullOrBlank() && it.deviceId.equals(cleanPeerId, ignoreCase = true)) ||
                (!cleanSnowId.isNullOrBlank() && it.snowId.equals(cleanSnowId, ignoreCase = true)) ||
                (cleanHost.isNotBlank() && cleanHost != "127.0.0.1" && it.ipAddress == cleanHost)
        }
        val canonicalKey = cleanPeerId
            ?: cleanSnowId
            ?: matchedDiscovered?.deviceId?.takeIf { it.isNotBlank() }
            ?: run {
                val fallbackFp = if (certPinStorage.listPinnedDeviceIds().isEmpty()) {
                    certPinStorage.getPinnedFingerprint()
                } else null
                fallbackFp?.takeIf { it.isNotBlank() }?.let { "peer-fp-${it.replace(":", "").lowercase().take(16)}" }
            }
            ?: if (cleanHost.isNotBlank()) "peer-$cleanHost:$port" else "peer-$sessionId"

        val pinnedFp = (cleanPeerId?.let { activeCertPinStorage.getPinnedFingerprintForDevice(it) })
            ?: (cleanSnowId?.let { activeCertPinStorage.getPinnedFingerprintForDevice(it) })
            ?: matchedDiscovered?.certFingerprint?.takeIf { it.isNotBlank() }
            ?: activeCertPinStorage.getPinnedFingerprintForDevice(canonicalKey)
            ?: if (activeCertPinStorage.listPinnedDeviceIds().isEmpty()) activeCertPinStorage.getPinnedFingerprint() else null

        val nowStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())

        val resolvedSnowId = cleanSnowId
            ?: matchedDiscovered?.snowId?.trim()?.uppercase()?.takeIf { it.isNotBlank() }
            ?: cleanPeerId?.takeIf { it.startsWith("SNW-", ignoreCase = true) }?.uppercase()
        val rawType = peerDeviceType?.takeIf { it.isNotBlank() }
            ?: matchedDiscovered?.deviceType?.takeIf { it.isNotBlank() }
        val resolvedType = when {
            rawType != null && (rawType.equals("android", ignoreCase = true) || rawType.equals("phone", ignoreCase = true)) -> "phone"
            rawType != null -> "pc"
            else -> null
        }
        val resolvedName = peerDeviceName?.takeIf { it.isNotBlank() }
            ?: matchedDiscovered?.deviceName?.takeIf { it.isNotBlank() }
        val normalizedIncomingTier = normalizeTrustTier(tier)
        val hasExplicitRemoteProfile = isExplicitPermissionProfileToken(peerPermissionProfile)
        val normalizedRemoteProfile = if (peerPermissionProfile != null) {
            normalizeAccessProfile(peerPermissionProfile)
        } else {
            null
        }

        val current = _savedDevices.value.toMutableList()
        val probe = SavedDevice(
            deviceId = canonicalKey,
            deviceName = resolvedName ?: "Desktop Core",
            host = cleanHost,
            port = port,
            lastSeen = nowStr,
            trustTier = normalizedIncomingTier,
            certFingerprint = pinnedFp,
            snowId = resolvedSnowId,
            deviceType = resolvedType ?: "pc",
            permissionProfile = normalizedRemoteProfile ?: "not_allowed"
        )
        val existingIdx = current.indexOfFirst { canMergeSavedDevices(it, probe) }

        val updatedEndpoints = mutableListOf<DeviceEndpoint>()
        if (cleanHost.isNotBlank() && cleanHost != "127.0.0.1") {
            updatedEndpoints.add(DeviceEndpoint(cleanHost, port, System.currentTimeMillis()))
        }
        if (existingIdx >= 0) {
            val existing = current[existingIdx]
            for (ep in existing.recentEndpoints) {
                if (ep.host != cleanHost && updatedEndpoints.size < 5) {
                    updatedEndpoints.add(ep)
                }
            }
            val effectiveTier = if (normalizedIncomingTier == "peer" && existing.trustTier.trim().isNotEmpty()) {
                normalizeTrustTier(existing.trustTier)
            } else {
                normalizedIncomingTier
            }
            val effectiveType = resolvedType ?: existing.deviceType
            val isIncomingGenericName = resolvedName == null ||
                resolvedName.equals("Desktop Core", ignoreCase = true) ||
                resolvedName.equals("SNOW Desktop", ignoreCase = true) ||
                resolvedName.equals("Android Peer", ignoreCase = true)
            val existingCustom = existing.deviceName.trim().takeIf {
                it.isNotEmpty() && !it.equals("Desktop Core", ignoreCase = true) && !it.equals("Paired Desktop Core", ignoreCase = true)
            }
            val effectiveName = if (isIncomingGenericName && existingCustom != null) {
                existingCustom
            } else {
                resolvedName ?: existing.deviceName
            }
            val (_, preservedProfile) = resolveSeparatedTrustAndProfile(
                existing.trustTier,
                existing.permissionProfile
            )
            val effectiveProfile = if (hasExplicitRemoteProfile && normalizedRemoteProfile != null) {
                normalizedRemoteProfile
            } else {
                preservedProfile
            }
            val nextCanonicalId = if (!isWeakSyntheticDeviceId(canonicalKey)) canonicalKey else existing.deviceId
            val resolvedPort = peerTransferPort?.takeIf { it > 0 }
                ?: existing.transferPort.takeIf { it > 0 }
                ?: if (effectiveType == "phone") org.snow.network.AndroidPeerHostManager.DEFAULT_MEDIA_PORT else 8766
            val effectiveRel = explicitRel ?: existing.relationship
            current[existingIdx] = existing.copy(
                deviceId = nextCanonicalId,
                deviceName = effectiveName,
                deviceType = effectiveType,
                host = if (cleanHost != "127.0.0.1" || existing.host.isBlank()) cleanHost else existing.host,
                port = if (cleanHost != "127.0.0.1" || existing.host.isBlank()) port else existing.port,
                transferPort = resolvedPort,
                lastSeen = nowStr,
                trustTier = effectiveTier,
                certFingerprint = pinnedFp ?: existing.certFingerprint,
                recentEndpoints = updatedEndpoints.take(5),
                snowId = resolvedSnowId ?: existing.snowId,
                permissionProfile = effectiveProfile,
                relationship = effectiveRel,
                networkId = cleanPeerNet ?: existing.networkId
            )
        } else {
            val finalType = resolvedType ?: "pc"
            val finalName = resolvedName
                ?: if (finalType == "phone") "Android Peer ($cleanHost)" else "Desktop Core ($cleanHost)"
            val resolvedPort = peerTransferPort?.takeIf { it > 0 }
                ?: if (finalType == "phone") org.snow.network.AndroidPeerHostManager.DEFAULT_MEDIA_PORT else 8766
            current.add(
                0,
                SavedDevice(
                    deviceId = canonicalKey,
                    deviceName = finalName,
                    host = cleanHost,
                    port = port,
                    transferPort = resolvedPort,
                    lastSeen = nowStr,
                    trustTier = normalizedIncomingTier,
                    certFingerprint = pinnedFp,
                    recentEndpoints = updatedEndpoints.take(5),
                    snowId = resolvedSnowId,
                    deviceType = finalType,
                    permissionProfile = normalizedRemoteProfile ?: "not_allowed",
                    relationship = explicitRel ?: "member",
                    networkId = cleanPeerNet
                )
            )
        }

        val deduped = deduplicateSavedDevices(current)
        _savedDevices.value = deduped
        val prefsV2 = appContext.getSharedPreferences("snow_paired_devices_v2", Context.MODE_PRIVATE)
        prefsV2.edit().putString("devices_json", serializeSavedDevices(deduped)).apply()
    }

    private fun saveDevice(device: SavedDevice) {
        val current = _savedDevices.value.filter { it.deviceId != device.deviceId }
        val updated = listOf(device) + current
        _savedDevices.value = updated
        val prefsV2 = appContext.getSharedPreferences("snow_paired_devices_v2", Context.MODE_PRIVATE)
        prefsV2.edit().putString("devices_json", serializeSavedDevices(updated)).apply()
    }

    fun removeSavedDevice(deviceId: String) {
        val updated = _savedDevices.value.filter { it.deviceId != deviceId }
        _savedDevices.value = updated
        val prefsV2 = appContext.getSharedPreferences("snow_paired_devices_v2", Context.MODE_PRIVATE)
        prefsV2.edit().putString("devices_json", serializeSavedDevices(updated)).apply()
    }

    fun clearTerminalOutput() {
        _terminalState.value = TerminalExecutionState()
    }

    private fun clearSavedDevices() {
        _savedDevices.value = emptyList()
        val prefsV2 = appContext.getSharedPreferences("snow_paired_devices_v2", Context.MODE_PRIVATE)
        prefsV2.edit().remove("devices_json").apply()
    }

    // --- Phase 20 Zero-IP-Friction Onboarding & USB Actions ---

    fun connectUsbLocalhost() {
        appendLog("INFO", TAG, "Connecting to desktop core over USB reverse mapping (127.0.0.1:8765)...")
        connect("127.0.0.1", 8765)
    }

    fun handleQrScanPayload(qrJson: String, onComplete: (Boolean, String?) -> Unit) {
        appendLog("INFO", TAG, "Processing QR onboarding payload...")
        val payload = try {
            org.json.JSONObject(qrJson)
        } catch (e: Exception) {
            val err = "Malformed QR payload: not valid JSON."
            appendLog("ERROR", TAG, err)
            onComplete(false, err)
            return
        }

        val v = payload.optInt("v", -1)
        if (v != 1 && v != 2) {
            val err = "Unsupported QR version: $v. Expected 1 or 2."
            appendLog("ERROR", TAG, err)
            onComplete(false, err)
            return
        }

        val expSec = payload.optLong("exp", 0L)
        if (expSec > 0L && (System.currentTimeMillis() / 1000L) > expSec) {
            val err = "QR code has expired. Generate a fresh QR code on host."
            appendLog("ERROR", TAG, err)
            onComplete(false, err)
            return
        }

        val nodeId = payload.optString("device_id", "").trim()
            .ifEmpty { payload.optString("id", "").trim() }
        val qrSnowId = payload.optString("snow_id", "").trim().uppercase().takeIf { it.isNotBlank() }
        val qrDeviceType = payload.optString("device_type", "").trim().lowercase().takeIf { it.isNotBlank() }
        val port = payload.optInt("port", 8765)
        val qrTransferPort = payload.optInt("transfer_port", 0).takeIf { it in 1..65535 }
            ?: if (qrDeviceType == "android" || qrDeviceType == "phone" || port == 8767) {
                org.snow.network.AndroidPeerHostManager.DEFAULT_MEDIA_PORT
            } else {
                8766
            }
        val pin = payload.optString("pin", "").trim()
        val hasHandshakeField = payload.has("handshake_token") && !payload.isNull("handshake_token")
        val handshakeToken = payload.optString("handshake_token", "").trim()
        val networkId = if (payload.isNull("network_id")) "" else payload.optString("network_id", "").trim()
        val hubUrl = payload.optString("hub_url", "").trim()
        val rdvId = payload.optString("rdv_id", "").trim()
        val fp = payload.optString("fp", "").replace(":", "").replace(" ", "").trim()

        val hasValidPin = pin.length == 6 && pin.all { it.isDigit() }
        val hasValidHandshake = handshakeToken.length >= 16
        if (hasHandshakeField && handshakeToken.isNotEmpty() && !hasValidHandshake) {
            val err = "Invalid QR handshake token in payload."
            appendLog("ERROR", TAG, err)
            onComplete(false, err)
            return
        }
        if (nodeId.isEmpty() || (!hasValidPin && !hasValidHandshake) || fp.length != 64) {
            val err = "Invalid QR payload schema (missing id, handshake token/pin, or invalid fingerprint)."
            appendLog("ERROR", TAG, err)
            onComplete(false, err)
            return
        }

        if (hubUrl.startsWith("https://") || hubUrl.startsWith("http://")) {
            val normHub = normalizeRelayUrl(hubUrl)
            if (normHub.isNotBlank()) {
                updateRemoteRelayConfig(true, normHub)
                appendLog("INFO", TAG, "QR onboarding configured Default Hub endpoint: $normHub")
            }
        }

        val rawIps = payload.optJSONArray("ips")
        val candidateIpsSet = LinkedHashSet<String>()
        if (rawIps != null) {
            for (i in 0 until rawIps.length()) {
                val ipStr = rawIps.getString(i).trim()
                val isLoopback = ipStr == "127.0.0.1" || ipStr.startsWith("127.") || ipStr == "::1"
                if (ipStr.isNotBlank() && (!isLoopback || allowLoopbackCandidateIpsForTest) && !ipStr.startsWith("169.254.")) {
                    candidateIpsSet.add(ipStr)
                }
            }
        }
        val candidateIps = candidateIpsSet.toList()

        if (candidateIps.isEmpty() && rdvId.isBlank()) {
            val err = "No reachable candidate LAN IPs found in QR payload."
            appendLog("ERROR", TAG, err)
            onComplete(false, err)
            return
        }

        // Per-device pinned certificate verification (multi-device safe: different nodeIds never collide)
        val existingPinForNode = activeCertPinStorage.getPinnedFingerprintForDevice(nodeId)
        val savedMatchForNode = _savedDevices.value.find { it.deviceId.equals(nodeId, ignoreCase = true) }
        val pinnedFp = existingPinForNode ?: savedMatchForNode?.certFingerprint?.takeIf { it.isNotBlank() }
        if (pinnedFp != null) {
            val cleanPinned = pinnedFp.replace(":", "").replace(" ", "").trim()
            if (!cleanPinned.equals(fp, ignoreCase = true)) {
                val err = "CRITICAL: Certificate fingerprint in QR does not match existing pinned certificate for device '$nodeId'! Mismatch blocked."
                appendLog("ERROR", TAG, err)
                _authState.value = AuthState.FingerprintMismatch(pinnedFp, fp)
                onComplete(false, err)
                return
            }
            if (existingPinForNode == null) {
                activeCertPinStorage.pinFingerprintForDevice(nodeId, fp)
            }
        } else {
            // TOFU initial trust scoped strictly to this QR host nodeId
            activeCertPinStorage.pinFingerprintForDevice(nodeId, fp)
            appendLog("INFO", TAG, "Pinned TLS certificate fingerprint for device '$nodeId' from scanned QR code.")
        }

        // Master QR: provision remote relay credentials if included
        val relayUrl = payload.optString("relay_url", "").trim()
        val relayTicket = payload.optString("relay_ticket", "").trim()
        val groupId = payload.optString("group_id", "").trim()
        if (relayUrl.isNotEmpty() && relayTicket.isNotEmpty()) {
            if (relayUrl.startsWith("wss://") || relayUrl.startsWith("ws://")) {
                try {
                    getRelayTokenStorage().saveToken(relayTicket)
                    setRemoteRelayEndpoint(relayUrl)
                    if (groupId.isNotEmpty()) {
                        val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
                        prefs.edit().putString("remote_relay_group_id", groupId).apply()
                    }
                    setRemoteRelayEnabled(true)
                    appendLog("INFO", TAG, "Master QR: Securely provisioned remote relay credentials and endpoint.")
                } catch (e: Exception) {
                    appendLog("WARN", TAG, "Could not persist remote relay credentials from QR: ${e.message}")
                }
            } else {
                appendLog("WARN", TAG, "Ignoring invalid relay_url scheme from QR: $relayUrl")
            }
        }

        // Try every ranked candidate IP sequentially using EXPLICIT_PAIRING_INITIATOR mode
        repoScope.launch {
            var callbackInvoked = false
            fun finishQr(ok: Boolean, errMsg: String?) {
                if (!callbackInvoked) {
                    callbackInvoked = true
                    onComplete(ok, errMsg)
                }
            }

            val perCandidateMs = qrCandidateTimeoutMs.coerceIn(250L, 10_000L)
            for ((idx, targetIp) in candidateIps.withIndex()) {
                appendLog(
                    "INFO",
                    TAG,
                    "Initiating QR onboarding connection ${idx + 1}/${candidateIps.size} to $targetIp:$port (device=$nodeId)..."
                )
                connect(
                    host = targetIp,
                    port = port,
                    targetDeviceId = nodeId,
                    handshakeMode = org.snow.network.ConnectionHandshakeMode.EXPLICIT_PAIRING_INITIATOR
                )

                val deadlineMs = System.currentTimeMillis() + perCandidateMs
                var steps = 0
                var terminalDecisionMade = false

                while (System.currentTimeMillis() < deadlineMs) {
                    kotlinx.coroutines.delay(50)
                    steps++
                    val state = _connectionState.value
                    val auth = _authState.value
                    if (state == ConnectionState.CONNECTED && auth is AuthState.Authenticated) {
                        appendLog("INFO", TAG, "Device already authenticated with host. Onboarding complete.")
                        recordSuccessfulConnection(
                            host = targetIp,
                            port = port,
                            sessionId = auth.sessionId,
                            tier = auth.trustTier,
                            peerDeviceName = auth.peerDeviceName,
                            peerDeviceType = auth.peerDeviceType ?: qrDeviceType,
                            peerDeviceId = auth.peerDeviceId?.takeIf { it.isNotBlank() } ?: nodeId,
                            peerSnowId = auth.peerSnowId ?: qrSnowId,
                            peerPermissionProfile = auth.permissionProfile,
                            peerNetworkId = auth.peerNetworkId ?: networkId.takeIf { it.isNotBlank() },
                            peerTransferPort = qrTransferPort
                        )
                        finishQr(true, null)
                        return@launch
                    } else if (state == ConnectionState.CONNECTED && auth is AuthState.ConnectedUnauthenticated) {
                        val pairingOutcome = kotlinx.coroutines.CompletableDeferred<Pair<Boolean, String?>>()
                        val onQrPairingResult: (PairingState) -> Unit = { pState ->
                            when (pState) {
                                is PairingState.Paired -> {
                                    appendLog("INFO", TAG, "QR pairing successful [tier=${pState.trustTier}]")
                                    recordSuccessfulConnection(
                                        host = targetIp,
                                        port = port,
                                        sessionId = pState.sessionId,
                                        tier = pState.trustTier,
                                        peerDeviceName = pState.desktopName,
                                        peerDeviceType = pState.deviceType ?: qrDeviceType,
                                        peerDeviceId = pState.desktopId.takeIf { it.isNotBlank() && it != "unknown" } ?: nodeId,
                                        peerSnowId = pState.peerSnowId ?: qrSnowId,
                                        peerPermissionProfile = pState.permissionProfile,
                                        peerNetworkId = pState.hostNetworkId ?: pState.peerNetworkId ?: networkId.takeIf { it.isNotBlank() && !pState.networkConflict },
                                        peerTransferPort = qrTransferPort,
                                        peerRelationship = pState.relationship,
                                        networkConflict = pState.networkConflict
                                    )
                                    pairingOutcome.complete(true to null)
                                }
                                is PairingState.WrongPin -> {
                                    val msg = pState.message.ifBlank { "QR pairing rejected: invalid or revoked credential." }
                                    appendLog("ERROR", TAG, "QR pairing failed: $msg")
                                    pairingOutcome.complete(false to msg)
                                }
                                is PairingState.Expired -> {
                                    val msg = pState.message.ifBlank { "QR pairing credential has expired. Generate a fresh QR code on host." }
                                    appendLog("ERROR", TAG, "QR pairing failed: $msg")
                                    pairingOutcome.complete(false to msg)
                                }
                                is PairingState.Locked -> {
                                    val msg = pState.message.ifBlank { "QR pairing locked due to too many failed attempts." }
                                    appendLog("ERROR", TAG, "QR pairing locked: $msg")
                                    pairingOutcome.complete(false to msg)
                                }
                                is PairingState.ConnectionLost -> {
                                    appendLog("ERROR", TAG, "QR pairing connection lost: ${pState.message}")
                                    pairingOutcome.complete(false to pState.message)
                                }
                                is PairingState.Error -> {
                                    appendLog("ERROR", TAG, "QR pairing error: ${pState.message}")
                                    pairingOutcome.complete(false to pState.message)
                                }
                                else -> {}
                            }
                        }
                        if (hasValidHandshake) {
                            appendLog("INFO", TAG, "Connection established; submitting single-use QR handshake token...")
                            pairDeviceWithHandshakeToken(handshakeToken, networkId, nodeId, onQrPairingResult)
                        } else if (hasHandshakeField) {
                            finishQr(false, "QR handshake token missing or invalid.")
                            return@launch
                        } else {
                            appendLog("INFO", TAG, "Connection established; auto-submitting pairing PIN from QR...")
                            pairDevice(pin, onQrPairingResult)
                        }
                        val (ok, pairErr) = pairingOutcome.await()
                        finishQr(ok, pairErr)
                        return@launch
                    } else if (auth is AuthState.AuthFailed) {
                        appendLog("ERROR", TAG, "QR onboarding authentication failed: ${auth.reason}")
                        finishQr(false, auth.reason)
                        return@launch
                    } else if (auth is AuthState.FingerprintMismatch) {
                        val err = "Certificate fingerprint mismatch during QR pairing."
                        appendLog("ERROR", TAG, err)
                        finishQr(false, err)
                        return@launch
                    } else if (auth is AuthState.FingerprintConfirmationRequired) {
                        val err = "Certificate confirmation required before completing QR pairing."
                        appendLog("WARN", TAG, err)
                        finishQr(false, err)
                        return@launch
                    } else if (state == ConnectionState.DISCONNECTED && steps >= 6) {
                        appendLog("WARN", TAG, "Candidate IP $targetIp:$port unreachable; advancing to next candidate...")
                        terminalDecisionMade = true
                        break
                    }
                }
                if (!terminalDecisionMade) {
                    appendLog("WARN", TAG, "Candidate IP $targetIp:$port timed out; advancing to next candidate...")
                }
            }

            if (rdvId.isNotBlank()) {
                appendLog("INFO", TAG, "LAN candidate IPs unavailable; attempting Render Hub rendezvous fallback ($rdvId)...")
                completeRendezvousOnboardingFromQr(
                    rdvId = rdvId,
                    hostNodeId = nodeId,
                    hostSnowId = qrSnowId,
                    hostFp = fp,
                    hostDeviceType = qrDeviceType,
                    hostTransferPort = qrTransferPort,
                    handshakeToken = handshakeToken.takeIf { hasValidHandshake },
                    pin = pin.takeIf { !hasValidHandshake && hasValidPin },
                    hubUrlOverride = hubUrl.takeIf { it.isNotBlank() },
                    onResult = { ok, errMsg ->
                        finishQr(ok, errMsg)
                    }
                )
                return@launch
            }

            finishQr(
                false,
                "Timed out reaching host on ${candidateIps.size} candidate IP(s): ${candidateIps.joinToString(", ")}."
            )
        }
    }

    // --- Phase 5A: Unified Connection Resolution & Relay Normalization ---

    fun normalizeRelayUrl(raw: String): String = Companion.normalizeRelayUrl(raw)

    fun connectRelay(normalizedRelayUrl: String) {
        updateRemoteRelayConfig(true, normalizedRelayUrl)
        appendLog("INFO", TAG, "Configured remote relay endpoint: $normalizedRelayUrl")
    }

    internal var snowIdDiscoveryBurstMs: Long = 2500L
    internal var allowDevLoopbackForTest: Boolean = false
    internal var hubBearerTokenProvider: (() -> String?)? = null

    fun connectByInput(raw: String, onResult: (Boolean, String, String?) -> Unit) {
        val input = raw.trim()
        if (input.isEmpty()) {
            onResult(false, "Input cannot be empty", null)
            return
        }

        // 0. Check JSON QR payload format
        if (input.startsWith("{")) {
            processScannedQr(input, onResult)
            return
        }

        // 1. Check optional "SNOW_ID 6DIGIT_PIN" (or bare SNOW ID / Network ID)
        val snowPinParts = Regex("^(\\S+)(?:\\s+|#)(\\d{6})$").matchEntire(input)
        val snowCandidate = (snowPinParts?.groupValues?.get(1) ?: input).trim()
        val pairedPinCandidate = snowPinParts?.groupValues?.get(2)?.takeIf { it.length == 6 }

        val snowIdRegex = Regex("^(SNW-NET-[A-F0-9]{8}|SNW-[A-Z0-9]{4}-[A-Z0-9]{4}|SNW-[A-Z0-9]{4}|DEV-[A-Z0-9]{4})$", RegexOption.IGNORE_CASE)
        if (snowIdRegex.matches(snowCandidate)) {
            val upperSnowId = snowCandidate.uppercase()
            appendLog("INFO", TAG, "Resolving connection for SNOW ID: $upperSnowId")

            fun findDiscoveredPeer(): DiscoveredPeer? = _discoveredPeers.value.find { peer ->
                peer.snowId.equals(upperSnowId, ignoreCase = true) ||
                    peer.deviceId.equals(upperSnowId, ignoreCase = true) ||
                    (upperSnowId.length == 8 && (
                        peer.snowId?.startsWith(upperSnowId, ignoreCase = true) == true ||
                            peer.deviceId.startsWith(upperSnowId, ignoreCase = true)
                        ))
            }

            // Step 1: Immediate live LAN peer match
            findDiscoveredPeer()?.let { matchedPeer ->
                appendLog("INFO", TAG, "Found discovered peer for $upperSnowId at ${matchedPeer.ipAddress}:${matchedPeer.port}")
                connect(matchedPeer.ipAddress, matchedPeer.port, targetDeviceId = matchedPeer.deviceId)
                onResult(true, "Connecting to discovered peer for $upperSnowId", "lan")
                return
            }

            // Step 2: Saved-device canonical lookup (only when reachable LAN/direct endpoint exists & not remote_only)
            val savedDev = _savedDevices.value.find { dev ->
                dev.snowId?.equals(upperSnowId, ignoreCase = true) == true ||
                    dev.deviceId.equals(upperSnowId, ignoreCase = true) ||
                    (upperSnowId.length == 8 && (
                        dev.snowId?.startsWith(upperSnowId, ignoreCase = true) == true ||
                            dev.deviceId.startsWith(upperSnowId, ignoreCase = true)
                        ))
            }
            if (savedDev != null && savedDev.connectionMode != "remote_only") {
                val targetHost = savedDev.recentEndpoints.firstOrNull { it.host.isNotBlank() }?.host
                    ?: savedDev.host.takeIf { it.isNotBlank() }
                val targetPort = savedDev.recentEndpoints.firstOrNull { it.host.isNotBlank() }?.port ?: savedDev.port
                if (!targetHost.isNullOrBlank()) {
                    appendLog("INFO", TAG, "Found saved device for $upperSnowId: $targetHost:$targetPort")
                    connect(targetHost, targetPort, targetDeviceId = savedDev.deviceId)
                    onResult(true, "Connecting to saved device for $upperSnowId", "saved")
                    return
                }
            }

            // Step 3: Cancellable ~2.5s active non-blocking LAN discovery burst, then authenticated Hub rendezvous
            snowIdResolveJob?.cancel()
            snowIdResolveJob = repoScope.launch {
                val dm = serviceRef?.discoveryManager
                try {
                    dm?.startListening()
                } catch (_: Exception) {}

                val burstDeadline = System.currentTimeMillis() + snowIdDiscoveryBurstMs.coerceAtLeast(0L)
                var lanMatched: DiscoveredPeer? = findDiscoveredPeer()
                while (lanMatched == null && System.currentTimeMillis() < burstDeadline) {
                    val remaining = (burstDeadline - System.currentTimeMillis()).coerceAtLeast(10L)
                    kotlinx.coroutines.withContext(Dispatchers.IO) {
                        kotlinx.coroutines.delay(minOf(100L, remaining))
                    }
                    lanMatched = findDiscoveredPeer()
                }

                if (lanMatched != null) {
                    appendLog("INFO", TAG, "LAN burst resolved $upperSnowId at ${lanMatched.ipAddress}:${lanMatched.port}")
                    connect(lanMatched.ipAddress, lanMatched.port, targetDeviceId = lanMatched.deviceId)
                    onResult(true, "Connecting to $upperSnowId on local Wi-Fi", "lan")
                    return@launch
                }

                // Step 4: If user included 6-digit pairing PIN, redeem via authenticated /v1/rendezvous/join
                // and complete full E2E TLS tunnel pairing BEFORE reporting success.
                if (!pairedPinCandidate.isNullOrBlank()) {
                    joinRendezvousOnboarding(
                        snowId = upperSnowId,
                        pin = pairedPinCandidate,
                        allowDevLoopback = allowDevLoopbackForTest
                    ) { ok, rdvData, err ->
                        if (ok && rdvData != null) {
                            val hostDevId = (rdvData["host_device_id"] as? String)?.trim().orEmpty()
                            val fp = (rdvData["host_cert_fingerprint"] as? String)?.replace(":", "")?.trim().orEmpty()
                            val relayWs = (rdvData["relay_ws_url"] as? String)?.trim().orEmpty()
                            val bootstrapTok = (rdvData["bootstrap_token"] as? String)?.trim().orEmpty()
                            if (hostDevId.isBlank() || fp.length != 64 || relayWs.isBlank() || bootstrapTok.isBlank()) {
                                onResult(
                                    false,
                                    "Rendezvous response missing required E2E tunnel identity or credentials for $upperSnowId.",
                                    "hub_unavailable"
                                )
                                return@joinRendezvousOnboarding
                            }
                            val dataWithMeta = rdvData.toMutableMap().apply {
                                if ((get("host_snow_id") as? String).isNullOrBlank()) {
                                    put("host_snow_id", upperSnowId)
                                }
                            }
                            val pairCallback: (Boolean, String?) -> Unit = { pairedOk, pairErr ->
                                if (pairedOk) {
                                    onResult(true, "Paired & connected to $upperSnowId via Render Hub E2E tunnel", "rendezvous")
                                } else {
                                    onResult(false, pairErr ?: "E2E tunnel pairing failed for $upperSnowId.", "hub_auth_failed")
                                }
                            }
                            val hook = customRendezvousTunnelPairerForTest
                            if (hook != null) {
                                hook.invoke(dataWithMeta, pairedPinCandidate, null, pairCallback)
                            } else {
                                completeRendezvousPairingOverTunnel(
                                    rdvData = dataWithMeta,
                                    pin = pairedPinCandidate,
                                    handshakeToken = null,
                                    onResult = pairCallback
                                )
                            }
                        } else {
                            onResult(false, err ?: "Render Hub rendezvous failed for $upperSnowId.", "hub_auth_failed")
                        }
                    }
                    return@launch
                }

                // Step 5: Credentialed Hub directory resolution ONLY when caller holds an authenticated Bearer token;
                // never call unauthenticated /v1/directory/resolve and never fall back to 127.0.0.1:8765.
                val bearerToken = hubBearerTokenProvider?.invoke()?.trim()?.takeIf { it.isNotBlank() }
                val hubBase = try {
                    getDefaultHubUrl(allowDevLoopback = allowDevLoopbackForTest)
                } catch (_: Exception) {
                    ""
                }
                if (bearerToken != null && (hubBase.startsWith("https://") || hubBase.startsWith("http://"))) {
                    val outcome = kotlinx.coroutines.withContext(Dispatchers.IO) {
                        var resolvedOnline = false
                        var resolvedRelayWs = ""
                        var resolvedHostId = ""
                        var resolvedNetId = ""
                        var failureReason = "Could not resolve $upperSnowId on local network or cloud hub."
                        var failureTag = "not_found"
                        try {
                            val req = okhttp3.Request.Builder()
                                .url("$hubBase/v1/directory/resolve/${java.net.URLEncoder.encode(upperSnowId, "UTF-8")}")
                                .addHeader("Authorization", "Bearer $bearerToken")
                                .get()
                                .build()
                            val httpClient = okhttp3.OkHttpClient.Builder()
                                .callTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                                .build()
                            httpClient.newCall(req).execute().use { resp ->
                                val bodyStr = resp.body?.string() ?: "{}"
                                val obj = try { org.json.JSONObject(bodyStr) } catch (_: Exception) { org.json.JSONObject() }
                                when {
                                    resp.isSuccessful -> {
                                        resolvedOnline = obj.optBoolean("online", false)
                                        resolvedRelayWs = obj.optString("relay_ws_url", "").trim()
                                        resolvedHostId = obj.optString("device_id", "").trim()
                                        resolvedNetId = obj.optString("network_id", "").trim()
                                        if (!resolvedOnline) {
                                            failureReason = "Remote device $upperSnowId is offline."
                                            failureTag = "offline"
                                        }
                                    }
                                    resp.code == 401 -> {
                                        failureReason = obj.optString("error").ifBlank { "Hub session expired or unauthorized (HTTP 401)." }
                                        failureTag = "hub_auth_failed"
                                    }
                                    resp.code == 403 -> {
                                        failureReason = obj.optString("error").ifBlank { "Cross-network directory lookup denied (HTTP 403)." }
                                        failureTag = "forbidden"
                                    }
                                    resp.code == 404 -> {
                                        failureReason = "Device $upperSnowId not found on LAN or cloud hub."
                                        failureTag = "not_found"
                                    }
                                    else -> {
                                        failureReason = "Cloud hub directory unavailable (HTTP ${resp.code})."
                                        failureTag = "hub_unavailable"
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            failureReason = "Cloud hub unreachable while resolving $upperSnowId: ${e.message ?: "network error"}"
                            failureTag = "hub_unavailable"
                        }
                        listOf(resolvedOnline.toString(), resolvedRelayWs, resolvedHostId, resolvedNetId, failureReason, failureTag)
                    }
                    val okOnline = outcome[0] == "true"
                    val relayWs = outcome[1]
                    val hostDev = outcome[2]
                    val netId = outcome[3]
                    val errReason = outcome[4]
                    val errTag = outcome[5]
                    if (okOnline) {
                        if (netId.isNotBlank()) applyNonConflictingNetworkAdoption(netId)
                        val relayEp = relayWs.ifBlank { getEffectiveRelayEndpointForHub() }
                        if (relayEp.isNotBlank()) {
                            connectRelay(relayEp)
                            onResult(true, "Connecting to $upperSnowId via Cloud Hub", "hub_directory")
                        } else {
                            onResult(false, "Relay endpoint unavailable for $upperSnowId.", "hub_unavailable")
                        }
                    } else {
                        appendLog("WARN", TAG, "Unresolved SNOW ID $upperSnowId ($errTag): $errReason")
                        onResult(false, errReason, errTag)
                    }
                    return@launch
                }

                val guidance = "Device $upperSnowId not found on local network. Pair via QR code or enter '$upperSnowId <6-digit PIN>' to connect over Render Hub."
                appendLog("WARN", TAG, "Unresolved SNOW ID $upperSnowId: $guidance")
                onResult(false, guidance, "rendezvous_required")
            }
            return
        } else if (snowCandidate.startsWith("SNW-", ignoreCase = true) || snowCandidate.startsWith("DEV-", ignoreCase = true)) {
            onResult(false, "Invalid SNOW ID format: $snowCandidate", "INVALID_SNOW_ID")
            return
        }

        // 2. Check 6-digit PIN: ^\d{6}$
        if (input.length == 6 && input.all { it.isDigit() }) {
            appendLog("INFO", TAG, "Initiating pairing with 6-digit PIN: $input")
            pairDevice(input) { state ->
                when (state) {
                    is PairingState.Paired -> onResult(true, "Pairing successful", "pin")
                    is PairingState.WrongPin -> onResult(false, "Invalid PIN (${state.remainingAttempts} attempts remaining)", "pin")
                    is PairingState.Expired -> onResult(false, "PIN expired", "pin")
                    is PairingState.Locked -> onResult(false, "Pairing locked", "pin")
                    is PairingState.Error -> onResult(false, state.message, "pin")
                    else -> {}
                }
            }
            return
        }

        // 3. Check 9-digit Federation code: ^\d{9}$ or ^\d{3}[-\s]?\d{3}[-\s]?\d{3}$
        val cleanFedDigits = input.replace("-", "").replace(" ", "").trim()
        if (cleanFedDigits.length == 9 && cleanFedDigits.all { it.isDigit() }) {
            appendLog("INFO", TAG, "Processing 9-digit Federation code: $cleanFedDigits")
            acceptFederationInvite(cleanFedDigits) { success, _, err ->
                onResult(success, err ?: if (success) "Federation invite accepted" else "Failed to accept federation code", "federation")
            }
            return
        }

        // 4. Check Relay URL or Direct URL: starts with wss://, ws://, https://, http:// or contains trycloudflare / /v1/tunnel
        if (input.startsWith("wss://", ignoreCase = true) || input.startsWith("ws://", ignoreCase = true) ||
            input.startsWith("https://", ignoreCase = true) || input.startsWith("http://", ignoreCase = true) ||
            input.contains(".trycloudflare.com", ignoreCase = true) || input.contains("/v1/tunnel", ignoreCase = true)) {
            val normalizedRelay = normalizeRelayUrl(input)
            appendLog("INFO", TAG, "Connecting via Normalized Relay URL: $normalizedRelay")
            connectRelay(normalizedRelay)
            onResult(true, "Connecting via Relay: $normalizedRelay", "relay")
            return
        }

        // 5. Direct IP:Port or Host:Port or raw IP (default port 8765)
        val hostPart = input.substringBeforeLast(":").trim()
        val portPart = input.substringAfterLast(":", "").trim()
        val parsedPort = portPart.toIntOrNull()

        if (parsedPort != null && hostPart.isNotEmpty()) {
            appendLog("INFO", TAG, "Connecting directly to host:port: $hostPart:$parsedPort")
            connect(hostPart, parsedPort)
            onResult(true, "Connecting to $hostPart:$parsedPort", "direct")
            return
        } else if (input.matches(Regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}$")) || input.equals("localhost", ignoreCase = true)) {
            appendLog("INFO", TAG, "Connecting directly to IP on default port 8765: $input:8765")
            connect(input, 8765)
            onResult(true, "Connecting to $input:8765", "direct")
            return
        }

        onResult(false, "Unrecognized connection format: $input", null)
    }

    fun processScannedQr(qrText: String, onResult: (Boolean, String, String?) -> Unit) {
        handleQrScanPayload(qrText) { success, errorMsg ->
            if (success) {
                onResult(true, "Pairing connected successfully!", "qr")
            } else {
                onResult(false, errorMsg ?: "Failed to process QR code", null)
            }
        }
    }

    fun serializeSavedDevices(devices: List<SavedDevice>): String {
        val arr = org.json.JSONArray()
        for (d in devices) {
            val (normTier, normProfile) = resolveSeparatedTrustAndProfile(d.trustTier, d.permissionProfile)
            val obj = org.json.JSONObject()
            obj.put("deviceId", d.deviceId)
            obj.put("deviceName", d.deviceName)
            obj.put("host", d.host)
            obj.put("port", d.port)
            obj.put("lastSeen", d.lastSeen ?: "")
            obj.put("trustTier", normTier)
            obj.put("permissionProfile", normProfile)
            obj.put("certFingerprint", d.certFingerprint ?: "")
            obj.put("connectionMode", d.connectionMode)
            obj.put("snowId", d.snowId ?: "")
            obj.put("deviceType", d.deviceType)
            obj.put("transferPort", d.transferPort)
            obj.put("relationship", d.relationship)
            obj.put("networkId", d.networkId ?: "")
            val epArr = org.json.JSONArray()
            for (ep in d.recentEndpoints) {
                val epObj = org.json.JSONObject()
                epObj.put("host", ep.host)
                epObj.put("port", ep.port)
                epObj.put("lastSuccessTimestamp", ep.lastSuccessTimestamp)
                epArr.put(epObj)
            }
            obj.put("recentEndpoints", epArr)
            arr.put(obj)
        }
        return arr.toString()
    }

    fun deserializeSavedDevices(jsonStr: String): List<SavedDevice> {
        if (jsonStr.isBlank()) return emptyList()
        val list = mutableListOf<SavedDevice>()
        try {
            val arr = org.json.JSONArray(jsonStr)
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                val eps = mutableListOf<DeviceEndpoint>()
                val epArr = obj.optJSONArray("recentEndpoints")
                if (epArr != null) {
                    for (j in 0 until epArr.length()) {
                        val epObj = epArr.getJSONObject(j)
                        eps.add(
                            DeviceEndpoint(
                                host = epObj.getString("host"),
                                port = epObj.getInt("port"),
                                lastSuccessTimestamp = epObj.optLong("lastSuccessTimestamp", 0L)
                            )
                        )
                    }
                }
                val parsedType = obj.optString("deviceType", obj.optString("platform", "")).takeIf { it.isNotBlank() }
                    ?: if (obj.optString("deviceName", "").lowercase().contains("phone") ||
                           obj.optString("deviceName", "").lowercase().contains("android") ||
                           obj.optString("connectionMode", "").lowercase().contains("phone")) "phone" else "pc"
                val rawTier = obj.optString("trustTier", "peer")
                val rawProfile = obj.optString("permissionProfile", "")
                val (normTier, normProfile) = resolveSeparatedTrustAndProfile(rawTier, rawProfile)
                list.add(
                    SavedDevice(
                        deviceId = obj.getString("deviceId"),
                        deviceName = obj.optString("deviceName", "Desktop Core"),
                        host = obj.getString("host"),
                        port = obj.getInt("port"),
                        lastSeen = obj.optString("lastSeen", "").takeIf { it.isNotBlank() },
                        trustTier = normTier,
                        certFingerprint = obj.optString("certFingerprint", "").takeIf { it.isNotBlank() },
                        recentEndpoints = eps.take(5),
                        connectionMode = obj.optString("connectionMode", "auto"),
                        snowId = obj.optString("snowId", "").takeIf { it.isNotBlank() },
                        deviceType = parsedType,
                        permissionProfile = normProfile,
                        transferPort = obj.optInt("transferPort", if (parsedType == "phone") org.snow.network.AndroidPeerHostManager.DEFAULT_MEDIA_PORT else 8766),
                        relationship = obj.optString("relationship", "member").ifBlank { "member" },
                        networkId = obj.optString("networkId", "").takeIf { it.isNotBlank() }
                    )
                )
            }
        } catch (_: Exception) {}
        return deduplicateSavedDevices(list)
    }

    fun updateDeviceTrustTier(deviceId: String, tier: String) {
        val canonicalTier = normalizeTrustTier(tier)
        val current = _savedDevices.value.toMutableList()
        val idx = current.indexOfFirst { it.deviceId == deviceId }
        if (idx >= 0) {
            current[idx] = current[idx].copy(trustTier = canonicalTier)
            _savedDevices.value = current
            val prefsV2 = appContext.getSharedPreferences("snow_paired_devices_v2", Context.MODE_PRIVATE)
            prefsV2.edit().putString("devices_json", serializeSavedDevices(current)).apply()
        }
    }

    fun updateDevicePermissionProfile(deviceId: String, profile: String) {
        val canonicalProfile = normalizeAccessProfile(profile)
        val current = _savedDevices.value.toMutableList()
        val idx = current.indexOfFirst { it.deviceId == deviceId }
        if (idx >= 0) {
            current[idx] = current[idx].copy(permissionProfile = canonicalProfile)
            _savedDevices.value = current
            val prefsV2 = appContext.getSharedPreferences("snow_paired_devices_v2", Context.MODE_PRIVATE)
            prefsV2.edit().putString("devices_json", serializeSavedDevices(current)).apply()
        }
    }

    fun refreshTransportSnapshot(deviceId: String? = null) {
        val orch = activeTransportOrchestrator()
        val devList = if (deviceId != null) {
            _savedDevices.value.filter { it.deviceId == deviceId }
        } else {
            _savedDevices.value
        }
        val activeEp = _connectedEndpoint.value.orEmpty()
        val isAuthConn = isSessionTrulyConnected(_uiConnectionState.value, _authState.value)
        val authDevId = (_authState.value as? AuthState.Authenticated)?.peerDeviceId
        val nextMap = _transportSnapshots.value.toMutableMap()
        val relayVerifiedLive = serviceRef?.relayClient?.isSessionAndTunnelVerified() == true ||
            (isAuthConn && (activeEp.contains("relay") || activeEp.contains("tunnel")))
        val relayOn = isRemoteRelayEnabled() && relayVerifiedLive

        for (dev in devList) {
            val discPeer = _discoveredPeers.value.firstOrNull { it.deviceId.equals(dev.deviceId, ignoreCase = true) }
            if (discPeer != null) {
                val discRoute = org.snow.network.TransportClassifier.classifyRoute(host = discPeer.ipAddress)
                orch.registerDiscovered(dev.deviceId, discRoute, discPeer.ipAddress, discPeer.port, discPeer.transferPort)
            }
            if (relayOn) {
                orch.markVerified(dev.deviceId, org.snow.network.TransportRoute.REMOTE_RELAY, host = "relay", port = 443, isActive = false)
            }
            if (isAuthConn && (authDevId == null || authDevId.equals(dev.deviceId, ignoreCase = true))) {
                val epHost = activeEp.substringBefore(":").ifBlank { dev.host }
                val activeRoute = org.snow.network.TransportClassifier.classifyRoute(host = epHost, mode = dev.connectionMode)
                orch.markVerified(dev.deviceId, activeRoute, host = epHost, port = dev.port, isActive = true)
            }
            nextMap[dev.deviceId] = orch.snapshotFor(dev.deviceId)
        }
        _transportSnapshots.value = nextMap
    }

    private suspend fun activateAndVerifyRemoteRelay(
        deviceId: String,
        mode: org.snow.network.TransportMode,
        orch: org.snow.network.TransportOrchestrator,
        reasonLabel: String
    ): Pair<Boolean, String> {
        val endpoint = getEffectiveRelayEndpointForHub()
        val validScheme = endpoint.startsWith("wss://") || endpoint.startsWith("ws://")
        if (endpoint.isBlank() || !validScheme) {
            val reason = "Remote relay endpoint is not configured or invalid."
            orch.markUnavailable(deviceId, org.snow.network.TransportRoute.REMOTE_RELAY, reason)
            _lastTransportError.value = reason
            refreshTransportSnapshot(deviceId)
            return false to reason
        }
        val verifier = relayActivationVerifierForTest
        val (verified, reason) = if (verifier != null) {
            verifier.invoke(endpoint, deviceId)
        } else {
            val svc = serviceRef
            if (svc == null) {
                false to "Connection service is offline; cannot verify Remote Relay."
            } else {
                svc.startRelayAndVerify(endpoint = endpoint, targetDeviceId = deviceId)
            }
        }
        if (!verified) {
            val err = reason.ifBlank { "Remote relay authentication or handshake failed." }
            orch.markUnavailable(deviceId, org.snow.network.TransportRoute.REMOTE_RELAY, err)
            _lastTransportError.value = err
            appendLog("WARN", TAG, "Remote Relay activation failed for $deviceId: $err")
            refreshTransportSnapshot(deviceId)
            return false to err
        }
        _lastTransportError.value = null
        val parsedUri = runCatching { java.net.URI(endpoint) }.getOrNull()
        val relayHost = parsedUri?.host?.takeIf { it.isNotBlank() } ?: "relay"
        val relayPort = parsedUri?.port?.takeIf { it in 1..65535 } ?: 443
        orch.markVerified(deviceId, org.snow.network.TransportRoute.REMOTE_RELAY, host = relayHost, port = relayPort, isActive = true)
        val (modeOk, modeMsg) = orch.setMode(deviceId, mode, reasonLabel)
        if (!modeOk) {
            _lastTransportError.value = modeMsg
            refreshTransportSnapshot(deviceId)
            return false to modeMsg
        }
        return true to "Remote relay authenticated and active"
    }

    suspend fun switchDeviceTransport(deviceId: String, requestedMode: String): Pair<Boolean, String> {
        val mode = org.snow.network.TransportMode.normalize(requestedMode)
            ?: return false to "Unsupported transport mode '$requestedMode'."
        val dev = _savedDevices.value.firstOrNull { it.deviceId == deviceId }
            ?: return false to "Device not found."

        val orch = activeTransportOrchestrator()
        refreshTransportSnapshot(deviceId)
        val svc = serviceRef
        val wsClient = svc?.client
        _lastTransportError.value = null

        if (mode.isSingleRouteOverride()) {
            val targetRoute = mode.targetRouteOrNull()!!
            orch.setSwitching(deviceId, true, "Verifying ${targetRoute.badge}")
            _transportSnapshots.value = _transportSnapshots.value.toMutableMap().apply {
                this[deviceId] = orch.snapshotFor(deviceId)
            }
            try {
                if (targetRoute == org.snow.network.TransportRoute.REMOTE_RELAY) {
                    val (ok, msg) = activateAndVerifyRemoteRelay(
                        deviceId = deviceId,
                        mode = mode,
                        orch = orch,
                        reasonLabel = "Manual switch to Remote"
                    )
                    if (!ok) {
                        return false to msg
                    }
                } else {
                    val candHost = when (targetRoute) {
                        org.snow.network.TransportRoute.USB -> "127.0.0.1"
                        org.snow.network.TransportRoute.HOTSPOT -> {
                            _discoveredPeers.value.firstOrNull {
                                it.deviceId.equals(deviceId, ignoreCase = true) &&
                                    org.snow.network.TransportClassifier.isHotspotHostOrHint(it.ipAddress)
                            }?.ipAddress
                                ?: dev.recentEndpoints.firstOrNull {
                                    org.snow.network.TransportClassifier.isHotspotHostOrHint(it.host)
                                }?.host
                                ?: dev.host.takeIf { org.snow.network.TransportClassifier.isHotspotHostOrHint(it) }
                                ?: ""
                        }
                        org.snow.network.TransportRoute.WIFI_LAN -> {
                            _discoveredPeers.value.firstOrNull {
                                it.deviceId.equals(deviceId, ignoreCase = true) &&
                                    org.snow.network.TransportClassifier.classifyRoute(host = it.ipAddress) == org.snow.network.TransportRoute.WIFI_LAN
                            }?.ipAddress
                                ?: dev.recentEndpoints.firstOrNull {
                                    org.snow.network.TransportClassifier.classifyRoute(host = it.host) == org.snow.network.TransportRoute.WIFI_LAN
                                }?.host
                                ?: dev.host.takeIf { org.snow.network.TransportClassifier.classifyRoute(host = it) == org.snow.network.TransportRoute.WIFI_LAN }
                                ?: ""
                        }
                        else -> ""
                    }
                    if (candHost.isBlank()) {
                        val reason = "No verified ${targetRoute.shortLabel} endpoint known."
                        orch.markUnavailable(deviceId, targetRoute, reason)
                        _lastTransportError.value = reason
                        return false to reason
                    }
                    if (wsClient == null) {
                        val reason = "Connection service is offline; cannot verify ${targetRoute.shortLabel}."
                        _lastTransportError.value = reason
                        return false to reason
                    }
                    val probeRes = wsClient.probeAndPromoteEndpoint(
                        newHost = candHost,
                        newPort = dev.port,
                        targetDeviceId = deviceId,
                        timeoutMs = 2_500L,
                        verifyPing = true
                    )
                    if (!probeRes.promoted) {
                        val reason = probeRes.error ?: "Verification failed for ${targetRoute.shortLabel}."
                        orch.markUnavailable(deviceId, targetRoute, reason)
                        _lastTransportError.value = reason
                        return false to reason
                    }
                    orch.markVerified(deviceId, targetRoute, host = candHost, port = dev.port, isActive = true)
                    orch.setMode(deviceId, mode, "Manual switch to ${targetRoute.shortLabel}")
                }
            } finally {
                orch.setSwitching(deviceId, false)
            }
        } else if (mode == org.snow.network.TransportMode.REMOTE_ONLY) {
            orch.setSwitching(deviceId, true, "Verifying Remote • Uses Data")
            _transportSnapshots.value = _transportSnapshots.value.toMutableMap().apply {
                this[deviceId] = orch.snapshotFor(deviceId)
            }
            try {
                val (ok, msg) = activateAndVerifyRemoteRelay(
                    deviceId = deviceId,
                    mode = mode,
                    orch = orch,
                    reasonLabel = "Mode updated to remote_only"
                )
                if (!ok) {
                    return false to msg
                }
                updateRemoteRelayConfig(true, getEffectiveRelayEndpointForHub())
            } finally {
                orch.setSwitching(deviceId, false)
            }
        } else {
            val (ok, msg) = orch.setMode(deviceId, mode, "Mode updated to ${mode.wireName}")
            if (!ok) {
                _lastTransportError.value = msg
                refreshTransportSnapshot(deviceId)
                return false to msg
            }
            if (mode == org.snow.network.TransportMode.LOCAL_ONLY) {
                svc?.stopRelay()
            } else if (mode == org.snow.network.TransportMode.AUTO && svc != null) {
                svc.promoteLocalRouteFromDiscoveryIfAvailable()
            }
        }

        val current = _savedDevices.value.toMutableList()
        val idx = current.indexOfFirst { it.deviceId == deviceId }
        if (idx >= 0) {
            current[idx] = current[idx].copy(connectionMode = mode.wireName)
            _savedDevices.value = current
            val prefsV2 = appContext.getSharedPreferences("snow_paired_devices_v2", Context.MODE_PRIVATE)
            prefsV2.edit().putString("devices_json", serializeSavedDevices(current)).apply()
        }
        refreshTransportSnapshot(deviceId)
        return true to "Switched to ${mode.wireName.uppercase()}"
    }

    fun updateDeviceConnectionMode(deviceId: String, mode: String) {
        val current = _savedDevices.value.toMutableList()
        val idx = current.indexOfFirst { it.deviceId == deviceId }
        if (idx >= 0) {
            current[idx] = current[idx].copy(connectionMode = mode)
            _savedDevices.value = current
            val prefsV2 = appContext.getSharedPreferences("snow_paired_devices_v2", Context.MODE_PRIVATE)
            prefsV2.edit().putString("devices_json", serializeSavedDevices(current)).apply()

            when (mode) {
                "local_only" -> {
                    serviceRef?.stopRelay()
                }
                "remote_only" -> {
                    val endpoint = getEffectiveRelayEndpointForHub()
                    updateRemoteRelayConfig(true, endpoint)
                    serviceRef?.startRelay(endpoint)
                }
                "auto" -> {
                    if (_connectionState.value == ConnectionState.DISCONNECTED) {
                        val endpoint = getEffectiveRelayEndpointForHub()
                        if (isRemoteRelayEnabled() && endpoint.isNotBlank()) {
                            serviceRef?.startRelay(endpoint)
                        }
                    } else {
                        serviceRef?.promoteLocalRouteFromDiscoveryIfAvailable()
                    }
                }
            }
            refreshTransportSnapshot(deviceId)
        }
    }

    // --- Telemetry & Status ---

    fun refreshPhoneTelemetry() {
        try {
            val intentFilter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
            val batteryStatus = appContext.registerReceiver(null, intentFilter)
            if (batteryStatus != null) {
                val level = batteryStatus.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
                val scale = batteryStatus.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
                val status = batteryStatus.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
                val isCharging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
                                status == BatteryManager.BATTERY_STATUS_FULL
                val tempTenths = batteryStatus.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1)
                val tempCelsius = if (tempTenths > 0) tempTenths / 10.0f else null

                val pct = if (level >= 0 && scale > 0) (level * 100) / scale else 0

                var ramTotal: Long? = null
                var ramAvail: Long? = null
                try {
                    val actManager = appContext.getSystemService(Context.ACTIVITY_SERVICE) as? android.app.ActivityManager
                    if (actManager != null) {
                        val memInfo = android.app.ActivityManager.MemoryInfo()
                        actManager.getMemoryInfo(memInfo)
                        ramTotal = memInfo.totalMem
                        ramAvail = memInfo.availMem
                    }
                } catch (_: Exception) {
                }

                var storageTotal: Long? = null
                var storageAvail: Long? = null
                try {
                    val stat = android.os.StatFs(android.os.Environment.getDataDirectory().path)
                    storageTotal = stat.totalBytes
                    storageAvail = stat.availableBytes
                } catch (_: Exception) {
                }

                _phoneTelemetry.value = PhoneTelemetry(
                    batteryPercent = pct,
                    isCharging = isCharging,
                    temperatureCelsius = tempCelsius,
                    isAvailable = true,
                    lastUpdated = System.currentTimeMillis(),
                    ramTotalBytes = ramTotal,
                    ramAvailableBytes = ramAvail,
                    storageTotalBytes = storageTotal,
                    storageAvailableBytes = storageAvail
                )
                return
            }
        } catch (e: Exception) {
            SafeLog.w(TAG, "Failed reading phone battery telemetry: ${e.message}")
        }
        _phoneTelemetry.value = PhoneTelemetry.UNAVAILABLE
    }

    fun queryPcStatus(onComplete: ((Boolean) -> Unit)? = null) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            onComplete?.invoke(false)
            return
        }

        client.sendRequest("desktop_status", emptyMap()) { resp ->
            repoScope.launch {
                if (resp.isSuccess) {
                    val data = resp.payload?.get("data") as? Map<*, *>
                    val battery = data?.get("battery") as? Map<*, *>
                    val batteryPct = (battery?.get("percent") as? Number)?.toInt()
                    val charging = battery?.get("charging") as? Boolean
                    val os = (data?.get("os_name") as? String)?.takeIf { it.isNotBlank() }
                        ?: (data?.get("os") as? String)?.takeIf { it.isNotBlank() }
                        ?: (data?.get("platform") as? String)
                    val hostname = data?.get("hostname") as? String
                    val cpuPct = (data?.get("cpu_percent") as? Number)?.toDouble()
                    val memPct = (data?.get("memory_percent") as? Number)?.toDouble()

                    _pcTelemetry.value = PcTelemetry(
                        isConnected = true,
                        batteryPercent = batteryPct,
                        isCharging = charging,
                        hostname = hostname,
                        os = os,
                        cpuPercent = cpuPct,
                        memoryPercent = memPct,
                        isAvailable = true,
                        lastUpdated = System.currentTimeMillis()
                    )
                    appendLog("INFO", TAG, "PC telemetry updated: $hostname ($os)")
                    onComplete?.invoke(true)
                } else {
                    appendLog("WARN", TAG, "Failed querying PC status: ${resp.payload?.get("error")}")
                    onComplete?.invoke(false)
                }
            }
        }
    }

    // --- Quick Actions & Clipboard ---

    var activePermissionProfile: String
        get() {
            val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
            return serviceRef?.capabilityDispatcher?.activePermissionProfile
                ?: prefs.getString(
                    PREF_KEY_PERMISSION_PROFILE,
                    prefs.getString("active_permission_profile", "full_control")
                )
                ?: "full_control"
        }
        set(value) {
            val canonical = normalizeAccessProfile(value)
            serviceRef?.capabilityDispatcher?.activePermissionProfile = canonical
            val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
            prefs.edit()
                .putString(PREF_KEY_PERMISSION_PROFILE, canonical)
                .putString("active_permission_profile", canonical)
                .apply()
            _permissionProfileState.value = canonical
            if (canonical != "full_control") {
                stopScreenShare()
                closeIncomingViewer()
            }
            appendLog("INFO", TAG, "Active permission profile updated to $canonical")
        }

    fun setAccessProfile(profileKey: String) {
        activePermissionProfile = profileKey
    }

    fun ringLocalPhone(durationSeconds: Int = 5) {
        repoScope.launch {
            try {
                val ringer = RingerHandler(appContext)
                val res = ringer.ringPhone(durationSeconds)
                appendLog("INFO", TAG, "Triggered local phone ringer: ${res["status"]}")
            } catch (e: Exception) {
                appendLog("ERROR", TAG, "Local phone ringer error: ${e.message}")
            }
        }
    }

    fun ringPhone(durationSeconds: Int = 5) {
        ringLocalPhone(durationSeconds)
    }

    fun ringPeerPhone(durationSeconds: Int = 5, onComplete: ((Boolean, String?) -> Unit)? = null) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            appendLog("WARN", TAG, "Cannot ring peer phone: not connected")
            onComplete?.invoke(false, "Not connected to peer.")
            return
        }
        repoScope.launch {
            try {
                client.sendRequest(
                    action = "ring_phone",
                    data = mapOf("duration_seconds" to durationSeconds)
                ) { response ->
                    val success = response.isSuccess
                    val err = response.error?.message
                    appendLog("INFO", TAG, "Ring peer phone result: isSuccess=$success, err=$err")
                    onComplete?.invoke(success, err)
                }
            } catch (e: Exception) {
                appendLog("ERROR", TAG, "Error ringing peer phone: ${e.message}")
                onComplete?.invoke(false, e.message)
            }
        }
    }

    fun sendMediaKey(action: String, value: Int? = null, onComplete: ((Boolean, String?) -> Unit)? = null) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            appendLog("WARN", TAG, "Cannot send media key: not connected")
            onComplete?.invoke(false, "Not connected.")
            return
        }
        val canonical = when (action.trim().lowercase()) {
            "play", "pause", "play_pause", "toggle" -> "play_pause"
            "next", "next_track" -> "next"
            "prev", "previous", "previous_track" -> "previous"
            "volume_up", "vol_up" -> "volume_up"
            "volume_down", "vol_down" -> "volume_down"
            "volume", "volume_set" -> "volume_set"
            "mute", "unmute", "toggle_mute", "volume_mute" -> "volume_mute"
            "stop" -> "stop"
            else -> action.lowercase()
        }
        val dataPayload = mutableMapOf<String, Any>("action" to canonical)
        if (canonical == "volume_set" && value != null) {
            dataPayload["value"] = value.coerceIn(0, 100)
        }
        repoScope.launch {
            try {
                client.sendRequest(
                    action = "media_control",
                    data = dataPayload
                ) { response ->
                    val success = response.isSuccess
                    val err = response.error?.message
                    appendLog("INFO", TAG, "Media control '$canonical' result: isSuccess=$success, err=$err")
                    onComplete?.invoke(success, err)
                }
            } catch (e: Exception) {
                appendLog("ERROR", TAG, "Error sending media key: ${e.message}")
                onComplete?.invoke(false, e.message)
            }
        }
    }

    fun shareLink(url: String?, text: String?, onComplete: ((Boolean, String?) -> Unit)? = null) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            appendLog("WARN", TAG, "Cannot share link: not connected")
            onComplete?.invoke(false, "Not connected.")
            return
        }
        if (url.isNullOrBlank() && text.isNullOrBlank()) {
            onComplete?.invoke(false, "Both URL and text cannot be empty.")
            return
        }
        repoScope.launch {
            try {
                val data = mutableMapOf<String, Any>()
                if (!url.isNullOrBlank()) data["url"] = url.trim()
                if (!text.isNullOrBlank()) data["text"] = text.trim()
                client.sendRequest(
                    action = "share_link",
                    data = data
                ) { response ->
                    val success = response.isSuccess
                    val err = response.error?.message
                    appendLog("INFO", TAG, "Share link result: isSuccess=$success, err=$err")
                    onComplete?.invoke(success, err)
                }
            } catch (e: Exception) {
                appendLog("ERROR", TAG, "Error sharing link: ${e.message}")
                onComplete?.invoke(false, e.message)
            }
        }
    }

    fun triggerCameraCapture(onComplete: ((Boolean, String?) -> Unit)? = null) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            appendLog("WARN", TAG, "Cannot trigger camera: not connected")
            onComplete?.invoke(false, "Not connected.")
            return
        }
        repoScope.launch {
            try {
                client.sendRequest(
                    action = "camera_capture",
                    data = emptyMap()
                ) { response ->
                    val success = response.isSuccess
                    val err = response.error?.message
                    appendLog("INFO", TAG, "Camera capture result: isSuccess=$success, err=$err")
                    onComplete?.invoke(success, err)
                }
            } catch (e: Exception) {
                appendLog("ERROR", TAG, "Error triggering camera capture: ${e.message}")
                onComplete?.invoke(false, e.message)
            }
        }
    }

    fun lockPc(onComplete: (Boolean, String?) -> Unit) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            onComplete(false, "Desktop not connected.")
            return
        }

        appendLog("INFO", TAG, "Requesting PC screen lock...")
        client.sendRequest("desktop_app_launch", mapOf("app_name" to "lock_screen")) { resp ->
            repoScope.launch {
                if (resp.isSuccess) {
                    appendLog("INFO", TAG, "PC screen locked successfully.")
                    onComplete(true, null)
                } else {
                    val err = resp.payload?.get("error") as? String ?: "Failed locking PC"
                    appendLog("ERROR", TAG, err)
                    onComplete(false, err)
                }
            }
        }
    }

    fun launchWindowsApp(appName: String, onComplete: (Boolean, String?) -> Unit) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            onComplete(false, "Desktop core is not connected.")
            return
        }

        val cleanName = appName.trim()
        if (cleanName.isEmpty()) {
            onComplete(false, "Application target cannot be empty.")
            return
        }

        appendLog("INFO", TAG, "Launching Windows application: $cleanName")
        client.sendRequest("desktop_app_launch", mapOf("app_name" to cleanName)) { resp ->
            repoScope.launch {
                if (resp.isSuccess) {
                    appendLog("INFO", TAG, "Windows app launched successfully: $cleanName")
                    onComplete(true, null)
                } else {
                    val err = resp.payload?.get("error") as? String ?: "Failed launching application: $cleanName"
                    appendLog("ERROR", TAG, err)
                    onComplete(false, err)
                }
            }
        }
    }

    private var lastClipboardHash: String? = null
    private val imageClipboardLock = Any()
    @Volatile
    private var lastImageClipboardSha256: String? = null
    @Volatile
    private var lastImageClipboardCanonicalSha256: String? = null

    internal var canonicalDigestComputerOverrideForTest: ((File) -> String?)? = null

    internal fun computeCanonicalImageDigestForFile(file: File?): String? {
        if (file == null || !file.isFile || file.length() <= 0L) return null
        val override = canonicalDigestComputerOverrideForTest
        if (override != null) {
            return override.invoke(file)?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
        }
        return org.snow.capabilities.CanonicalImageDigest.computeFromFile(file)
    }

    @JvmOverloads
    fun recordIncomingClipboardImageSha256(sha256: String?, canonicalSha256: String? = null) {
        val normSha = sha256?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
        val normCanon = canonicalSha256?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
        if (normSha == null && normCanon == null) return
        synchronized(imageClipboardLock) {
            if (normSha != null) {
                lastImageClipboardSha256 = normSha
                lastImageClipboardCanonicalSha256 = normCanon
            } else {
                lastImageClipboardCanonicalSha256 = normCanon
            }
        }
    }

    fun getLastImageClipboardSha256(): String? = synchronized(imageClipboardLock) {
        lastImageClipboardSha256
    }

    fun getLastImageClipboardCanonicalSha256(): String? = synchronized(imageClipboardLock) {
        lastImageClipboardCanonicalSha256
    }

    @JvmOverloads
    fun isDuplicateImageClipboard(sha256: String?, canonicalSha256: String? = null): Boolean {
        val normSha = sha256?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
        val normCanon = canonicalSha256?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
        if (normSha == null && normCanon == null) return false
        return synchronized(imageClipboardLock) {
            (normSha != null && lastImageClipboardSha256 == normSha) ||
                (normCanon != null && lastImageClipboardCanonicalSha256 == normCanon)
        }
    }

    fun resetImageClipboardEchoGuard() {
        synchronized(imageClipboardLock) {
            lastImageClipboardSha256 = null
            lastImageClipboardCanonicalSha256 = null
        }
    }

    fun isOwnFileProviderAuthority(scheme: String?, authority: String?): Boolean {
        val ownAuthority = "${appContext.packageName}.fileprovider"
        return scheme.equals("content", ignoreCase = true) && authority.equals(ownAuthority, ignoreCase = true)
    }

    fun isOwnFileProviderUriString(uriString: String?): Boolean {
        val clean = uriString?.trim() ?: return false
        val expectedPrefix = "content://${appContext.packageName}.fileprovider"
        return clean.equals(expectedPrefix, ignoreCase = true) ||
            clean.startsWith("$expectedPrefix/", ignoreCase = true) ||
            clean.startsWith("$expectedPrefix?", ignoreCase = true)
    }

    fun isOwnFileProviderUri(uri: Uri?): Boolean {
        if (uri == null) return false
        val scheme = try { uri.scheme } catch (_: Exception) { null }
        val authority = try { uri.authority } catch (_: Exception) { null }
        if (!scheme.isNullOrBlank() || !authority.isNullOrBlank()) {
            return isOwnFileProviderAuthority(scheme, authority)
        }
        return isOwnFileProviderUriString(try { uri.toString() } catch (_: Exception) { null })
    }

    private fun clipboardAckPrefs() =
        appContext.getSharedPreferences(PREFS_CLIPBOARD_ACK, Context.MODE_PRIVATE)

    fun getLastAckedClipboardSeq(): Long =
        clipboardAckPrefs().getLong(PREF_KEY_CLIP_LAST_ACKED_SEQ, 0L)

    fun hasCommittedClipboardEvent(eventId: String?): Boolean {
        val clean = eventId?.trim() ?: return false
        if (clean.isEmpty()) return false
        return clipboardAckPrefs().getString(PREF_KEY_CLIP_LAST_COMMITTED_EVENT, null) == clean
    }

    fun markCommittedClipboardEvent(eventId: String?, seq: Long) {
        val prefs = clipboardAckPrefs()
        val editor = prefs.edit()
        val clean = eventId?.trim()
        if (!clean.isNullOrEmpty()) {
            editor.putString(PREF_KEY_CLIP_LAST_COMMITTED_EVENT, clean)
        }
        val currentSeq = prefs.getLong(PREF_KEY_CLIP_LAST_COMMITTED_SEQ, 0L)
        if (seq > currentSeq) {
            editor.putLong(PREF_KEY_CLIP_LAST_COMMITTED_SEQ, seq)
        }
        editor.apply()
    }

    fun isSelfOriginClipboardEvent(originDeviceId: String?): Boolean {
        val clean = originDeviceId?.trim() ?: return false
        return clean.isNotEmpty() && clean == identity.deviceId.trim()
    }

    internal var clipboardAckObserverForTest: ((Long, String) -> Unit)? = null

    fun sendClipboardAck(
        seq: Long,
        eventId: String,
        clientOverride: org.snow.network.SnowWebSocketClient? = null
    ): Boolean {
        val cleanEventId = eventId.trim()
        if (seq <= 0L || cleanEventId.isEmpty()) {
            return false
        }
        val prefs = clipboardAckPrefs()
        val currentAcked = prefs.getLong(PREF_KEY_CLIP_LAST_ACKED_SEQ, 0L)
        if (seq > currentAcked) {
            prefs.edit().putLong(PREF_KEY_CLIP_LAST_ACKED_SEQ, seq).apply()
        }
        clipboardAckObserverForTest?.invoke(seq, cleanEventId)
        val client = clientOverride ?: serviceRef?.client ?: return (clipboardAckObserverForTest != null)
        client.sendRequest(
            "clipboard_ack",
            mapOf(
                "seq" to seq,
                "event_id" to cleanEventId,
                "last_acked_seq" to seq,
                "last_acked_event_id" to cleanEventId
            )
        ) { resp ->
            if (!resp.isSuccess) {
                SafeLog.w(TAG, "clipboard_ack rejected by host for seq=$seq: ${resp.error?.message}")
            }
        }
        return true
    }

    suspend fun handleIncomingClipboardFilePush(
        data: Map<String, Any?>,
        transferClient: FileTransferClient,
        serverHost: String,
        defaultTransferPort: Int = 8766,
        safManagerOverride: SafFolderManager? = null,
        clientOverride: org.snow.network.SnowWebSocketClient? = null,
        notifyUser: Boolean = true
    ): Result<List<String>> = withContext(Dispatchers.IO) {
        val originId = data["origin_device_id"] as? String
        if (isSelfOriginClipboardEvent(originId)) {
            return@withContext Result.success(emptyList())
        }
        val eventId = (data["event_id"] as? String)?.trim() ?: ""
        val seq = (data["seq"] as? Number)?.toLong() ?: 0L
        val rawFiles = data["files"]
        val parsed = validateIncomingFileBundlePayload(rawFiles).getOrElse { err ->
            return@withContext Result.failure(err)
        }
        return@withContext applyRemoteClipboardBundle(
            entries = parsed,
            transferClient = transferClient,
            serverHost = serverHost,
            defaultTransferPort = defaultTransferPort,
            eventId = eventId,
            seq = seq,
            safManagerOverride = safManagerOverride,
            clientOverride = clientOverride,
            notifyUser = notifyUser
        )
    }

    suspend fun applyRemoteClipboardBundle(
        entries: List<ClipboardFileEntryDto>,
        transferClient: FileTransferClient,
        serverHost: String,
        defaultTransferPort: Int = 8766,
        eventId: String = "",
        seq: Long = 0L,
        safManagerOverride: SafFolderManager? = null,
        clientOverride: org.snow.network.SnowWebSocketClient? = null,
        notifyUser: Boolean = true
    ): Result<List<String>> = withContext(Dispatchers.IO) {
        if (entries.isEmpty() || entries.size > MAX_CLIPBOARD_BUNDLE_FILES) {
            return@withContext Result.failure(IllegalArgumentException("Bundle must contain 1..5 files."))
        }
        if (serverHost.isBlank()) {
            return@withContext Result.failure(IllegalStateException("Desktop host is unknown."))
        }
        if (eventId.isNotBlank() && hasCommittedClipboardEvent(eventId)) {
            if (seq > 0L) {
                sendClipboardAck(seq, eventId, clientOverride)
            }
            return@withContext Result.success(emptyList())
        }

        val saf = safManagerOverride ?: safFolderManager
        val stagingDir = saf.getStagingDir()
        val stagedPairs = mutableListOf<Pair<File, String>>()
        var totalDownloadedBytes = 0L

        for ((idx, entry) in entries.withIndex()) {
            val transferId = entry.transferId?.takeIf { it.isNotBlank() }
                ?: return@withContext Result.failure(IllegalArgumentException("Missing transfer_id for ${entry.name}"))
            val safeName = try {
                org.snow.capabilities.ClipboardHandler.sanitizeClipboardFileName(entry.name)
            } catch (e: IllegalArgumentException) {
                return@withContext Result.failure(e)
            }
            val safePrefix = transferId.replace(Regex("[^A-Za-z0-9_-]"), "_")
            val stagedFile = File(stagingDir, "${safePrefix}_${idx}_$safeName")
            val dlRes = transferClient.downloadFile(
                serverHost = serverHost,
                transferPort = entry.transferPort.takeIf { it > 0 } ?: defaultTransferPort,
                transferId = transferId,
                destinationFile = stagedFile,
                expectedSha256 = entry.sha256
            )
            if (dlRes !is FileTransferClient.TransferResult.Success) {
                val errMsg = (dlRes as? FileTransferClient.TransferResult.Error)?.message
                    ?: "Failed downloading clipboard file '${safeName}'"
                return@withContext Result.failure(IllegalStateException(errMsg))
            }
            val actualLen = dlRes.file.length()
            if (actualLen > MAX_CLIPBOARD_FILE_BYTES) {
                dlRes.file.delete()
                return@withContext Result.failure(
                    IllegalStateException("Downloaded file '$safeName' exceeds 15 MiB limit.")
                )
            }
            totalDownloadedBytes += actualLen
            if (totalDownloadedBytes > MAX_CLIPBOARD_BUNDLE_BYTES) {
                dlRes.file.delete()
                return@withContext Result.failure(
                    IllegalStateException("Downloaded clipboard bundle exceeds 15 MiB limit.")
                )
            }
            stagedPairs.add(Pair(dlRes.file, safeName))
        }

        val commitRes = saf.commitVerifiedDownloadBatch(stagedPairs)
        if (commitRes.isFailure) {
            return@withContext commitRes
        }

        val savedNames = commitRes.getOrNull().orEmpty()
        markCommittedClipboardEvent(eventId, seq)
        if (notifyUser && savedNames.isNotEmpty()) {
            try {
                val label = if (savedNames.size == 1) {
                    "Saved ${savedNames[0]}"
                } else {
                    "Saved ${savedNames.size} files: ${savedNames.take(3).joinToString(", ")}"
                }
                val openIntent = Intent(appContext, org.snow.ui.MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                }
                org.snow.capabilities.ActionNotificationHelper.postActionNotification(
                    context = appContext,
                    title = "Clipboard Files Received",
                    content = label,
                    intent = openIntent,
                    isSilent = true
                )
            } catch (_: Exception) {}
        }
        if (seq > 0L && eventId.isNotBlank()) {
            sendClipboardAck(seq, eventId, clientOverride)
        }
        Result.success(savedNames)
    }

    fun recordIncomingClipboardText(text: String?) {
        if (!text.isNullOrEmpty()) {
            try {
                val md = java.security.MessageDigest.getInstance("SHA-256")
                lastClipboardHash = md.digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
            } catch (_: Exception) {}
        }
    }

    fun isDuplicateClipboard(text: String): Boolean {
        return try {
            val md = java.security.MessageDigest.getInstance("SHA-256")
            val hash = md.digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
            if (hash == lastClipboardHash) {
                true
            } else {
                lastClipboardHash = hash
                false
            }
        } catch (_: Exception) {
            false
        }
    }

    fun isConnectedAndAuthenticated(): Boolean {
        return _connectionState.value == ConnectionState.CONNECTED && _authState.value is AuthState.Authenticated
    }

    fun checkAndSyncForegroundClipboard() {
        org.snow.capabilities.ClipboardHandler.isAppInForeground = true
        org.snow.capabilities.ClipboardHandler.isUserIntentGranted = true

        val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(PREF_KEY_INSTANT_SYNC, true)) return
        if (!isConnectedAndAuthenticated()) return

        try {
            val cm = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
            val clip = cm.primaryClip ?: return
            if (clip.itemCount == 0) return

            val item = clip.getItemAt(0)
            val uri = item.uri
            if (isOwnFileProviderUri(uri)) {
                appendLog("DEBUG", TAG, "Skipping foreground clipboard sync for own FileProvider URI.")
                return
            }
            val clipDescriptionMime = clip.description?.let { desc ->
                (0 until desc.mimeTypeCount).map { desc.getMimeType(it) }.firstOrNull { it.startsWith("image/") }
            }
            val resolvedMime = clipDescriptionMime ?: uri?.let { appContext.contentResolver.getType(it) }
            val isImage = (resolvedMime?.startsWith("image/") == true) || (uri != null && (clipDescriptionMime != null || appContext.contentResolver.getType(uri)?.startsWith("image/") == true))

            if (isImage && uri != null) {
                // Image on clipboard (own FileProvider URI already excluded above; push checks raw + canonical SHA-256)
                pushCurrentClipboard(userInitiated = false) { success, _ ->
                    if (success) {
                        appendLog("INFO", TAG, "Auto-synced foreground image to PC clipboard.")
                    }
                }
                return
            }

            val text = item.text?.toString() ?: item.coerceToText(appContext)?.toString()
            if (!text.isNullOrBlank() && !isDuplicateClipboard(text)) {
                appendLog("INFO", TAG, "Auto-syncing foreground text to PC clipboard...")
                pushClipboard(text) { success, _ ->
                    if (success) {
                        appendLog("INFO", TAG, "Auto-synced text to PC clipboard: ${text.take(20)}...")
                    }
                }
            }
        } catch (e: Exception) {
            SafeLog.w(TAG, "Foreground clipboard check failed: ${e.message}")
        }
    }

    private var cachedWallpaperBitmap: android.graphics.Bitmap? = null
    private var cachedWallpaperBytes: ByteArray? = null
    private var cachedWallpaperEtag: String? = null

    fun invalidateWallpaperCache() {
        cachedWallpaperBytes = null
        cachedWallpaperEtag = null
        cachedWallpaperBitmap = null
        _desktopWallpaper.value = null
    }

    fun refreshDesktopWallpaper() {
        repoScope.launch {
            loadDesktopWallpaper()
        }
    }

    suspend fun loadDesktopWallpaper(): android.graphics.Bitmap? {
        val targetHost = connectedHost.ifBlank { serviceRef?.client?.currentTargetHost ?: "" }
        if (targetHost.isBlank() || _connectionState.value != ConnectionState.CONNECTED) {
            return null
        }
        val transferClient = _fileTransferClient ?: serviceRef?.transferClient ?: return null
        return when (val result = transferClient.getDesktopWallpaper(targetHost, 8766, cachedWallpaperEtag)) {
            is FileTransferClient.WallpaperResult.Updated -> {
                cachedWallpaperBytes = result.bytes
                cachedWallpaperEtag = result.etag
                val bmp = android.graphics.BitmapFactory.decodeByteArray(result.bytes, 0, result.bytes.size)
                cachedWallpaperBitmap = bmp
                _desktopWallpaper.value = bmp
                bmp
            }
            is FileTransferClient.WallpaperResult.NotModified -> {
                (cachedWallpaperBitmap ?: cachedWallpaperBytes?.let {
                    val bmp = android.graphics.BitmapFactory.decodeByteArray(it, 0, it.size)
                    cachedWallpaperBitmap = bmp
                    bmp
                })?.also { _desktopWallpaper.value = it }
            }
            is FileTransferClient.WallpaperResult.Unavailable -> {
                invalidateWallpaperCache()
                null
            }
        }
    }

    @JvmOverloads
    fun uploadScreenshot(
        uri: Uri,
        displayName: String,
        size: Long,
        userInitiated: Boolean = false,
        onComplete: ((Boolean, String?) -> Unit)? = null
    ) {
        val client = serviceRef?.client
        val targetHost = client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
        val transferClient = if (isConnectedAndAuthenticated()) resolveOrCreateTransferClient(requireConnectedAuth = false) else (_fileTransferClient ?: serviceRef?.transferClient)

        if (client == null || !isConnectedAndAuthenticated() || transferClient == null) {
            onComplete?.invoke(false, "Desktop not connected or transfer client not ready.")
            return
        }

        repoScope.launch(Dispatchers.IO) {
            var toCleanup: File? = null
            try {
                val cacheDir = File(appContext.cacheDir, "screenshots")
                val stagedFile = SafeStagingManager.createStagedFile(cacheDir, displayName)
                toCleanup = stagedFile

                appContext.contentResolver.openInputStream(uri)?.use { input ->
                    stagedFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
                val actualSize = stagedFile.length()
                if (actualSize <= 0L) {
                    SafeStagingManager.cleanupStagedFile(stagedFile)
                    toCleanup = null
                    repoScope.launch(Dispatchers.Main) {
                        onComplete?.invoke(false, "Screenshot data unreadable or empty.")
                    }
                    return@launch
                }
                uploadStagedScreenshotFile(
                    stagedFile = stagedFile,
                    transferClient = transferClient,
                    targetHost = targetHost,
                    client = client,
                    userInitiated = userInitiated,
                    onComplete = onComplete
                )
                toCleanup = null
            } catch (e: Exception) {
                repoScope.launch(Dispatchers.Main) {
                    appendLog("ERROR", TAG, "Screenshot upload exception: ${e.message}")
                    onComplete?.invoke(false, e.message)
                }
            } finally {
                SafeStagingManager.cleanupStagedFile(toCleanup)
            }
        }
    }

    internal suspend fun uploadStagedScreenshotFile(
        stagedFile: File,
        transferClient: FileTransferClient,
        targetHost: String,
        client: org.snow.network.SnowWebSocketClient,
        userInitiated: Boolean = false,
        onComplete: ((Boolean, String?) -> Unit)? = null
    ) {
        try {
            val safeName = stagedFile.name
            val actualSize = stagedFile.length()
            val localSha256 = FileTransferClient.computeSha256(stagedFile)
            val localCanonical = computeCanonicalImageDigestForFile(stagedFile)
            if (!userInitiated && isDuplicateImageClipboard(localSha256, localCanonical)) {
                appendLog("DEBUG", TAG, "Skipping duplicate screenshot upload (matches last synced raw/canonical SHA-256).")
                repoScope.launch(Dispatchers.Main) {
                    onComplete?.invoke(true, "Screenshot already synced")
                }
                return
            }

            appendLog("INFO", TAG, "Uploading screenshot '$safeName' ($actualSize bytes) to PC...")
            val upRes = transferClient.uploadFile(
                serverHost = targetHost,
                transferPort = 8766,
                file = stagedFile
            )
            SafeStagingManager.cleanupStagedFile(stagedFile)

            val dispatchReq: (String, Map<String, Any?>, (org.snow.protocol.SnowMessage) -> Unit) -> Unit = { action, payload, cb ->
                val override = clipboardRequestDispatchOverrideForTest
                if (override != null) {
                    override.invoke(action, payload, cb)
                } else {
                    client.sendRequest(action, payload, cb)
                }
            }

            when (upRes) {
                is FileTransferClient.TransferResult.Success -> {
                    val reqPayload = buildMap<String, Any?> {
                        put("type", "image")
                        put("transfer_id", upRes.transferId)
                        put("sha256", upRes.sha256)
                        put("file_name", safeName)
                        if (!localCanonical.isNullOrBlank()) put("canonical_sha256", localCanonical)
                        if (userInitiated) put("user_initiated", true)
                    }
                    dispatchReq("desktop_clipboard_set", reqPayload) { resp ->
                        repoScope.launch(Dispatchers.Main) {
                            if (resp.isSuccess) {
                                recordIncomingClipboardImageSha256(upRes.sha256, localCanonical)
                                appendLog("INFO", TAG, "Screenshot synced to PC clipboard: $safeName")
                                try {
                                    Toast.makeText(appContext, "Screenshot synced to PC clipboard ❄️", Toast.LENGTH_SHORT).show()
                                } catch (_: Exception) {
                                }
                                onComplete?.invoke(true, safeName)
                            } else {
                                val err = resp.payload?.get("error") as? String ?: "Failed setting image on PC"
                                appendLog("WARN", TAG, "Failed setting screenshot on PC clipboard: $err")
                                onComplete?.invoke(false, err)
                            }
                        }
                    }
                }
                is FileTransferClient.TransferResult.Duplicate -> {
                    val reqPayload = buildMap<String, Any?> {
                        put("type", "image")
                        put("sha256", upRes.sha256)
                        put("file_name", safeName)
                        if (!localCanonical.isNullOrBlank()) put("canonical_sha256", localCanonical)
                        if (userInitiated) put("user_initiated", true)
                    }
                    dispatchReq("desktop_clipboard_set", reqPayload) { resp ->
                        repoScope.launch(Dispatchers.Main) {
                            if (resp.isSuccess) {
                                recordIncomingClipboardImageSha256(upRes.sha256, localCanonical)
                                appendLog("INFO", TAG, "Screenshot synced to PC clipboard: $safeName")
                                try {
                                    Toast.makeText(appContext, "Screenshot synced to PC clipboard ❄️", Toast.LENGTH_SHORT).show()
                                } catch (_: Exception) {
                                }
                                onComplete?.invoke(true, safeName)
                            } else {
                                val err = resp.payload?.get("error") as? String ?: "Failed setting image on PC"
                                appendLog("WARN", TAG, "Failed setting screenshot on PC clipboard: $err")
                                onComplete?.invoke(false, err)
                            }
                        }
                    }
                }
                is FileTransferClient.TransferResult.Error -> {
                    repoScope.launch(Dispatchers.Main) {
                        appendLog("ERROR", TAG, "Screenshot upload failed: ${upRes.message}")
                        onComplete?.invoke(false, upRes.message)
                    }
                }
            }
        } finally {
            SafeStagingManager.cleanupStagedFile(stagedFile)
        }
    }

    fun pushLatestRecentScreenshotIfAvailable(onComplete: (Boolean, String?) -> Unit) {
        val client = serviceRef?.client
        val targetHost = client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
        val transferClient = if (isConnectedAndAuthenticated()) resolveOrCreateTransferClient(requireConnectedAuth = false) else (_fileTransferClient ?: serviceRef?.transferClient)

        if (client == null || !isConnectedAndAuthenticated() || transferClient == null) {
            onComplete(false, "Desktop not connected or transfer client not ready.")
            return
        }

        repoScope.launch(Dispatchers.IO) {
            try {
                val projection = arrayOf(
                    MediaStore.Images.Media._ID,
                    MediaStore.Images.Media.DISPLAY_NAME,
                    MediaStore.Images.Media.DATE_ADDED,
                    MediaStore.Images.Media.DATE_MODIFIED,
                    MediaStore.Images.Media.SIZE
                )
                val sortOrder = "${MediaStore.Images.Media.DATE_MODIFIED} DESC, ${MediaStore.Images.Media.DATE_ADDED} DESC"
                val cursor = appContext.contentResolver.query(
                    MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
                    projection,
                    null,
                    null,
                    sortOrder
                )
                if (cursor == null || !cursor.moveToFirst()) {
                    cursor?.close()
                    repoScope.launch(Dispatchers.Main) { onComplete(false, "No screenshots found.") }
                    return@launch
                }
                var foundUri: Uri? = null
                var foundName: String? = null
                var foundSize: Long = 0L
                val nowSec = System.currentTimeMillis() / 1000L

                cursor.use { c ->
                    val idCol = c.getColumnIndexOrThrow(MediaStore.Images.Media._ID)
                    val nameCol = c.getColumnIndexOrThrow(MediaStore.Images.Media.DISPLAY_NAME)
                    val sizeCol = c.getColumnIndexOrThrow(MediaStore.Images.Media.SIZE)
                    val dateCol = c.getColumnIndexOrThrow(MediaStore.Images.Media.DATE_ADDED)

                    do {
                        val name = c.getString(nameCol) ?: ""
                        val size = c.getLong(sizeCol)
                        val date = c.getLong(dateCol)
                        val isRecent = (nowSec - date) <= 300 // within 5 minutes
                        val isScreenshot = name.contains("screenshot", ignoreCase = true) || name.startsWith("Screenshot_", ignoreCase = true)
                        if (size > 0L && (isScreenshot || isRecent)) {
                            val id = c.getLong(idCol)
                            foundUri = Uri.withAppendedPath(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, id.toString())
                            foundName = name
                            foundSize = size
                            break
                        }
                    } while (c.moveToNext())
                }

                if (foundUri != null && foundName != null) {
                    uploadScreenshot(foundUri!!, foundName!!, foundSize, userInitiated = true, onComplete = onComplete)
                } else {
                    repoScope.launch(Dispatchers.Main) { onComplete(false, "No recent screenshot found.") }
                }
            } catch (e: Exception) {
                repoScope.launch(Dispatchers.Main) { onComplete(false, "Screenshot error: ${e.message}") }
            }
        }
    }

    fun setPendingScreenShareTargets(targetIds: List<String>) {
        _pendingScreenShareTargets.value = targetIds.filter { it.isNotBlank() }.distinct()
    }

    fun getEligibleScreenTargets(): List<ScreenShareTarget> {
        if (!isSessionTrulyConnected(_connectionState.value, _authState.value)) {
            return emptyList()
        }
        val activeBadge = resolveTransportBadge(_connectedEndpoint.value)
        val targets = mutableListOf<ScreenShareTarget>()
        val currentAuth = _authState.value as? AuthState.Authenticated
        val activePeerId = currentAuth?.peerDeviceId?.takeIf { it.isNotBlank() }
        val activePeerName = currentAuth?.peerDeviceName?.takeIf { it.isNotBlank() }
        val activePeerType = currentAuth?.peerDeviceType?.takeIf { it.isNotBlank() } ?: "windows"

        if (activePermissionProfile.trim().lowercase() == "full_control" && activePeerId != null) {
            targets.add(
                ScreenShareTarget(
                    deviceId = activePeerId,
                    deviceName = activePeerName ?: "Connected Host",
                    platform = activePeerType,
                    routeBadge = activeBadge
                )
            )
        }
        _savedDevices.value.forEach { dev ->
            if (dev.deviceId != activePeerId &&
                normalizeAccessProfile(dev.permissionProfile) == "full_control" &&
                targets.none { it.deviceId == dev.deviceId }
            ) {
                val badge = resolveTransportBadge(if (dev.port > 0) "${dev.host}:${dev.port}" else dev.host)
                targets.add(
                    ScreenShareTarget(
                        deviceId = dev.deviceId,
                        deviceName = dev.deviceName,
                        platform = dev.deviceType,
                        routeBadge = badge
                    )
                )
            }
        }
        return targets
    }

    fun selectIncomingSender(senderId: String) {
        if (_incomingScreenStreams.value.containsKey(senderId)) {
            _selectedIncomingSenderId.value = senderId
            ensureIncomingStreamPolling(active = true)
        }
    }

    fun refreshIncomingStreamsOnce() {
        val client = serviceRef?.client ?: return
        val tc = _fileTransferClient ?: serviceRef?.transferClient ?: return
        if (!isSessionTrulyConnected(_connectionState.value, _authState.value)) return
        if (activePermissionProfile.trim().lowercase() != "full_control") return
        val host = client.currentTargetHost.takeIf { it.isNotBlank() } ?: connectedHost
        if (host.isBlank()) return

        repoScope.launch(Dispatchers.IO) {
            val senders = tc.getScreenSenders(host, 8766)
                .filter { it.senderDeviceId != identity.deviceId }
            if (senders.isEmpty()) {
                val currentStreams = _incomingScreenStreams.value.toMutableMap()
                if (currentStreams.isNotEmpty()) {
                    currentStreams.clear()
                    _incomingScreenStreams.value = emptyMap()
                    _selectedIncomingSenderId.value = null
                }
                return@launch
            }

            ensureIncomingStreamPolling(active = true)
            val chosen = _selectedIncomingSenderId.value?.takeIf { id -> senders.any { it.senderDeviceId == id } }
                ?: senders.first().senderDeviceId
            _selectedIncomingSenderId.value = chosen

            val frame = tc.getScreenFrame(host, 8766, chosen)
            if (frame != null) {
                val info = senders.firstOrNull { it.senderDeviceId == chosen }
                val badge = info?.routeBadge?.takeIf { it.isNotBlank() } ?: resolveTransportBadge(_connectedEndpoint.value)
                val updated = _incomingScreenStreams.value.toMutableMap()
                updated[chosen] = IncomingScreenStream(
                    senderId = chosen,
                    senderName = frame.senderName.ifBlank { info?.senderName ?: chosen },
                    senderPlatform = info?.senderPlatform ?: "windows",
                    sessionId = frame.sessionId,
                    frameSeq = frame.frameSeq,
                    width = info?.frameWidth ?: 0,
                    height = info?.frameHeight ?: 0,
                    fps = info?.fps ?: 4.0f,
                    routeBadge = badge,
                    timestampMs = System.currentTimeMillis(),
                    frameBytes = frame.bytes
                )
                _incomingScreenStreams.value = updated
            }
        }
    }

    fun ensureIncomingStreamPolling(active: Boolean) {
        if (!active) {
            incomingStreamPollJob?.cancel()
            incomingStreamPollJob = null
            return
        }
        if (incomingStreamPollJob?.isActive == true) return
        incomingStreamPollJob = repoScope.launch(Dispatchers.IO) {
            while (kotlinx.coroutines.currentCoroutineContext()[Job]?.isActive == true) {
                if (!isSessionTrulyConnected(_connectionState.value, _authState.value)) {
                    _incomingScreenStreams.value = emptyMap()
                    _selectedIncomingSenderId.value = null
                    break
                }
                val host = serviceRef?.client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
                val tc = _fileTransferClient ?: serviceRef?.transferClient
                if (host.isNotBlank() && tc != null) {
                    val senders = tc.getScreenSenders(host, 8766)
                        .filter { it.senderDeviceId != identity.deviceId }
                    if (senders.isEmpty()) {
                        if (_incomingScreenStreams.value.isNotEmpty()) {
                            _incomingScreenStreams.value = emptyMap()
                            _selectedIncomingSenderId.value = null
                        }
                        break
                    }
                    val chosen = _selectedIncomingSenderId.value?.takeIf { id -> senders.any { it.senderDeviceId == id } }
                        ?: senders.first().senderDeviceId
                    _selectedIncomingSenderId.value = chosen
                    val frame = tc.getScreenFrame(host, 8766, chosen)
                    if (frame != null) {
                        val info = senders.firstOrNull { it.senderDeviceId == chosen }
                        val badge = info?.routeBadge?.takeIf { it.isNotBlank() } ?: resolveTransportBadge(_connectedEndpoint.value)
                        val updated = _incomingScreenStreams.value.toMutableMap()
                        val prev = updated[chosen]
                        if (prev == null || prev.sessionId != frame.sessionId || frame.frameSeq >= prev.frameSeq) {
                            updated[chosen] = IncomingScreenStream(
                                senderId = chosen,
                                senderName = frame.senderName.ifBlank { info?.senderName ?: chosen },
                                senderPlatform = info?.senderPlatform ?: "windows",
                                sessionId = frame.sessionId,
                                frameSeq = frame.frameSeq,
                                width = info?.frameWidth ?: 0,
                                height = info?.frameHeight ?: 0,
                                fps = info?.fps ?: 4.0f,
                                routeBadge = badge,
                                timestampMs = System.currentTimeMillis(),
                                frameBytes = frame.bytes
                            )
                            _incomingScreenStreams.value = updated
                        }
                    }
                }
                kotlinx.coroutines.delay(500L)
            }
        }
    }

    fun closeIncomingViewer() {
        ensureIncomingStreamPolling(active = false)
        val host = serviceRef?.client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
        val tc = _fileTransferClient ?: serviceRef?.transferClient
        if (host.isNotBlank() && tc != null) {
            repoScope.launch(Dispatchers.IO) {
                tc.postScreenSubscribe(host, 8766, subscribe = false)
            }
        }
        _incomingScreenStreams.value = emptyMap()
        _selectedIncomingSenderId.value = null
    }

    fun onScreenStreamEvent(data: Map<String, Any?>) {
        if (activePermissionProfile.trim().lowercase() != "full_control") {
            closeIncomingViewer()
            return
        }
        val eventType = (data["event_type"] as? String)?.trim()?.uppercase().orEmpty()
        val senderId = (data["sender_device_id"] as? String)?.trim().orEmpty()
        if (eventType == "STREAM_STOPPED" || eventType == "REVOKED") {
            if (senderId.isBlank()) {
                closeIncomingViewer()
            } else {
                val updated = _incomingScreenStreams.value.toMutableMap()
                updated.remove(senderId)
                _incomingScreenStreams.value = updated
                if (_selectedIncomingSenderId.value == senderId) {
                    _selectedIncomingSenderId.value = updated.keys.firstOrNull()
                }
                if (updated.isEmpty()) {
                    ensureIncomingStreamPolling(active = false)
                }
            }
            return
        }
        if (eventType == "STREAM_AVAILABLE" && senderId.isNotBlank() && senderId != identity.deviceId) {
            _selectedIncomingSenderId.value = _selectedIncomingSenderId.value ?: senderId
            val host = serviceRef?.client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
            val tc = _fileTransferClient ?: serviceRef?.transferClient
            if (host.isNotBlank() && tc != null) {
                repoScope.launch(Dispatchers.IO) {
                    tc.postScreenSubscribe(host, 8766, subscribe = true)
                }
            }
            refreshIncomingStreamsOnce()
            ensureIncomingStreamPolling(active = true)
        }
    }

    fun onIncomingRelayScreenFrame(sourceId: String, meta: Map<String, Any?>, jpegBytes: ByteArray) {
        if (activePermissionProfile.trim().lowercase() != "full_control") return
        val senderId = (meta["sender_device_id"] as? String)?.ifBlank { sourceId } ?: sourceId
        val sessionId = (meta["session_id"] as? String) ?: ""
        val seq = (meta["frame_seq"] as? Number)?.toLong() ?: 0L
        val existing = _incomingScreenStreams.value[senderId]
        if (existing != null && existing.sessionId == sessionId && seq > 0 && seq < existing.frameSeq) {
            return // Ignore stale frame on relay
        }
        val stream = IncomingScreenStream(
            senderId = senderId,
            senderName = (meta["sender_name"] as? String) ?: senderId,
            senderPlatform = (meta["sender_platform"] as? String) ?: "remote",
            sessionId = sessionId,
            frameSeq = seq,
            width = (meta["frame_width"] as? Number)?.toInt() ?: 0,
            height = (meta["frame_height"] as? Number)?.toInt() ?: 0,
            fps = (meta["fps"] as? Number)?.toFloat() ?: 4.0f,
            routeBadge = (meta["route_badge"] as? String)?.ifBlank { "Remote • Uses Data" } ?: "Remote • Uses Data",
            timestampMs = System.currentTimeMillis(),
            frameBytes = jpegBytes
        )
        val updated = _incomingScreenStreams.value.toMutableMap()
        updated[senderId] = stream
        _incomingScreenStreams.value = updated
        if (_selectedIncomingSenderId.value == null) {
            _selectedIncomingSenderId.value = senderId
        }
    }

    /**
     * Start live screen streaming session via foreground service.
     */
    fun startScreenShare(resultCode: Int, data: Intent, targetIds: List<String> = _pendingScreenShareTargets.value) {
        SnowForegroundService.startScreenShare(appContext, resultCode, data, targetIds)
    }

    /**
     * Stop live screen streaming session via foreground service.
     */
    fun stopScreenShare() {
        SnowForegroundService.stopScreenShare(appContext)
    }

    fun setCameraCapturing() {
        _cameraDelivery.value = CameraDeliveryInfo(status = CameraDeliveryStatus.CAPTURING)
    }

    /**
     * Upload staged camera photo to connected desktop PC via authenticated HTTPS.
     */
    fun uploadCameraPhoto(onComplete: (Boolean, String?) -> Unit) {
        val client = serviceRef?.client
        val targetHost = client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
        val transferClient = if (isConnectedAndAuthenticated()) resolveOrCreateTransferClient(requireConnectedAuth = false) else (_fileTransferClient ?: serviceRef?.transferClient)

        if (client == null || !isConnectedAndAuthenticated() || transferClient == null) {
            val err = "Desktop not connected or transfer client not ready."
            _cameraDelivery.value = CameraDeliveryInfo(status = CameraDeliveryStatus.FAILED, error = err)
            onComplete(false, err)
            return
        }

        _cameraDelivery.value = CameraDeliveryInfo(status = CameraDeliveryStatus.UPLOADING)
        val handler = CameraCaptureHandler(appContext) { transferClient }
        repoScope.launch(Dispatchers.IO) {
            try {
                val res = handler.capturePhoto(targetHost, 8766)
                val success = res["success"] as? Boolean ?: false
                if (success) {
                    val fileName = res["file_name"] as? String ?: "photo.jpg"
                    val sizeBytes = (res["size_bytes"] as? Number)?.toLong() ?: 0L
                    val sha256 = res["sha256"] as? String ?: ""
                    // Notify desktop via WSS control plane
                    client.sendRequest(
                        action = "camera_photo_delivered",
                        data = mapOf(
                            "file_name" to fileName,
                            "size_bytes" to sizeBytes,
                            "sha256" to sha256,
                            "timestamp" to System.currentTimeMillis()
                        )
                    ) { _ -> }
                    _cameraDelivery.value = CameraDeliveryInfo(
                        status = CameraDeliveryStatus.DELIVERED,
                        fileName = fileName
                    )
                    repoScope.launch(Dispatchers.Main) {
                        onComplete(true, fileName)
                    }
                } else {
                    val err = res["error"] as? String ?: "Camera upload failed"
                    _cameraDelivery.value = CameraDeliveryInfo(
                        status = CameraDeliveryStatus.FAILED,
                        error = err
                    )
                    repoScope.launch(Dispatchers.Main) {
                        onComplete(false, err)
                    }
                }
            } catch (e: Exception) {
                val err = e.message ?: "Camera upload error"
                _cameraDelivery.value = CameraDeliveryInfo(
                    status = CameraDeliveryStatus.FAILED,
                    error = err
                )
                repoScope.launch(Dispatchers.Main) {
                    onComplete(false, err)
                }
            }
        }
    }

    fun retryCameraUpload(onComplete: (Boolean, String?) -> Unit) {
        CameraCaptureHandler.isUserInteractionActive = true
        uploadCameraPhoto(onComplete)
    }

    fun dismissCameraDelivery() {
        CameraCaptureHandler.isUserInteractionActive = false
        CameraCaptureHandler.stagedPhotoFile?.let { staged ->
            try {
                if (staged.exists()) staged.delete()
            } catch (_: Exception) {}
        }
        CameraCaptureHandler.stagedPhotoFile = null
        _cameraDelivery.value = CameraDeliveryInfo(status = CameraDeliveryStatus.IDLE)
    }

    fun setCameraFailed(errorMessage: String) {
        CameraCaptureHandler.isUserInteractionActive = false
        _cameraDelivery.value = CameraDeliveryInfo(status = CameraDeliveryStatus.FAILED, error = errorMessage)
    }

    fun toggleInstantClipboardSync(enabled: Boolean, onComplete: ((Boolean) -> Unit)? = null) {
        val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
        prefs.edit().putBoolean(PREF_KEY_INSTANT_SYNC, enabled).apply()
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            onComplete?.invoke(false)
            return
        }
        client.sendRequest("desktop_clipboard_sync_toggle", mapOf("enabled" to enabled)) { resp ->
            onComplete?.invoke(resp.isSuccess)
        }
    }

    fun isRemoteRelayEnabled(): Boolean {
        val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
        return prefs.getBoolean(PREF_KEY_REMOTE_RELAY_ENABLED, false)
    }

    fun setRemoteRelayEnabled(enabled: Boolean) {
        val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
        prefs.edit().putBoolean(PREF_KEY_REMOTE_RELAY_ENABLED, enabled).apply()
    }

    fun getRemoteRelayEndpoint(): String {
        val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
        return prefs.getString(PREF_KEY_REMOTE_RELAY_ENDPOINT, "")?.trim().orEmpty()
    }

    /**
     * Resolve effective WSS relay URL, defaulting to built-in Render Hub when no custom endpoint is set.
     */
    fun getEffectiveRelayEndpointForHub(): String {
        val custom = getRemoteRelayEndpoint()
        if (custom.isNotBlank()) {
            return normalizeRelayUrl(custom)
        }
        return normalizeRelayUrl(getDefaultHubUrl())
    }

    /**
     * Resolve Default Hub HTTP(S) base URL with deterministic precedence:
     * 1. Persisted user setting (`default_hub_url` or legacy `remote_relay_endpoint`).
     * 2. Explicit environment / override value when supplied.
     * 3. Built-in default Render Hub (`https://snow-relay.onrender.com`).
     * Never overwrites a user's existing custom hub configuration.
     */
    fun getDefaultHubUrl(envOverride: String? = null, allowDevLoopback: Boolean = false): String {
        val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
        val persistedHub = prefs.getString("default_hub_url", null)?.trim().orEmpty()
        val persistedRelay = prefs.getString(PREF_KEY_REMOTE_RELAY_ENDPOINT, null)?.trim().orEmpty()
        val candidates = listOf(
            persistedHub,
            persistedRelay
                .replace("wss://", "https://")
                .replace("ws://", "http://")
                .removeSuffix("/v1/tunnel")
                .trimEnd('/'),
            envOverride?.trim().orEmpty()
        )
        for (raw in candidates) {
            if (raw.isNotEmpty()) {
                try {
                    return validateHubUrl(raw, allowDevLoopback = allowDevLoopback)
                } catch (_: Exception) {
                }
            }
        }
        return DEFAULT_BUILTIN_HUB_URL
    }

    fun setDefaultHubUrl(hubUrl: String, allowDevLoopback: Boolean = false): String {
        val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
        val clean = hubUrl.trim()
        if (clean.isEmpty()) {
            prefs.edit().remove("default_hub_url").apply()
            return getDefaultHubUrl(allowDevLoopback = allowDevLoopback)
        }
        val validated = validateHubUrl(clean, allowDevLoopback = allowDevLoopback)
        prefs.edit().putString("default_hub_url", validated).apply()
        return validated
    }

    /**
     * Join an active Render Hub rendezvous session for unpaired remote onboarding
     * (never auto-pairs: returns scoped bootstrap material so TLS pinning + E2E verification can run).
     */
    internal var customRendezvousTunnelPairerForTest: ((Map<String, Any?>, String?, String?, (Boolean, String?) -> Unit) -> Unit)? = null

    fun joinRendezvousOnboarding(
        snowId: String? = null,
        pin: String? = null,
        handshakeToken: String? = null,
        federationCode: String? = null,
        allowDevLoopback: Boolean = false,
        rendezvousId: String? = null,
        hubUrlOverride: String? = null,
        onComplete: (Boolean, Map<String, Any?>?, String?) -> Unit
    ) {
        val hubBase = try {
            val rawHub = hubUrlOverride?.trim()?.takeIf { it.isNotBlank() }
            if (rawHub != null) validateHubUrl(rawHub, allowDevLoopback = allowDevLoopback)
            else getDefaultHubUrl(allowDevLoopback = allowDevLoopback)
        } catch (e: Exception) {
            onComplete(false, null, e.message ?: "Invalid Hub URL")
            return
        }
        repoScope.launch(Dispatchers.IO) {
            try {
                val payload = org.json.JSONObject().apply {
                    put("client_device_id", identity.deviceId)
                    if (!rendezvousId.isNullOrBlank()) put("rendezvous_id", rendezvousId.trim())
                    if (!snowId.isNullOrBlank()) put("snow_id", snowId.trim().uppercase())
                    if (!pin.isNullOrBlank()) put("pin", pin.trim())
                    if (!handshakeToken.isNullOrBlank()) put("handshake_token", handshakeToken.trim())
                    if (!federationCode.isNullOrBlank()) put("federation_code", federationCode.trim())
                }
                val body = payload.toString().toRequestBody("application/json; charset=utf-8".toMediaType())
                val req = okhttp3.Request.Builder()
                    .url("$hubBase/v1/rendezvous/join")
                    .post(body)
                    .build()
                val httpClient = okhttp3.OkHttpClient.Builder()
                    .callTimeout(8, java.util.concurrent.TimeUnit.SECONDS)
                    .build()
                httpClient.newCall(req).execute().use { resp ->
                    val rawStr = resp.body?.string() ?: "{}"
                    val obj = org.json.JSONObject(rawStr)
                    if (!resp.isSuccessful || !obj.optBoolean("success", false)) {
                        val err = obj.optString("error", "Rendezvous failed (HTTP ${resp.code})")
                        kotlinx.coroutines.withContext(Dispatchers.Main) {
                            onComplete(false, null, err)
                        }
                        return@launch
                    }
                    val fp = obj.optString("host_cert_fingerprint", "").trim()
                    val hostDevId = obj.optString("host_device_id", "").trim()
                    val netId = obj.optString("network_id", "").trim()
                    if (fp.length == 64 && hostDevId.isNotBlank()) {
                        val existing = activeCertPinStorage.getPinnedFingerprintForDevice(hostDevId)
                        if (existing == null) {
                            activeCertPinStorage.pinFingerprintForDevice(hostDevId, fp)
                        } else if (!existing.replace(":", "").equals(fp.replace(":", ""), ignoreCase = true)) {
                            kotlinx.coroutines.withContext(Dispatchers.Main) {
                                onComplete(false, null, "Pinned certificate mismatch for host $hostDevId.")
                            }
                            return@launch
                        }
                    } else if (fp.length == 64 && activeCertPinStorage.listPinnedDeviceIds().isEmpty() && activeCertPinStorage.getPinnedFingerprint() == null) {
                        activeCertPinStorage.pinFingerprint(fp)
                    }
                    val resultMap = mapOf<String, Any?>(
                        "rendezvous_id" to obj.optString("rendezvous_id"),
                        "mode" to obj.optString("mode"),
                        "network_id" to obj.optString("network_id"),
                        "host_device_id" to obj.optString("host_device_id"),
                        "host_snow_id" to obj.optString("host_snow_id"),
                        "host_cert_fingerprint" to fp,
                        "relay_ws_url" to obj.optString("relay_ws_url"),
                        "bootstrap_token" to obj.optString("bootstrap_token"),
                        "trust_completed" to obj.optBoolean("trust_completed", false),
                        "requires_end_to_end_verification" to obj.optBoolean("requires_end_to_end_verification", true)
                    )
                    kotlinx.coroutines.withContext(Dispatchers.Main) {
                        onComplete(true, resultMap, null)
                    }
                }
            } catch (e: Exception) {
                kotlinx.coroutines.withContext(Dispatchers.Main) {
                    onComplete(false, null, e.message ?: "Rendezvous lookup error")
                }
            }
        }
    }

    private fun completeRendezvousOnboardingFromQr(
        rdvId: String,
        hostNodeId: String,
        hostSnowId: String?,
        hostFp: String,
        hostDeviceType: String?,
        hostTransferPort: Int,
        handshakeToken: String?,
        pin: String?,
        hubUrlOverride: String?,
        onResult: (Boolean, String?) -> Unit
    ) {
        joinRendezvousOnboarding(
            snowId = hostSnowId,
            pin = pin,
            handshakeToken = handshakeToken,
            allowDevLoopback = allowLoopbackCandidateIpsForTest,
            rendezvousId = rdvId,
            hubUrlOverride = hubUrlOverride
        ) { ok, rdvData, err ->
            if (!ok || rdvData == null) {
                onResult(false, err ?: "Rendezvous join failed.")
                return@joinRendezvousOnboarding
            }
            val joinedFp = (rdvData["host_cert_fingerprint"] as? String)?.replace(":", "")?.trim().orEmpty()
            if (joinedFp.length == 64 && !joinedFp.equals(hostFp, ignoreCase = true)) {
                onResult(false, "Rendezvous host certificate fingerprint mismatch.")
                return@joinRendezvousOnboarding
            }
            val dataWithMeta = rdvData.toMutableMap().apply {
                if (hostNodeId.isNotBlank() && (get("host_device_id") as? String).isNullOrBlank()) {
                    put("host_device_id", hostNodeId)
                }
                if (hostFp.length == 64 && (get("host_cert_fingerprint") as? String).isNullOrBlank()) {
                    put("host_cert_fingerprint", hostFp)
                }
                if (!hostDeviceType.isNullOrBlank()) put("host_device_type", hostDeviceType)
                put("host_transfer_port", hostTransferPort)
            }
            val hook = customRendezvousTunnelPairerForTest
            if (hook != null) {
                hook.invoke(dataWithMeta, pin, handshakeToken, onResult)
            } else {
                completeRendezvousPairingOverTunnel(dataWithMeta, pin, handshakeToken, onResult)
            }
        }
    }

    fun completeRendezvousPairingOverTunnel(
        rdvData: Map<String, Any?>,
        pin: String? = null,
        handshakeToken: String? = null,
        onResult: (Boolean, String?) -> Unit
    ) {
        val relayWsUrl = (rdvData["relay_ws_url"] as? String)?.trim().orEmpty()
        val hostDevId = (rdvData["host_device_id"] as? String)?.trim().orEmpty()
        val hostFp = (rdvData["host_cert_fingerprint"] as? String)?.replace(":", "")?.trim().orEmpty()
        val bootstrapToken = (rdvData["bootstrap_token"] as? String)?.trim().orEmpty()
        val hubRouteNetId = (rdvData["network_id"] as? String)?.trim().orEmpty()
        val hostSnowId = (rdvData["host_snow_id"] as? String)?.trim()?.uppercase()?.takeIf { it.isNotBlank() }
        val hostDeviceType = (rdvData["host_device_type"] as? String)?.trim()?.lowercase()
        val hostTransferPort = (rdvData["host_transfer_port"] as? Int) ?: 8766

        if (relayWsUrl.isBlank() || hostDevId.isBlank() || hostFp.length != 64 || bootstrapToken.isBlank()) {
            onResult(false, "Incomplete rendezvous bootstrap parameters for E2E tunnel.")
            return
        }
        if (identity.deviceId == hostDevId) {
            onResult(false, "Cannot open E2E relay tunnel to own device identity.")
            return
        }

        val deterministicClientMode = (identity.deviceId < hostDevId)
        val localKeyManagers: Array<javax.net.ssl.KeyManager>? = try {
            val loaded = org.snow.security.AndroidSelfSignedCertGenerator.loadOrCreate(activePeerHostCertStorage)
            loaded.keyManagers
        } catch (e: Exception) {
            if (!deterministicClientMode) {
                onResult(false, "Cannot take E2E TLS server role: persisted local TLS key material unavailable (${e.message}).")
                return
            }
            null
        }
        if (!deterministicClientMode && (localKeyManagers == null || localKeyManagers.isEmpty())) {
            onResult(false, "Cannot take E2E TLS server role: persisted local TLS keyManagers missing.")
            return
        }

        val completed = java.util.concurrent.atomic.AtomicBoolean(false)
        fun finish(ok: Boolean, msg: String?, rc: org.snow.network.RelayClient?) {
            if (completed.compareAndSet(false, true)) {
                if (!ok) {
                    try { rc?.disconnect() } catch (_: Exception) {}
                }
                repoScope.launch(Dispatchers.Main) {
                    onResult(ok, msg)
                }
            }
        }

        val usePublicCa = relayWsUrl.startsWith("wss://") &&
            !relayWsUrl.contains("127.0.0.1") &&
            !relayWsUrl.contains("localhost")
        lateinit var rc: org.snow.network.RelayClient
        rc = org.snow.network.RelayClient(
            relayUrl = relayWsUrl,
            deviceId = identity.deviceId,
            groupId = hubRouteNetId.ifBlank { hostDevId },
            ticket = "",
            targetPeerId = hostDevId,
            certPinStorage = activeCertPinStorage,
            expectedPeerFingerprint = hostFp,
            isClientMode = deterministicClientMode,
            scope = repoScope,
            bootstrapToken = bootstrapToken,
            networkId = hubRouteNetId,
            usePublicCaForOuterRelay = usePublicCa
        ).apply {
            keyManagers = localKeyManagers
        }
        rc.onTunnelFailed = { errMsg ->
            finish(false, errMsg, rc)
        }
        rc.onTunnelEstablished = {
            val pairReqData = mutableMapOf<String, Any?>(
                "device_id" to identity.deviceId,
                "device_name" to identity.deviceName,
                "device_type" to "android",
                "manifest" to org.snow.network.DeviceNode.buildAndroidManifest(appContext).toMap()
            )
            if (!handshakeToken.isNullOrBlank()) {
                pairReqData["handshake_token"] = handshakeToken.trim()
            } else if (!pin.isNullOrBlank()) {
                pairReqData["pin"] = pin.trim()
            }
            getEffectiveNetworkId()?.let { localNet ->
                pairReqData["client_network_id"] = localNet
            }
            val dispatched = rc.sendRequest("pair_request", pairReqData) { respMsg ->
                val pState = pairingFlow.handlePairingResponse(respMsg, fallbackDeviceId = hostDevId)
                if (pState is PairingState.Paired) {
                    pState.authToken?.takeIf { it.isNotBlank() }?.let { tok ->
                        activeTokenStorage.saveTokenForDevice(hostDevId, tok)
                    }
                    activeCertPinStorage.pinFingerprintForDevice(hostDevId, hostFp)
                    applyNegotiatedNetworkOutcome(pState)
                    recordSuccessfulConnection(
                        host = relayWsUrl,
                        port = 443,
                        sessionId = pState.sessionId,
                        tier = pState.trustTier,
                        peerDeviceName = pState.desktopName,
                        peerDeviceType = pState.deviceType ?: hostDeviceType,
                        peerDeviceId = pState.desktopId.takeIf { it.isNotBlank() && it != "unknown" } ?: hostDevId,
                        peerSnowId = pState.peerSnowId ?: hostSnowId,
                        peerPermissionProfile = pState.permissionProfile,
                        peerNetworkId = pState.hostNetworkId ?: pState.peerNetworkId,
                        peerTransferPort = hostTransferPort,
                        peerRelationship = pState.relationship,
                        networkConflict = pState.networkConflict
                    )
                    val sPrefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
                    sPrefs.edit().apply {
                        putString("remote_relay_target_peer", hostDevId)
                        (pState.peerNetworkId ?: hubRouteNetId.takeIf { it.isNotBlank() })?.let {
                            putString("remote_relay_group_id", it)
                        }
                    }.apply()
                    rc.disconnect()
                    finish(true, null, null)
                } else {
                    val errText = when (pState) {
                        is PairingState.WrongPin -> pState.message
                        is PairingState.Expired -> pState.message
                        is PairingState.Locked -> pState.message
                        is PairingState.Error -> pState.message
                        else -> "Rendezvous E2E pairing rejected."
                    }
                    finish(false, errText, rc)
                }
            }
            if (!dispatched) {
                finish(false, "Failed sending E2E pair_request over tunnel.", rc)
            }
        }
        rc.connect()
        repoScope.launch(Dispatchers.IO) {
            kotlinx.coroutines.delay(10_000L)
            finish(false, "Rendezvous E2E pairing timed out.", rc)
        }
    }

    fun setRemoteRelayEndpoint(endpoint: String) {
        val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
        prefs.edit().putString(PREF_KEY_REMOTE_RELAY_ENDPOINT, endpoint.trim()).apply()
    }

    fun updateRemoteRelayConfig(enabled: Boolean, endpoint: String) {
        setRemoteRelayEnabled(enabled)
        setRemoteRelayEndpoint(endpoint)
        if (enabled && endpoint.isNotBlank()) {
            serviceRef?.startRelay(endpoint)
        } else {
            serviceRef?.stopRelay()
        }
    }

    fun refreshDiscovery(resumeUdp: Boolean = true) {
        val svc = serviceRef ?: return
        if (resumeUdp) {
            svc.discoveryManager.startListening()
        }
        svc.promoteLocalRouteFromDiscoveryIfAvailable()
    }

    fun getRelayTokenStorage(keyStoreManager: org.snow.security.KeyStoreManager? = null): org.snow.security.TokenStorage {
        return if (keyStoreManager != null) {
            org.snow.security.SharedPreferencesTokenStorage(
                appContext.getSharedPreferences("snow_relay_security", Context.MODE_PRIVATE),
                keyStoreManager
            )
        } else {
            org.snow.security.SharedPreferencesTokenStorage(appContext, prefName = "snow_relay_security")
        }
    }

    fun pushClipboard(text: String, onComplete: (Boolean, String?) -> Unit) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            onComplete(false, "Desktop not connected.")
            return
        }

        appendLog("INFO", TAG, "Pushing clipboard to PC...")
        client.sendRequest("desktop_clipboard_set", mapOf("text" to text, "content" to text)) { resp ->
            repoScope.launch {
                if (resp.isSuccess) {
                    recordIncomingClipboardText(text)
                    appendLog("INFO", TAG, "Clipboard pushed to PC successfully.")
                    onComplete(true, null)
                } else {
                    val err = resp.payload?.get("error") as? String ?: "Push failed"
                    appendLog("ERROR", TAG, err)
                    onComplete(false, err)
                }
            }
        }
    }

    @JvmOverloads
    fun pushCurrentClipboard(userInitiated: Boolean = false, onComplete: (Boolean, String?) -> Unit) {
        val client = serviceRef?.client
        val targetHost = client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
        val transferClient = resolveOrCreateTransferClient(requireConnectedAuth = true)

        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            onComplete(false, "Desktop not connected.")
            return
        }

        val cm = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        val clip = cm?.primaryClip
        if (clip == null || clip.itemCount == 0) {
            onComplete(false, "Android clipboard is empty.")
            return
        }

        val item = clip.getItemAt(0)
        val uri = item.uri
        val clipDescriptionMime = clip.description?.let { desc ->
            (0 until desc.mimeTypeCount).map { desc.getMimeType(it) }.firstOrNull { it.startsWith("image/") }
        }
        val resolvedMime = clipDescriptionMime ?: uri?.let { appContext.contentResolver.getType(it) }
        val isImage = (resolvedMime?.startsWith("image/") == true) || (uri != null && (clipDescriptionMime != null || appContext.contentResolver.getType(uri)?.startsWith("image/") == true))

        // 1. If it's an image
        if (!userInitiated && isImage && uri != null && isOwnFileProviderUri(uri)) {
            appendLog("DEBUG", TAG, "Ignoring push for own SNOW clipboard FileProvider URI.")
            onComplete(false, "Image already originated from SNOW clipboard.")
            return
        }
        if (isImage && uri != null && transferClient != null && targetHost.isNotBlank()) {
            appendLog("INFO", TAG, "Uploading clipboard image to PC...")
            repoScope.launch(Dispatchers.IO) {
                var toCleanup: java.io.File? = null
                try {
                    val stagingDir = java.io.File(appContext.cacheDir, "safe_staging")
                    SafeStagingManager.cleanupStaleFiles(stagingDir)
                    val rawName = "clip_${System.currentTimeMillis()}.png"
                    val stagedFile = SafeStagingManager.createStagedFile(stagingDir, rawName)
                    toCleanup = stagedFile
                    appContext.contentResolver.openInputStream(uri)?.use { input ->
                        stagedFile.outputStream().use { output ->
                            input.copyTo(output)
                        }
                    }
                    val fileSize = stagedFile.length()
                    if (fileSize <= 0L) {
                        repoScope.launch(Dispatchers.Main) {
                            onComplete(false, "Clipboard image is empty or inaccessible.")
                        }
                        return@launch
                    }
                    if (fileSize > MAX_CLIPBOARD_IMAGE_BYTES) {
                        repoScope.launch(Dispatchers.Main) {
                            onComplete(false, "Image exceeds 15 MiB limit.")
                        }
                        return@launch
                    }
                    val localSha256 = FileTransferClient.computeSha256(stagedFile)
                    val localCanonical = computeCanonicalImageDigestForFile(stagedFile)
                    if (!userInitiated && isDuplicateImageClipboard(localSha256, localCanonical)) {
                        appendLog("DEBUG", TAG, "Skipping clipboard image upload (matches last synced raw/canonical SHA-256).")
                        repoScope.launch(Dispatchers.Main) {
                            onComplete(true, "Image already synced")
                        }
                        return@launch
                    }
                    val upRes = transferClient.uploadFile(
                        serverHost = targetHost,
                        transferPort = 8766,
                        file = stagedFile
                    )
                    handleUploadedClipboardImage(
                        upRes = upRes,
                        stagedName = stagedFile.name,
                        client = client,
                        canonicalSha256 = localCanonical,
                        userInitiated = userInitiated,
                        onComplete = onComplete
                    )
                } catch (e: Exception) {
                    repoScope.launch(Dispatchers.Main) {
                        onComplete(false, "Failed pushing image: ${e.message}")
                    }
                } finally {
                    SafeStagingManager.cleanupStagedFile(toCleanup)
                }
            }
            return
        }

        // 2. Otherwise text
        val text = item.text?.toString() ?: item.coerceToText(appContext)?.toString() ?: ""
        if (text.isNotBlank()) {
            pushClipboard(text, onComplete)
        } else {
            onComplete(false, "Clipboard content is not text or a supported image.")
        }
    }

    internal var clipboardRequestDispatchOverrideForTest: ((String, Map<String, Any?>, (org.snow.protocol.SnowMessage) -> Unit) -> Unit)? = null

    internal fun pushStagedImageFileToDesktop(
        stagedFile: java.io.File,
        transferClient: FileTransferClient,
        targetHost: String,
        client: org.snow.network.SnowWebSocketClient,
        userInitiated: Boolean = false,
        onComplete: (Boolean, String?) -> Unit
    ) {
        val localSha256 = FileTransferClient.computeSha256(stagedFile)
        val localCanonical = computeCanonicalImageDigestForFile(stagedFile)
        if (!userInitiated && isDuplicateImageClipboard(localSha256, localCanonical)) {
            appendLog("DEBUG", TAG, "Skipping clipboard image upload (matches last synced raw/canonical SHA-256).")
            repoScope.launch(Dispatchers.Main) {
                onComplete(true, "Image already synced")
            }
            return
        }
        val upRes = kotlinx.coroutines.runBlocking {
            transferClient.uploadFile(
                serverHost = targetHost,
                transferPort = 8766,
                file = stagedFile
            )
        }
        handleUploadedClipboardImage(
            upRes = upRes,
            stagedName = stagedFile.name,
            client = client,
            canonicalSha256 = localCanonical,
            userInitiated = userInitiated,
            onComplete = onComplete
        )
    }

    private fun handleUploadedClipboardImage(
        upRes: FileTransferClient.TransferResult,
        stagedName: String,
        client: org.snow.network.SnowWebSocketClient,
        canonicalSha256: String? = null,
        userInitiated: Boolean = false,
        onComplete: (Boolean, String?) -> Unit
    ) {
        val sendReq: (String, Map<String, Any?>, (org.snow.protocol.SnowMessage) -> Unit) -> Unit = { action, data, cb ->
            val override = clipboardRequestDispatchOverrideForTest
            if (override != null) {
                override.invoke(action, data, cb)
            } else {
                client.sendRequest(action, data, cb)
            }
        }
        when (upRes) {
            is FileTransferClient.TransferResult.Success -> {
                val payload = buildMap<String, Any?> {
                    put("type", "image")
                    put("transfer_id", upRes.transferId)
                    put("sha256", upRes.sha256)
                    put("file_name", stagedName)
                    if (!canonicalSha256.isNullOrBlank()) put("canonical_sha256", canonicalSha256)
                    if (userInitiated) put("user_initiated", true)
                }
                sendReq("desktop_clipboard_set", payload) { resp ->
                    repoScope.launch(Dispatchers.Main) {
                        if (resp.isSuccess) {
                            recordIncomingClipboardImageSha256(upRes.sha256, canonicalSha256)
                            appendLog("INFO", TAG, "Image pushed to PC clipboard.")
                            onComplete(true, "Image pushed to PC")
                        } else {
                            val err = resp.payload?.get("error") as? String ?: "Failed setting image on PC"
                            onComplete(false, err)
                        }
                    }
                }
            }
            is FileTransferClient.TransferResult.Duplicate -> {
                val payload = buildMap<String, Any?> {
                    put("type", "image")
                    put("sha256", upRes.sha256)
                    put("file_name", stagedName)
                    if (!canonicalSha256.isNullOrBlank()) put("canonical_sha256", canonicalSha256)
                    if (userInitiated) put("user_initiated", true)
                }
                sendReq("desktop_clipboard_set", payload) { resp ->
                    repoScope.launch(Dispatchers.Main) {
                        if (resp.isSuccess) {
                            recordIncomingClipboardImageSha256(upRes.sha256, canonicalSha256)
                            appendLog("INFO", TAG, "Image pushed to PC clipboard.")
                            onComplete(true, "Image pushed to PC")
                        } else {
                            val err = resp.payload?.get("error") as? String ?: "Failed setting image on PC"
                            onComplete(false, err)
                        }
                    }
                }
            }
            is FileTransferClient.TransferResult.Error -> {
                repoScope.launch(Dispatchers.Main) {
                    onComplete(false, "Upload failed: ${upRes.message}")
                }
            }
        }
    }

    fun pullClipboard(onComplete: (Boolean, String?) -> Unit) {
        val client = serviceRef?.client
        val targetHost = client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
        val transferClient = resolveOrCreateTransferClient(requireConnectedAuth = true)

        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            onComplete(false, "Desktop not connected.")
            return
        }

        appendLog("INFO", TAG, "Pulling clipboard from PC...")
        client.sendRequest("desktop_clipboard_get", emptyMap()) { resp ->
            repoScope.launch(Dispatchers.IO) {
                if (resp.isSuccess) {
                    val data = resp.payload?.get("data") as? Map<*, *>
                    val type = data?.get("type") as? String
                    if (type == "image" && transferClient != null && targetHost.isNotBlank()) {
                        val transferId = data["transfer_id"] as? String
                        val sha256 = data["sha256"] as? String ?: ""
                        val transferPort = (data["transfer_port"] as? Number)?.toInt() ?: 8766
                        if (transferId != null) {
                            val cacheDir = File(appContext.cacheDir, "clipboard").apply { mkdirs() }
                            val localFile = File(cacheDir, "clip_${sha256.take(16)}.png")
                            val dlRes = transferClient.downloadFile(
                                serverHost = targetHost,
                                transferPort = transferPort,
                                transferId = transferId,
                                destinationFile = localFile,
                                expectedSha256 = sha256
                            )
                            if (dlRes is FileTransferClient.TransferResult.Success) {
                                val pulledCanonical = computeCanonicalImageDigestForFile(dlRes.file)
                                    ?: (data["canonical_sha256"] as? String)
                                repoScope.launch(Dispatchers.Main) {
                                    try {
                                        val contentUri = androidx.core.content.FileProvider.getUriForFile(
                                            appContext,
                                            "${appContext.packageName}.fileprovider",
                                            dlRes.file
                                        )
                                        val cm = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                        val clip = ClipData.newUri(appContext.contentResolver, "Image", contentUri)
                                        cm.setPrimaryClip(clip)
                                        ClipboardHandler.grantImeUriPermission(appContext, contentUri)
                                        ClipboardHandler.postShareFallbackNotification(
                                            appContext,
                                            contentUri,
                                            "image/png",
                                            isUserInitiated = true
                                        )
                                        recordIncomingClipboardImageSha256(sha256.ifBlank { dlRes.sha256 }, pulledCanonical)
                                        appendLog("INFO", TAG, "Pulled image from PC to clipboard.")
                                        onComplete(true, "Image pulled to phone clipboard.")
                                    } catch (e: Exception) {
                                        onComplete(false, "Failed setting image to clipboard: ${e.message}")
                                    }
                                }
                                return@launch
                            } else {
                                repoScope.launch(Dispatchers.Main) {
                                    onComplete(false, "Failed downloading image from PC.")
                                }
                                return@launch
                            }
                        }
                    }

                    // Otherwise text
                    val text = (data?.get("text") as? String) ?: (data?.get("content") as? String) ?: ""
                    repoScope.launch(Dispatchers.Main) {
                        if (text.isEmpty()) {
                            onComplete(false, "PC clipboard is empty.")
                        } else {
                            recordIncomingClipboardText(text)
                            ClipboardHandler(appContext).pushClipboard(text)
                            appendLog("INFO", TAG, "Copied PC clipboard to phone.")
                            onComplete(true, text)
                        }
                    }
                } else {
                    val err = resp.payload?.get("error") as? String ?: "Pull failed"
                    repoScope.launch(Dispatchers.Main) {
                        appendLog("ERROR", TAG, err)
                        onComplete(false, err)
                    }
                }
            }
        }
    }

    // --- Phase 26B: Shared Clipboard Buffer Operations ---

    fun fetchClipboardBuffer(onComplete: ((Boolean, String?) -> Unit)? = null) {
        val client = serviceRef?.client ?: run {
            onComplete?.invoke(false, "Client disconnected")
            return
        }
        client.sendRequest("clipboard_buffer_list", mapOf("limit" to MAX_CLIPBOARD_ITEMS)) { resp ->
            if (resp.isSuccess) {
                val data = resp.payload?.get("data") as? Map<*, *> ?: resp.payload
                val rawItems = data?.get("items") as? List<*> ?: emptyList<Any>()
                val parsed = parseClipboardBufferItems(rawItems)
                _clipboardBufferItems.value = parsed
                prefetchClipboardThumbnails(parsed)
                repoScope.launch(Dispatchers.Main) {
                    onComplete?.invoke(true, "Fetched ${parsed.size} items")
                }
            } else {
                val errMsg = resp.error?.message ?: "Failed fetching clipboard buffer"
                repoScope.launch(Dispatchers.Main) {
                    onComplete?.invoke(false, errMsg)
                }
            }
        }
    }

    fun applyBufferItemToClipboard(item: ClipboardItemDto, onComplete: (Boolean, String?) -> Unit) {
        val client = serviceRef?.client ?: run {
            onComplete(false, "Client disconnected or offline")
            return
        }
        if (item.type == "file" || item.type == "file_bundle") {
            val transferClient = _fileTransferClient ?: run {
                onComplete(false, "File transfer client offline")
                return
            }
            val targetHost = client.currentTargetHost.takeIf { it.isNotBlank() } ?: connectedHost
            val targetDevice = identity.deviceId
            client.sendRequest("clipboard_buffer_apply", mapOf("item_id" to item.itemId, "target" to targetDevice, "stage_only" to true)) { resp ->
                if (resp.isSuccess) {
                    val data = resp.payload?.get("data") as? Map<*, *> ?: resp.payload
                    val rawFiles = data?.get("files")
                    val validated = validateIncomingFileBundlePayload(rawFiles)
                    if (validated.isFailure) {
                        repoScope.launch(Dispatchers.Main) {
                            onComplete(false, validated.exceptionOrNull()?.message ?: "Invalid file manifest")
                        }
                        return@sendRequest
                    }
                    repoScope.launch(Dispatchers.IO) {
                        val result = applyRemoteClipboardBundle(
                            entries = validated.getOrThrow(),
                            transferClient = transferClient,
                            serverHost = targetHost,
                            defaultTransferPort = (data?.get("transfer_port") as? Number)?.toInt() ?: 8766,
                            eventId = (data?.get("event_id") as? String) ?: item.eventId,
                            seq = (data?.get("seq") as? Number)?.toLong() ?: item.seq,
                            notifyUser = true
                        )
                        repoScope.launch(Dispatchers.Main) {
                            if (result.isSuccess) {
                                val saved = result.getOrNull().orEmpty()
                                val msg = when {
                                    saved.isEmpty() -> "Saved to Transfer Folder"
                                    saved.size == 1 -> "Saved ${saved[0]} to Transfer Folder"
                                    else -> "Saved ${saved.size} files to Transfer Folder (${saved.take(3).joinToString(", ")})"
                                }
                                onComplete(true, msg)
                            } else {
                                onComplete(false, result.exceptionOrNull()?.message ?: "Failed saving clipboard files")
                            }
                        }
                    }
                } else {
                    val errMsg = resp.error?.message ?: "Failed preparing clipboard files"
                    repoScope.launch(Dispatchers.Main) {
                        onComplete(false, errMsg)
                    }
                }
            }
            return
        }
        if (item.type == "image") {
            if (item.sizeBytes > MAX_CLIPBOARD_IMAGE_BYTES) {
                onComplete(false, "Image exceeds 15 MiB clipboard limit")
                return
            }
            val transferClient = _fileTransferClient ?: run {
                onComplete(false, "File transfer client offline")
                return
            }
            val targetHost = client.currentTargetHost.takeIf { it.isNotBlank() } ?: connectedHost
            val targetDevice = identity.deviceId
            client.sendRequest("clipboard_buffer_apply", mapOf("item_id" to item.itemId, "target" to targetDevice, "stage_only" to true)) { resp ->
                if (resp.isSuccess) {
                    val data = resp.payload?.get("data") as? Map<*, *> ?: resp.payload
                    val transferId = data?.get("transfer_id") as? String
                    val sha256 = (data?.get("sha256") as? String) ?: ""
                    val transferPort = (data?.get("transfer_port") as? Number)?.toInt() ?: 8766
                    val mimeType = data?.get("mime_type") as? String
                    val eventId = (data?.get("event_id") as? String) ?: item.eventId
                    val seq = (data?.get("seq") as? Number)?.toLong() ?: item.seq
                    if (transferId != null && targetHost.isNotBlank()) {
                        repoScope.launch(Dispatchers.IO) {
                            val cacheDir = org.snow.capabilities.ClipboardHandler.getClipboardCacheDir(appContext)
                            val ext = if (mimeType?.contains("jpeg") == true || mimeType?.contains("jpg") == true) "jpg" else "png"
                            val localFile = clipboardImageCacheFile(cacheDir, item.itemId, ext)
                            org.snow.capabilities.ClipboardHandler.pruneImageCache(cacheDir, preserveFileName = localFile.name)

                            val dlRes = transferClient.downloadFile(
                                serverHost = targetHost,
                                transferPort = transferPort,
                                transferId = transferId,
                                destinationFile = localFile,
                                expectedSha256 = sha256
                            )
                            if (dlRes is FileTransferClient.TransferResult.Success) {
                                if (dlRes.file.length() > MAX_CLIPBOARD_IMAGE_BYTES) {
                                    dlRes.file.delete()
                                    repoScope.launch(Dispatchers.Main) {
                                        onComplete(false, "Downloaded image exceeds 15 MiB limit")
                                    }
                                    return@launch
                                }
                                val appliedCanonical = computeCanonicalImageDigestForFile(dlRes.file)
                                    ?: (data?.get("canonical_sha256") as? String)
                                repoScope.launch(Dispatchers.Main) {
                                    try {
                                        val contentUri = androidx.core.content.FileProvider.getUriForFile(
                                            appContext,
                                            "${appContext.packageName}.fileprovider",
                                            dlRes.file
                                        )
                                        val resolvedMime = if (ext == "jpg") "image/jpeg" else "image/png"
                                        val cm = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                        val clip = ClipData(
                                            android.content.ClipDescription("SNOW Shared Clipboard", arrayOf(resolvedMime)),
                                            ClipData.Item(contentUri)
                                        )
                                        cm.setPrimaryClip(clip)
                                        org.snow.capabilities.ClipboardHandler.grantImeUriPermission(appContext, contentUri)
                                        org.snow.capabilities.ClipboardHandler.postShareFallbackNotification(appContext, contentUri, resolvedMime, isUserInitiated = true)

                                        recordIncomingClipboardImageSha256(sha256.ifBlank { dlRes.sha256 }, appliedCanonical)
                                        if (seq > 0L && eventId.isNotBlank()) {
                                            sendClipboardAck(seq, eventId, client)
                                        }
                                        appendLog("INFO", TAG, "Applied image buffer item to Android clipboard (${dlRes.file.length()} bytes, $resolvedMime).")
                                        onComplete(true, "Copied image to Android clipboard")
                                    } catch (e: Exception) {
                                        SafeLog.e(TAG, "Failed applying image buffer item: ${e.message}", e)
                                        onComplete(false, "Failed copying to clipboard: ${e.message}")
                                    }
                                }
                            } else {
                                repoScope.launch(Dispatchers.Main) {
                                    onComplete(false, "Failed downloading image buffer item")
                                }
                            }
                        }
                    } else {
                        repoScope.launch(Dispatchers.Main) {
                            onComplete(false, "Image transfer details unavailable")
                        }
                    }
                } else {
                    val errMsg = resp.error?.message ?: "Failed applying image buffer item"
                    repoScope.launch(Dispatchers.Main) {
                        onComplete(false, errMsg)
                    }
                }
            }
            return
        }

        // Fetch full text content via clipboard_buffer_get rather than preview truncation
        client.sendRequest("clipboard_buffer_get", mapOf("item_id" to item.itemId)) { resp ->
            if (resp.isSuccess) {
                val data = resp.payload?.get("data") as? Map<*, *> ?: resp.payload
                val textContent = data?.get("text_content") as? String
                if (textContent != null) {
                    val bytes = textContent.toByteArray(Charsets.UTF_8)
                    if (bytes.size > MAX_CLIPBOARD_TEXT_BYTES) {
                        repoScope.launch(Dispatchers.Main) {
                            onComplete(false, "Item exceeds 64 KiB clipboard limit")
                        }
                        return@sendRequest
                    }
                    repoScope.launch(Dispatchers.Main) {
                        try {
                            val cm = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            val clip = ClipData.newPlainText("SNOW Shared Clipboard", textContent)
                            cm.setPrimaryClip(clip)
                            recordIncomingClipboardText(textContent)
                            if (item.seq > 0L && item.eventId.isNotBlank()) {
                                sendClipboardAck(item.seq, item.eventId, client)
                            }
                            appendLog("INFO", TAG, "Applied full text buffer item to Android clipboard (${bytes.size} bytes).")
                            onComplete(true, "Copied full text to Android clipboard")
                        } catch (e: Exception) {
                            SafeLog.e(TAG, "Failed applying buffer item: ${e.message}", e)
                            onComplete(false, "Failed copying to clipboard: ${e.message}")
                        }
                    }
                } else {
                    repoScope.launch(Dispatchers.Main) {
                        onComplete(false, "Empty or missing text content in response")
                    }
                }
            } else {
                val errMsg = resp.error?.message ?: "Failed retrieving full clipboard item"
                repoScope.launch(Dispatchers.Main) {
                    onComplete(false, errMsg)
                }
            }
        }
    }

    fun pinClipboardBufferItem(itemId: String, isPinned: Boolean, onComplete: ((Boolean, String?) -> Unit)? = null) {
        val client = serviceRef?.client ?: run {
            onComplete?.invoke(false, "Client disconnected")
            return
        }
        client.sendRequest("clipboard_buffer_pin", mapOf("item_id" to itemId, "is_pinned" to isPinned)) { resp ->
            repoScope.launch(Dispatchers.Main) {
                if (resp.isSuccess) {
                    fetchClipboardBuffer()
                    onComplete?.invoke(true, null)
                } else {
                    onComplete?.invoke(false, resp.error?.message ?: "Failed to pin item")
                }
            }
        }
    }

    fun clearClipboardBuffer(onComplete: ((Boolean, String?) -> Unit)? = null) {
        val client = serviceRef?.client ?: run {
            onComplete?.invoke(false, "Client disconnected")
            return
        }
        client.sendRequest("clipboard_buffer_clear", emptyMap()) { resp ->
            repoScope.launch(Dispatchers.Main) {
                if (resp.isSuccess) {
                    _clipboardBufferItems.value = emptyList()
                    onComplete?.invoke(true, null)
                } else {
                    onComplete?.invoke(false, resp.error?.message ?: "Failed to clear clipboard")
                }
            }
        }
    }

    fun clipboardImageCacheFile(cacheDir: File, itemId: String, ext: String = "png"): File {
        val safeId = itemId.replace(Regex("[^A-Za-z0-9_-]"), "_")
        val cleanExt = if (ext.equals("jpg", ignoreCase = true) || ext.equals("jpeg", ignoreCase = true)) "jpg" else "png"
        return File(cacheDir, "clip_item_${safeId}.$cleanExt")
    }

    fun findCachedClipboardImageFile(cacheDir: File, itemId: String): File? {
        val safeId = itemId.replace(Regex("[^A-Za-z0-9_-]"), "_")
        for (ext in listOf("png", "jpg", "jpeg")) {
            val exact = File(cacheDir, "clip_item_${safeId}.$ext")
            if (exact.exists() && exact.length() > 0) return exact
        }
        val shortPrefix = itemId.take(8)
        return cacheDir.listFiles { f ->
            f.isFile && (f.name.contains(safeId) || (shortPrefix.isNotBlank() && f.name.contains(shortPrefix)))
        }?.firstOrNull()
    }

    fun createShareIntentForClipboardItem(item: ClipboardItemDto): Intent {
        val intent = Intent(Intent.ACTION_SEND)
        if (item.type == "image") {
            val cacheDir = org.snow.capabilities.ClipboardHandler.getClipboardCacheDir(appContext)
            val file = findCachedClipboardImageFile(cacheDir, item.itemId)
            if (file != null && file.exists()) {
                val uri = androidx.core.content.FileProvider.getUriForFile(
                    appContext,
                    "${appContext.packageName}.fileprovider",
                    file
                )
                intent.type = if (file.extension.equals("jpg", ignoreCase = true) || file.extension.equals("jpeg", ignoreCase = true)) {
                    "image/jpeg"
                } else {
                    "image/png"
                }
                intent.putExtra(Intent.EXTRA_STREAM, uri)
                intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            } else {
                intent.type = "text/plain"
                intent.putExtra(Intent.EXTRA_TEXT, item.previewText)
            }
        } else {
            intent.type = "text/plain"
            intent.putExtra(Intent.EXTRA_TEXT, item.previewText)
        }
        return Intent.createChooser(intent, "Share via SNOW")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }

    fun shareClipboardItem(item: ClipboardItemDto, onComplete: ((Boolean, String?) -> Unit)? = null) {
        if (item.type != "image") {
            appContext.startActivity(createShareIntentForClipboardItem(item))
            onComplete?.invoke(true, null)
            return
        }
        val cacheDir = org.snow.capabilities.ClipboardHandler.getClipboardCacheDir(appContext)
        val cached = findCachedClipboardImageFile(cacheDir, item.itemId)
        if (cached != null && cached.exists()) {
            appContext.startActivity(createShareIntentForClipboardItem(item))
            onComplete?.invoke(true, null)
            return
        }
        val client = serviceRef?.client
        val transferClient = _fileTransferClient
        val targetHost = client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
        if (client == null || transferClient == null || targetHost.isBlank()) {
            onComplete?.invoke(false, "Connect to host to share uncached clipboard image.")
            return
        }
        client.sendRequest("clipboard_buffer_apply", mapOf("item_id" to item.itemId, "target" to identity.deviceId, "stage_only" to true)) { resp ->
            if (!resp.isSuccess) {
                repoScope.launch(Dispatchers.Main) {
                    onComplete?.invoke(false, resp.error?.message ?: "Failed preparing clipboard image")
                }
                return@sendRequest
            }
            val data = resp.payload?.get("data") as? Map<*, *> ?: resp.payload
            val transferId = data?.get("transfer_id") as? String
            val sha256 = (data?.get("sha256") as? String) ?: ""
            val transferPort = (data?.get("transfer_port") as? Number)?.toInt() ?: 8766
            val mimeType = data?.get("mime_type") as? String
            if (transferId.isNullOrBlank()) {
                repoScope.launch(Dispatchers.Main) {
                    onComplete?.invoke(false, "Image transfer ID unavailable")
                }
                return@sendRequest
            }
            repoScope.launch(Dispatchers.IO) {
                val ext = if (mimeType?.contains("jpeg") == true || mimeType?.contains("jpg") == true) "jpg" else "png"
                val localFile = clipboardImageCacheFile(cacheDir, item.itemId, ext)
                org.snow.capabilities.ClipboardHandler.pruneImageCache(cacheDir, preserveFileName = localFile.name)
                val dlRes = transferClient.downloadFile(
                    serverHost = targetHost,
                    transferPort = transferPort,
                    transferId = transferId,
                    destinationFile = localFile,
                    expectedSha256 = sha256
                )
                repoScope.launch(Dispatchers.Main) {
                    if (dlRes is FileTransferClient.TransferResult.Success) {
                        appContext.startActivity(createShareIntentForClipboardItem(item))
                        onComplete?.invoke(true, null)
                    } else {
                        onComplete?.invoke(false, "Failed downloading image for sharing")
                    }
                }
            }
        }
    }

    // --- Terminal Console with Stage 19A Confirmation Tickets ---

    fun executeTerminalCommand(
        command: String,
        ticket: String? = null,
        onResult: (TerminalResult) -> Unit = {}
    ) {
        val client = serviceRef?.client
        val cleanCmd = command.trim()
        if (cleanCmd.isEmpty()) {
            onResult(TerminalResult.Error("Command cannot be empty."))
            return
        }

        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            onResult(TerminalResult.Error("Desktop core is not connected."))
            return
        }

        val currentLines = _terminalState.value.outputLines.toMutableList()
        currentLines.add(TerminalOutputLine("$ $cleanCmd", isSystem = true))

        _terminalState.value = _terminalState.value.copy(
            isRunning = true,
            activeCommand = cleanCmd,
            outputLines = currentLines
        )

        val params = mutableMapOf<String, Any>(
            "command" to cleanCmd,
            "confirmed" to true
        )
        if (ticket != null) {
            params["confirmation_ticket"] = ticket
        }

        appendLog("INFO", TAG, "Executing terminal command: $cleanCmd")

        client.sendRequest("desktop_exec", params) { resp ->
            repoScope.launch {
                val payload = resp.payload
                val data = payload?.get("data") as? Map<*, *>
                val opStatus = (data?.get("status") as? String) ?: (payload?.get("status") as? String)
                val stdout = (data?.get("stdout") as? String) ?: ""
                val stderr = (data?.get("stderr") as? String) ?: ""
                val exitCode = (data?.get("exit_code") as? Number)?.toInt()
                val err = payload?.get("error") as? String ?: data?.get("error") as? String

                if (opStatus == "CONFIRMATION_REQUIRED") {
                    val serverTicket = data?.get("confirmation_ticket") as? String
                    appendLog("WARN", TAG, "Command requires owner confirmation. Ticket received.")
                    _terminalState.value = _terminalState.value.copy(
                        isRunning = false,
                        pendingTicket = serverTicket,
                        pendingCommand = cleanCmd
                    )
                    onResult(TerminalResult.ConfirmationRequired(cleanCmd, serverTicket))
                    return@launch
                }

                val newLines = _terminalState.value.outputLines.toMutableList()
                if (stdout.isNotEmpty()) {
                    newLines.add(TerminalOutputLine(stdout, isStderr = false))
                }
                if (stderr.isNotEmpty()) {
                    newLines.add(TerminalOutputLine(stderr, isStderr = true))
                }
                if (err != null && stdout.isEmpty() && stderr.isEmpty()) {
                    newLines.add(TerminalOutputLine("Error: $err", isStderr = true))
                }

                _terminalState.value = _terminalState.value.copy(
                    isRunning = false,
                    activeCommand = null,
                    exitCode = exitCode,
                    outputLines = newLines,
                    pendingTicket = null,
                    pendingCommand = null
                )

                if (resp.isSuccess) {
                    onResult(TerminalResult.Success(stdout, stderr, exitCode ?: 0))
                } else {
                    onResult(TerminalResult.Failed(err ?: "Command execution failed", exitCode))
                }
            }
        }
    }

    fun cancelTerminalCommand() {
        _terminalState.value = _terminalState.value.copy(
            isRunning = false,
            activeCommand = null,
            pendingTicket = null,
            pendingCommand = null
        )
        appendLog("INFO", TAG, "Terminal command cancelled by user.")
    }

    // --- Files Explorer and Transfers ---

    fun listPcDirectory(
        path: String = "",
        hideHidden: Boolean = true,
        onResult: (List<PcFileItem>?, String?) -> Unit
    ) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            onResult(null, "Desktop not connected.")
            return
        }

        val params = mutableMapOf<String, Any>()
        if (path.isNotBlank()) {
            params["path"] = path
            params["directory_path"] = path
        }
        params["hide_hidden"] = hideHidden

        client.sendRequest("desktop_file_list", params) { resp ->
            repoScope.launch {
                if (resp.isSuccess) {
                    val data = resp.payload?.get("data") as? Map<*, *>
                    val currentDir = (data?.get("directory") as? String)?.takeIf { it.isNotBlank() } ?: path
                    val filesList = (data?.get("files") ?: data?.get("items")) as? List<*> ?: emptyList<Any>()

                    val items = filesList.mapNotNull { raw ->
                        val m = raw as? Map<*, *> ?: return@mapNotNull null
                        val name = m["name"] as? String ?: "unknown"
                        val type = (m["type"] as? String) ?: (m["item_type"] as? String)
                        val isDir = type.equals("directory", ignoreCase = true) ||
                            type.equals("dir", ignoreCase = true) ||
                            type.equals("folder", ignoreCase = true) ||
                            (m["is_dir"] as? Boolean == true) ||
                            (m["is_directory"] as? Boolean == true) ||
                            (m["isDirectory"] as? Boolean == true)
                        val sizeBytes = (m["size_bytes"] as? Number)?.toLong()
                            ?: (m["size"] as? Number)?.toLong() ?: 0L

                        val explicitPath = m["path"] as? String
                        val itemPath = if (!explicitPath.isNullOrBlank()) {
                            explicitPath
                        } else {
                            val sep = if (currentDir.contains("/")) "/" else "\\"
                            val cleanDir = currentDir.trimEnd('\\', '/')
                            if (cleanDir.isEmpty()) name else "$cleanDir$sep$name"
                        }

                        val isHidden = name.startsWith(".") || name.startsWith("$") ||
                            name.equals("System Volume Information", ignoreCase = true) ||
                            name.equals("Documents and Settings", ignoreCase = true) ||
                            name.equals("pagefile.sys", ignoreCase = true) ||
                            name.equals("swapfile.sys", ignoreCase = true) ||
                            name.equals("hiberfil.sys", ignoreCase = true) ||
                            name.equals("DumpStack.log.tmp", ignoreCase = true) ||
                            name.equals("Desktop.ini", ignoreCase = true) ||
                            name.equals("Thumbs.db", ignoreCase = true) ||
                            (m["is_hidden"] as? Boolean == true)

                        PcFileItem(
                            name = name,
                            path = itemPath,
                            isDirectory = isDir,
                            size = sizeBytes,
                            modified = (m["modified_at"] as? String) ?: (m["modified"] as? String),
                            isHidden = isHidden
                        )
                    }
                    val resultItems = if (hideHidden) items.filterNot { it.isHidden } else items
                    onResult(resultItems, null)
                } else {
                    val err = resp.payload?.get("error") as? String ?: "Failed listing directory"
                    onResult(null, err)
                }
            }
        }
    }

    fun startFileDownload(item: PcFileItem, onComplete: (Boolean, String?) -> Unit) {
        val client = serviceRef?.client
        val targetHost = client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
        val transferClient = resolveOrCreateTransferClient(requireConnectedAuth = true)

        if (client == null || transferClient == null || targetHost.isBlank() || _connectionState.value != ConnectionState.CONNECTED) {
            onComplete(false, "Desktop or file transfer client not ready.")
            return
        }

        appendLog("INFO", TAG, "Staging download for remote file: ${item.name}...")
        client.sendRequest("desktop_file_stage_download", mapOf("path" to item.path)) { resp ->
            repoScope.launch {
                if (resp.isSuccess) {
                    val data = resp.payload?.get("data") as? Map<*, *>
                    val transferId = data?.get("transfer_id") as? String ?: ""
                    val fileName = data?.get("file_name") as? String ?: item.name
                    val sha256 = data?.get("sha256") as? String ?: ""
                    val transferPort = (data?.get("transfer_port") as? Number)?.toInt()?.takeIf { it > 0 }
                        ?: resolveActiveTransferPort()
                    val targetHost = client.currentTargetHost

                    val stagedFile = File(safFolderManager.getStagingDir(), "${transferId}_$fileName")
                    val routeBadge = resolveTransportBadge(_connectedEndpoint.value)

                    _activeTransfer.value = ActiveTransferInfo(
                        transferId = transferId,
                        fileName = fileName,
                        direction = "DOWNLOAD",
                        bytesTransferred = 0L,
                        totalBytes = item.size,
                        status = "IN_PROGRESS",
                        transportLabel = routeBadge
                    )

                    activeDownloadJob = repoScope.launch(Dispatchers.IO) {
                        try {
                            val dlRes = transferClient.downloadFile(
                                serverHost = targetHost,
                                transferPort = transferPort,
                                transferId = transferId,
                                destinationFile = stagedFile,
                                expectedSha256 = sha256,
                                onProgress = { progress ->
                                    _activeTransfer.value = _activeTransfer.value?.copy(
                                        bytesTransferred = progress.bytesTransferred,
                                        totalBytes = progress.totalBytes
                                    )
                                }
                            )
                            repoScope.launch(Dispatchers.Main) {
                                when (dlRes) {
                                    is FileTransferClient.TransferResult.Success -> {
                                        // Commit verified bytes to configured SAF directory or Downloads/SNOW fallback
                                        val commitResult = safFolderManager.commitVerifiedDownload(stagedFile, fileName)
                                        if (commitResult.isSuccess) {
                                            val savedPath = commitResult.getOrNull() ?: fileName
                                            _activeTransfer.value = _activeTransfer.value?.copy(status = "COMPLETED")
                                            appendLog("INFO", TAG, "Download complete and committed to SAF: $savedPath")
                                            onComplete(true, savedPath)
                                            repoScope.launch {
                                                kotlinx.coroutines.delay(1500L)
                                                val cur = _activeTransfer.value
                                                if (cur?.transferId == transferId && cur.status == "COMPLETED") {
                                                    _activeTransfer.value = null
                                                }
                                            }
                                        } else {
                                            val commitErr = commitResult.exceptionOrNull()?.message ?: "Failed writing to SAF destination"
                                            _activeTransfer.value = _activeTransfer.value?.copy(status = "FAILED")
                                            appendLog("ERROR", TAG, "SAF commit failed: $commitErr")
                                            onComplete(false, commitErr)
                                        }
                                    }
                                    is FileTransferClient.TransferResult.Error -> {
                                        if (dlRes.message.equals("Transfer cancelled", ignoreCase = true)) {
                                            _activeTransfer.value = null
                                            onComplete(false, "Transfer cancelled")
                                        } else {
                                            _activeTransfer.value = _activeTransfer.value?.copy(status = "FAILED")
                                            appendLog("ERROR", TAG, "Download failed: ${dlRes.message}")
                                            onComplete(false, dlRes.message)
                                        }
                                    }
                                    is FileTransferClient.TransferResult.Duplicate -> {
                                        _activeTransfer.value = _activeTransfer.value?.copy(status = "DUPLICATE")
                                        appendLog("WARN", TAG, "Duplicate file: ${dlRes.fileName}")
                                        onComplete(true, dlRes.fileName)
                                        repoScope.launch {
                                            kotlinx.coroutines.delay(1500L)
                                            val cur = _activeTransfer.value
                                            if (cur?.transferId == transferId && cur.status == "DUPLICATE") {
                                                _activeTransfer.value = null
                                            }
                                        }
                                    }
                                }
                            }
                        } catch (_: kotlinx.coroutines.CancellationException) {
                            repoScope.launch(Dispatchers.Main) {
                                _activeTransfer.value = null
                                onComplete(false, "Transfer cancelled")
                            }
                        } catch (e: Exception) {
                            repoScope.launch(Dispatchers.Main) {
                                _activeTransfer.value = _activeTransfer.value?.copy(status = "FAILED")
                                appendLog("ERROR", TAG, "Download error: ${e.message}")
                                onComplete(false, e.message)
                            }
                        }
                    }
                } else {
                    val err = resp.payload?.get("error") as? String ?: "Failed staging file"
                    appendLog("ERROR", TAG, err)
                    onComplete(false, err)
                }
            }
        }
    }

    fun resolveActiveTransferPort(): Int {
        val client = activeClient()
        val activeId = client?.activeTargetDeviceId()
        val host = client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
        val savedMatch = _savedDevices.value.firstOrNull { d ->
            (!activeId.isNullOrBlank() && d.deviceId.equals(activeId, ignoreCase = true)) ||
                (host.isNotBlank() && d.host == host && d.port == (client?.currentTargetPort ?: d.port))
        }
        if (savedMatch != null) {
            if (savedMatch.transferPort > 0) return savedMatch.transferPort
            if (savedMatch.isPhone) return org.snow.network.AndroidPeerHostManager.DEFAULT_MEDIA_PORT
        }
        val discMatch = _discoveredPeers.value.firstOrNull { d ->
            (!activeId.isNullOrBlank() && d.deviceId.equals(activeId, ignoreCase = true)) ||
                (host.isNotBlank() && d.ipAddress == host)
        }
        if (discMatch != null && discMatch.transferPort > 0) {
            return discMatch.transferPort
        }
        val auth = _authState.value
        if (auth is AuthState.Authenticated) {
            val dtype = auth.peerDeviceType?.trim()?.lowercase()
            if (dtype == "android" || dtype == "phone") {
                return org.snow.network.AndroidPeerHostManager.DEFAULT_MEDIA_PORT
            }
        }
        if (client?.currentTargetPort == org.snow.network.AndroidPeerHostManager.DEFAULT_HOST_PORT) {
            return org.snow.network.AndroidPeerHostManager.DEFAULT_MEDIA_PORT
        }
        return 8766
    }

    fun startFileUpload(
        uri: android.net.Uri,
        fileName: String,
        fileSize: Long,
        onComplete: (Boolean, String?) -> Unit
    ) {
        val client = serviceRef?.client
        val targetHost = client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
        val transferClient = resolveOrCreateTransferClient(requireConnectedAuth = true)

        if (transferClient == null || targetHost.isBlank() || _connectionState.value != ConnectionState.CONNECTED) {
            onComplete(false, "Desktop or file transfer client not ready.")
            return
        }

        val transferPort = resolveActiveTransferPort()
        val uploadTransferId = "upload_${System.currentTimeMillis()}"
        val routeBadge = resolveTransportBadge(_connectedEndpoint.value)

        appendLog("INFO", TAG, "Starting file upload to PC: $fileName ($fileSize bytes)...")
        _activeTransfer.value = ActiveTransferInfo(
            transferId = uploadTransferId,
            fileName = fileName,
            direction = "UPLOAD",
            bytesTransferred = 0L,
            totalBytes = fileSize,
            status = "IN_PROGRESS",
            transportLabel = routeBadge
        )

        activeDownloadJob = repoScope.launch(Dispatchers.IO) {
            try {
                val upRes = transferClient.uploadUri(
                    serverHost = targetHost,
                    transferPort = transferPort,
                    uri = uri,
                    fileName = fileName,
                    fileSize = fileSize,
                    onProgress = { progress ->
                        _activeTransfer.value = _activeTransfer.value?.copy(
                            bytesTransferred = progress.bytesTransferred,
                            totalBytes = progress.totalBytes
                        )
                    }
                )
                repoScope.launch(Dispatchers.Main) {
                    when (upRes) {
                        is FileTransferClient.TransferResult.Success -> {
                            _activeTransfer.value = _activeTransfer.value?.copy(status = "COMPLETED")
                            appendLog("INFO", TAG, "Upload to PC complete: $fileName (SHA-256: ${upRes.sha256.take(8)}...)")
                            onComplete(true, fileName)
                            repoScope.launch {
                                kotlinx.coroutines.delay(1500L)
                                val cur = _activeTransfer.value
                                if (cur?.transferId == uploadTransferId && cur.status == "COMPLETED") {
                                    _activeTransfer.value = null
                                }
                            }
                        }
                        is FileTransferClient.TransferResult.Duplicate -> {
                            _activeTransfer.value = _activeTransfer.value?.copy(status = "DUPLICATE")
                            appendLog("WARN", TAG, "File already exists on PC: $fileName")
                            onComplete(true, fileName)
                            repoScope.launch {
                                kotlinx.coroutines.delay(1500L)
                                val cur = _activeTransfer.value
                                if (cur?.transferId == uploadTransferId && cur.status == "DUPLICATE") {
                                    _activeTransfer.value = null
                                }
                            }
                        }
                        is FileTransferClient.TransferResult.Error -> {
                            if (upRes.message.equals("Transfer cancelled", ignoreCase = true)) {
                                _activeTransfer.value = null
                                onComplete(false, "Transfer cancelled")
                            } else {
                                _activeTransfer.value = _activeTransfer.value?.copy(status = "FAILED")
                                appendLog("ERROR", TAG, "Upload failed: ${upRes.message}")
                                onComplete(false, upRes.message)
                            }
                        }
                    }
                }
            } catch (_: kotlinx.coroutines.CancellationException) {
                repoScope.launch(Dispatchers.Main) {
                    _activeTransfer.value = null
                    onComplete(false, "Transfer cancelled")
                }
            } catch (e: Exception) {
                repoScope.launch(Dispatchers.Main) {
                    _activeTransfer.value = _activeTransfer.value?.copy(status = "FAILED")
                    appendLog("ERROR", TAG, "Upload error: ${e.message}")
                    onComplete(false, e.message)
                }
            }
        }
    }

    fun cancelActiveTransfer() {
        val active = _activeTransfer.value ?: return
        appendLog("INFO", TAG, "User cancelled active transfer: ${active.fileName}")
        serviceRef?.transferClient?.cancelActiveTransfer()
        _fileTransferClient?.cancelActiveTransfer()
        activeDownloadJob?.cancel()
        activeDownloadJob = null
        _activeTransfer.value = null
    }

    fun dismissActiveTransfer() {
        val current = _activeTransfer.value ?: return
        if (current.status == "IN_PROGRESS" || current.status == "STARTING") {
            cancelActiveTransfer()
        } else {
            _activeTransfer.value = null
        }
    }

    // --- Logging ---

    fun appendLog(level: String, tag: String, message: String) {
        val entry = UiLogEntry(
            timestamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date()),
            level = level,
            tag = tag,
            message = message
        )
        val updated = _logs.value.takeLast(100) + entry
        _logs.value = updated
    }

    fun clearLogs() {
        _logs.value = emptyList()
    }

    // --- Approvals Feed (Phase 24) ---

    fun onApprovalEventReceived() {
        refreshPendingApprovals(force = true)
    }

    fun setAndroidRemoteMcpEnabled(enabled: Boolean) {
        appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(org.snow.mcp.AndroidRemoteMcpController.PREF_KEY_ANDROID_REMOTE_MCP_ENABLED, enabled)
            .apply()
        _androidRemoteMcpEnabled.value = enabled
        serviceRef?.androidRemoteMcpController?.setEnabled(enabled)
    }

    fun revokeAuthorizedOAuthClient(clientId: String): Boolean {
        val ok = serviceRef?.androidRemoteMcpController?.revokeAuthorizedClient(clientId) ?: false
        syncMergedPendingApprovals()
        return ok
    }

    fun syncMergedPendingApprovals(remoteItems: List<PendingApprovalItem>? = null) {
        if (remoteItems != null) {
            lastCorePendingApprovals = remoteItems
        } else if (_authState.value !is AuthState.Authenticated) {
            lastCorePendingApprovals = emptyList()
        }
        val localItems = serviceRef?.androidRemoteMcpController?.listLocalApprovalItems().orEmpty()
        val combined = (localItems + lastCorePendingApprovals).distinctBy { it.requestId }
        _pendingApprovals.value = combined
        _pendingApprovalsCount.value = combined.size
    }

    fun refreshPendingApprovals(
        force: Boolean = false,
        callback: ((Result<List<PendingApprovalItem>>) -> Unit)? = null
    ) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED || _authState.value !is AuthState.Authenticated) {
            syncMergedPendingApprovals(emptyList())
            callback?.invoke(Result.success(_pendingApprovals.value))
            return
        }
        if (!approvalsFetchInFlight.compareAndSet(false, true)) {
            if (force) {
                approvalsPendingQueued.set(true)
            }
            callback?.invoke(Result.success(_pendingApprovals.value))
            return
        }

        val epoch = approvalsEpoch.get()
        client.sendRequest("approval_list", emptyMap()) { resp ->
            repoScope.launch {
                try {
                    if (resp.isSuccess) {
                        val rawList = resp.payload?.get("requests") as? List<*> ?: emptyList<Any>()
                        val items = rawList.filterIsInstance<Map<String, Any?>>().map { m ->
                            PendingApprovalItem(
                                requestId = m["request_id"] as? String ?: "",
                                principal = m["principal"] as? String ?: "AI_MCP",
                                action = m["action"] as? String ?: "",
                                targetDevice = m["target_device"] as? String ?: "local",
                                riskLevel = m["risk_level"] as? String ?: "MEDIUM",
                                reason = m["reason"] as? String ?: "",
                                timeRemainingSeconds = (m["time_remaining_seconds"] as? Number)?.toDouble() ?: 0.0,
                                sanitizedParams = (m["sanitized_params"] as? Map<*, *>)?.entries?.associate {
                                    it.key.toString() to it.value
                                } ?: emptyMap()
                            )
                        }
                        if (approvalsEpoch.get() == epoch && _authState.value is AuthState.Authenticated) {
                            syncMergedPendingApprovals(items)
                        }
                        callback?.invoke(Result.success(_pendingApprovals.value))
                    } else {
                        syncMergedPendingApprovals()
                        val err = resp.error?.message ?: (resp.payload?.get("error") as? String) ?: "Failed fetching approvals"
                        callback?.invoke(Result.failure(RuntimeException(err)))
                    }
                } finally {
                    approvalsFetchInFlight.set(false)
                    if (approvalsPendingQueued.getAndSet(false) &&
                        approvalsEpoch.get() == epoch &&
                        _authState.value is AuthState.Authenticated
                    ) {
                        refreshPendingApprovals(force = false)
                    }
                }
            }
        }
    }

    fun fetchPendingApprovals(callback: (Result<List<PendingApprovalItem>>) -> Unit) {
        refreshPendingApprovals(force = true, callback = callback)
    }

    fun resolveApproval(requestId: String, decision: String, callback: (Result<String>) -> Unit) {
        val cleanDecision = decision.trim().uppercase()
        val localResult = serviceRef?.androidRemoteMcpController?.tryResolveLocalApproval(requestId, cleanDecision)
        if (localResult != null) {
            if (localResult) {
                syncMergedPendingApprovals()
                callback(Result.success(cleanDecision))
            } else {
                callback(Result.failure(IllegalStateException("Approval request expired or already resolved.")))
            }
            return
        }

        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            callback(Result.failure(IllegalStateException("Not connected to SNOW Desktop Core.")))
            return
        }

        val data = mapOf("request_id" to requestId, "decision" to cleanDecision)
        client.sendRequest("approval_resolve", data) { resp ->
            repoScope.launch {
                if (resp.isSuccess) {
                    val remaining = lastCorePendingApprovals.filter { it.requestId != requestId }
                    syncMergedPendingApprovals(remaining)
                    refreshPendingApprovals(force = true)
                    val msg = resp.payload?.get("message") as? String ?: cleanDecision
                    callback(Result.success(msg))
                } else {
                    val err = resp.error?.message ?: (resp.payload?.get("message") as? String) ?: "Resolution failed"
                    callback(Result.failure(RuntimeException(err)))
                }
            }
        }
    }

    // --- Direct Phone-to-Phone Host Mode (Phase 27) ---

    fun isPeerHostEnabled(): Boolean = serviceRef?.peerHostManager?.isHostModeSettingEnabled() ?: false
    fun isPeerHostActive(): Boolean = serviceRef?.peerHostManager?.isHostModeActive() ?: false
    fun getPeerHostManager(): org.snow.network.AndroidPeerHostManager? = serviceRef?.peerHostManager

    fun getCachedClipboardImageFile(itemId: String): File? {
        val cacheDir = org.snow.capabilities.ClipboardHandler.getClipboardCacheDir(appContext)
        return findCachedClipboardImageFile(cacheDir, itemId)
    }

    private fun prefetchClipboardThumbnails(items: List<ClipboardItemDto>) {
        val client = serviceRef?.client ?: return
        val transferClient = _fileTransferClient ?: return
        val targetHost = client.currentTargetHost.takeIf { it.isNotBlank() } ?: connectedHost
        if (targetHost.isBlank()) return

        val cacheDir = org.snow.capabilities.ClipboardHandler.getClipboardCacheDir(appContext)
        items.filter { it.type == "image" && it.itemId.isNotBlank() && it.sizeBytes in 1L..MAX_CLIPBOARD_IMAGE_BYTES }
            .take(4)
            .forEach { item ->
                if (findCachedClipboardImageFile(cacheDir, item.itemId) != null) return@forEach
                if (!inFlightThumbnails.add(item.itemId)) return@forEach

                client.sendRequest(
                    "clipboard_buffer_apply",
                    mapOf("item_id" to item.itemId, "target" to identity.deviceId, "stage_only" to true)
                ) { resp ->
                    if (!resp.isSuccess) {
                        inFlightThumbnails.remove(item.itemId)
                        return@sendRequest
                    }
                    val data = resp.payload?.get("data") as? Map<*, *> ?: resp.payload
                    val transferId = data?.get("transfer_id") as? String
                    val sha256 = (data?.get("sha256") as? String) ?: ""
                    val transferPort = (data?.get("transfer_port") as? Number)?.toInt() ?: 8766
                    val mimeType = data?.get("mime_type") as? String
                    if (transferId.isNullOrBlank()) {
                        inFlightThumbnails.remove(item.itemId)
                        return@sendRequest
                    }
                    repoScope.launch(Dispatchers.IO) {
                        try {
                            val ext = if (mimeType?.contains("jpeg") == true || mimeType?.contains("jpg") == true) "jpg" else "png"
                            val localFile = clipboardImageCacheFile(cacheDir, item.itemId, ext)
                            val dlRes = transferClient.downloadFile(
                                serverHost = targetHost,
                                transferPort = transferPort,
                                transferId = transferId,
                                destinationFile = localFile,
                                expectedSha256 = sha256
                            )
                            if (dlRes is FileTransferClient.TransferResult.Success) {
                                _clipboardThumbnailVersion.value = _clipboardThumbnailVersion.value + 1
                            }
                        } finally {
                            inFlightThumbnails.remove(item.itemId)
                        }
                    }
                }
            }
    }

    @JvmOverloads
    fun generatePeerHostQrJson(includePin: Boolean = false): String? {
        val service = serviceRef ?: return null
        val hubUrl = try { getDefaultHubUrl() } catch (_: Exception) { null }
        return service.peerHostManager.generatePairingQrJson(
            localDeviceId = identity.deviceId,
            snowId = canonicalSnowId,
            networkId = getEffectiveNetworkId(),
            version = 2,
            hubUrl = hubUrl,
            includePin = includePin
        )
    }

    @JvmOverloads
    fun preparePeerHostPairingQr(includePin: Boolean = false, onReady: (qrJson: String?, error: String?) -> Unit) {
        val service = serviceRef
        if (service == null) {
            onReady(null, "Background service starting; retry in a moment.")
            return
        }
        val mgr = service.peerHostManager
        val hubUrl = try { getDefaultHubUrl() } catch (_: Exception) { null }
        val existing = mgr.generatePairingQrJson(
            localDeviceId = identity.deviceId,
            snowId = canonicalSnowId,
            networkId = getEffectiveNetworkId(),
            version = 2,
            hubUrl = hubUrl,
            includePin = includePin
        )
        if (!existing.isNullOrBlank()) {
            onReady(existing, null)
            return
        }
        repoScope.launch(Dispatchers.IO) {
            mgr.setHostModeSettingEnabled(true)
            service.startPeerHost()
            val generated = mgr.generatePairingQrJson(
                localDeviceId = identity.deviceId,
                snowId = canonicalSnowId,
                networkId = getEffectiveNetworkId(),
                version = 2,
                hubUrl = hubUrl,
                includePin = includePin
            )
            repoScope.launch(Dispatchers.Main) {
                if (!generated.isNullOrBlank()) {
                    onReady(generated, null)
                } else {
                    val err = mgr.hostState.value.errorMessage
                        ?: "Connect to Wi-Fi or local network to generate pairing QR."
                    onReady(null, err)
                }
            }
        }
    }

    fun cancelPeerHostPairing() {
        serviceRef?.peerHostManager?.cancelPairingPin()
    }

    fun startPeerHost() {
        val intent = Intent(appContext, SnowForegroundService::class.java).apply {
            action = SnowForegroundService.ACTION_START_PEER_HOST
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            appContext.startForegroundService(intent)
        } else {
            appContext.startService(intent)
        }
    }

    fun stopPeerHost() {
        val intent = Intent(appContext, SnowForegroundService::class.java).apply {
            action = SnowForegroundService.ACTION_STOP_PEER_HOST
        }
        appContext.startService(intent)
    }

    fun generatePeerHostPin(): String? {
        return serviceRef?.peerHostManager?.generatePairingPin()
    }

    // --- Phase 30 / Stage 4A: Cross-Network Federation Parity ---

    fun createFederationInvite(
        allowedCapabilities: List<String>? = null,
        allowedDeviceIds: List<String>? = null,
        ttlSeconds: Int = 600,
        grantTtlSeconds: Int = 86400,
        onComplete: (Boolean, Map<String, Any?>?, String?) -> Unit
    ) {
        val client = serviceRef?.client
        val availability = evaluateShareCodeEligibility(_connectionState.value, _authState.value)
        if (client == null || !availability.allowed) {
            onComplete(false, null, availability.reason ?: "Desktop not connected.")
            return
        }

        val data = mutableMapOf<String, Any>(
            "ttl_seconds" to ttlSeconds,
            "grant_ttl_seconds" to grantTtlSeconds
        )
        allowedCapabilities?.let { data["allowed_capabilities"] = it }
        allowedDeviceIds?.let { data["allowed_device_ids"] = it }

        client.sendRequest("federation_create_invite", data) { resp ->
            repoScope.launch {
                if (resp.isSuccess) {
                    onComplete(true, resp.payload, null)
                } else {
                    val err = resp.error?.message ?: "Failed to create federation invite."
                    onComplete(false, null, err)
                }
            }
        }
    }

    fun acceptFederationInvite(
        inviteCode: String,
        peerNetworkId: String? = null,
        peerNetworkName: String? = null,
        onComplete: (Boolean, Map<String, Any?>?, String?) -> Unit
    ) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            onComplete(false, null, "Desktop not connected.")
            return
        }

        val data = mutableMapOf<String, Any>("code" to inviteCode)
        peerNetworkId?.let { data["peer_network_id"] = it }
        peerNetworkName?.let { data["peer_network_name"] = it }

        client.sendRequest("federation_accept_invite", data) { resp ->
            repoScope.launch {
                if (resp.isSuccess) {
                    onComplete(true, resp.payload, null)
                } else {
                    val err = resp.error?.message ?: "Failed to accept federation invite."
                    onComplete(false, null, err)
                }
            }
        }
    }

    fun listFederationGrants(
        activeOnly: Boolean = false,
        onComplete: (Boolean, List<Map<String, Any?>>?, String?) -> Unit
    ) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            onComplete(false, null, "Desktop not connected.")
            return
        }

        client.sendRequest("federation_list_grants", mapOf("active_only" to activeOnly)) { resp ->
            repoScope.launch {
                if (resp.isSuccess) {
                    @Suppress("UNCHECKED_CAST")
                    val grants = resp.payload?.get("grants") as? List<Map<String, Any?>> ?: emptyList()
                    onComplete(true, grants, null)
                } else {
                    val err = resp.error?.message ?: "Failed to list federation grants."
                    onComplete(false, null, err)
                }
            }
        }
    }

    fun revokeFederationGrant(
        grantId: String,
        reason: String = "Revoked by Android owner",
        onComplete: (Boolean, String?) -> Unit
    ) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            onComplete(false, "Desktop not connected.")
            return
        }

        client.sendRequest("federation_revoke", mapOf("grant_id" to grantId, "reason" to reason)) { resp ->
            repoScope.launch {
                if (resp.isSuccess) {
                    onComplete(true, null)
                } else {
                    val err = resp.error?.message ?: "Failed to revoke federation grant."
                    onComplete(false, err)
                }
            }
        }
    }

    fun federationKillSwitch(
        reason: String = "Emergency Global Kill Switch Activated from Android",
        onComplete: (Boolean, String?) -> Unit
    ) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            onComplete(false, "Desktop not connected.")
            return
        }

        client.sendRequest("federation_kill_switch", mapOf("reason" to reason)) { resp ->
            repoScope.launch {
                if (resp.isSuccess) {
                    onComplete(true, null)
                } else {
                    val err = resp.error?.message ?: "Failed to activate federation kill switch."
                    onComplete(false, err)
                }
            }
        }
    }

    // --- Direct App Update Engine ---

    internal fun extractHostFromEndpoint(endpoint: String?): String? {
        if (endpoint.isNullOrBlank()) return null
        val trimmed = endpoint.trim()

        try {
            val uri = if (trimmed.startsWith("relay:", ignoreCase = true)) {
                java.net.URI("wss://${trimmed.substring("relay:".length).trimStart('/')}")
            } else if (!trimmed.contains("://")) {
                java.net.URI("dummy://$trimmed")
            } else {
                java.net.URI(trimmed)
            }

            val rawHost = uri.host
            if (!rawHost.isNullOrBlank()) {
                val host = if (rawHost.startsWith("[") && rawHost.endsWith("]")) {
                    rawHost.substring(1, rawHost.length - 1)
                } else {
                    rawHost
                }
                val lower = host.lowercase()
                if (lower != "wss" && lower != "relay" && lower != "ws" && lower != "http" && lower != "https") {
                    return host
                }
            }
        } catch (_: Exception) {
            // Fall through to manual parsing
        }

        // Safe fallback string parser
        var clean = trimmed
        if (clean.startsWith("relay:", ignoreCase = true)) {
            clean = clean.substring("relay:".length)
        }
        if (clean.contains("://")) {
            clean = clean.substringAfter("://")
        }
        clean = clean.trimStart('/').substringBefore("/")
        if (clean.startsWith("[")) {
            val closing = clean.indexOf("]")
            if (closing != -1) {
                return clean.substring(1, closing)
            }
        }
        val candidate = if (clean.contains(":")) clean.substringBefore(":") else clean
        val candidateTrimmed = candidate.trim()
        if (candidateTrimmed.isNotEmpty()) {
            val lower = candidateTrimmed.lowercase()
            if (lower != "wss" && lower != "relay" && lower != "ws" && lower != "http" && lower != "https") {
                return candidateTrimmed
            }
        }
        return null
    }

    fun resolveActiveConnectedHost(): String? {
        val clientHost = serviceRef?.client?.currentTargetHost?.takeIf { it.isNotBlank() }
        val parsedClientHost = extractHostFromEndpoint(clientHost)
        if (parsedClientHost != null) return parsedClientHost

        val ep = _connectedEndpoint.value?.takeIf { it.isNotBlank() }
        val parsedEp = extractHostFromEndpoint(ep)
        if (parsedEp != null) return parsedEp

        val ch = connectedHost.takeIf { it.isNotBlank() }
        val parsedCh = extractHostFromEndpoint(ch)
        if (parsedCh != null) return parsedCh

        if (_connectionState.value == ConnectionState.CONNECTED) {
            return "127.0.0.1"
        }

        val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
        val lastHost = prefs.getString("last_connected_host", null)?.takeIf { it.isNotBlank() }
        val parsedLastHost = extractHostFromEndpoint(lastHost)
        if (parsedLastHost != null) return parsedLastHost

        val savedDev = _savedDevices.value.firstOrNull()
        if (savedDev != null) {
            val devHost = savedDev.recentEndpoints.firstOrNull()?.host ?: savedDev.host
            val parsedDevHost = extractHostFromEndpoint(devHost)
            if (parsedDevHost != null) return parsedDevHost
        }

        return "127.0.0.1"
    }

    fun checkAppUpdate(onResult: (FileTransferClient.AppUpdateInfo?) -> Unit) {
        val host = resolveActiveConnectedHost()
        val transferClient = resolveOrCreateTransferClient(requireConnectedAuth = false)
            ?: createConfiguredTransferClient()
        if (host.isNullOrBlank()) {
            appendLog("WARN", TAG, "Cannot check app update: no active desktop endpoint resolved")
            onResult(null)
            return
        }

        repoScope.launch {
            try {
                val res = transferClient.getAppUpdateInfo(host, 8766)
                if (res.isSuccess) {
                    val rawInfo = res.getOrNull()
                    val strictlyNewer = isUpdateStrictlyNewer(
                        rawInfo,
                        org.snow.BuildConfig.VERSION_CODE,
                        org.snow.BuildConfig.VERSION_NAME
                    )
                    val checkedInfo = rawInfo?.copy(available = strictlyNewer)
                    appendLog("INFO", TAG, "App update check result: available=$strictlyNewer, remoteCode=${rawInfo?.versionCode}, localCode=${org.snow.BuildConfig.VERSION_CODE}")
                    onResult(checkedInfo)
                } else {
                    appendLog("WARN", TAG, "App update check failed on $host:8766: ${res.exceptionOrNull()?.message}")
                    onResult(null)
                }
            } catch (e: Exception) {
                appendLog("ERROR", TAG, "App update check error: ${e.message}")
                onResult(null)
            }
        }
    }

    fun downloadAndInstallUpdate(
        updateInfo: FileTransferClient.AppUpdateInfo,
        onProgress: (Int) -> Unit,
        onComplete: (Boolean, String?) -> Unit
    ) {
        val host = resolveActiveConnectedHost()
        val transferClient = resolveOrCreateTransferClient(requireConnectedAuth = false)
            ?: createConfiguredTransferClient()
        if (host.isNullOrBlank()) {
            onComplete(false, "No active desktop endpoint resolved.")
            return
        }

        repoScope.launch {
            try {
                val updatesDir = File(appContext.cacheDir, "updates")
                updatesDir.mkdirs()
                val targetApk = File(updatesDir, "snow-update-${updateInfo.versionCode}.apk")

                appendLog("INFO", TAG, "Starting direct signed APK download (${updateInfo.sizeBytes} bytes)...")
                val downloadRes = transferClient.downloadAppApk(
                    serverHost = host,
                    transferPort = 8766,
                    destFile = targetApk,
                    expectedSha256 = updateInfo.sha256,
                    onProgress = onProgress
                )

                if (!downloadRes.isSuccess) {
                    val err = downloadRes.exceptionOrNull()?.message ?: "Download failed"
                    appendLog("ERROR", TAG, "APK download failed: $err")
                    onComplete(false, err)
                    return@launch
                }

                val apkFile = downloadRes.getOrNull()
                if (apkFile == null || !apkFile.exists()) {
                    onComplete(false, "Downloaded APK file not found.")
                    return@launch
                }

                // Verify package signature & package name
                if (!verifyApkSignature(apkFile)) {
                    apkFile.delete()
                    val err = "Security violation: Downloaded APK signature does not match installed application."
                    appendLog("ERROR", TAG, err)
                    onComplete(false, err)
                    return@launch
                }

                appendLog("INFO", TAG, "APK verified successfully; launching package installer.")
                launchApkInstaller(apkFile)
                onComplete(true, null)
            } catch (e: Exception) {
                appendLog("ERROR", TAG, "Error during update download/install: ${e.message}")
                onComplete(false, e.message)
            }
        }
    }

    fun verifyApkSignature(apkFile: File): Boolean {
        try {
            val pm = appContext.packageManager
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES
            } else {
                @Suppress("DEPRECATION")
                android.content.pm.PackageManager.GET_SIGNATURES
            }

            val pkgInfo = pm.getPackageArchiveInfo(apkFile.absolutePath, flags) ?: return false

            if (pkgInfo.packageName != appContext.packageName) {
                appendLog("ERROR", TAG, "APK package name mismatch: ${pkgInfo.packageName} != ${appContext.packageName}")
                return false
            }

            val installedPkgInfo = pm.getPackageInfo(appContext.packageName, flags)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val apkSigner = pkgInfo.signingInfo ?: return false
                val installedSigner = installedPkgInfo.signingInfo ?: return false
                val apkSigs = apkSigner.apkContentsSigners
                val installedSigs = installedSigner.apkContentsSigners
                if (apkSigs.isEmpty() || installedSigs.isEmpty()) return false
                return apkSigs[0] == installedSigs[0]
            } else {
                @Suppress("DEPRECATION")
                val apkSigs = pkgInfo.signatures ?: return false
                @Suppress("DEPRECATION")
                val installedSigs = installedPkgInfo.signatures ?: return false
                if (apkSigs.isEmpty() || installedSigs.isEmpty()) return false
                return apkSigs[0] == installedSigs[0]
            }
        } catch (e: Exception) {
            appendLog("ERROR", TAG, "Failed verifying APK signature: ${e.message}")
            return false
        }
    }

    fun launchApkInstaller(apkFile: File) {
        try {
            if (safFolderManager.getDestinationUri() != null) {
                try {
                    val tempCopy = File(apkFile.parentFile ?: appContext.cacheDir, "saf_copy_${apkFile.name}")
                    apkFile.copyTo(tempCopy, overwrite = true)
                    safFolderManager.commitVerifiedDownload(tempCopy, apkFile.name)
                    appendLog("INFO", TAG, "Copied verified update APK '${apkFile.name}' to your configured SNOW SAF folder.")
                } catch (e: Exception) {
                    appendLog("WARN", TAG, "Optional SAF copy of update APK skipped: ${e.message}")
                }
            }
            val uri = androidx.core.content.FileProvider.getUriForFile(
                appContext,
                "org.snow.fileprovider",
                apkFile
            )
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            appContext.startActivity(intent)
        } catch (e: SecurityException) {
            appendLog("WARN", TAG, "Android blocked direct in-app APK installer launch: ${e.message}")
            repoScope.launch {
                Toast.makeText(
                    appContext,
                    "Verified update saved as '${apkFile.name}'. Open it in your Files app to install.",
                    Toast.LENGTH_LONG
                ).show()
            }
        } catch (e: android.content.ActivityNotFoundException) {
            appendLog("WARN", TAG, "No package installer activity available for APK: ${e.message}")
            repoScope.launch {
                Toast.makeText(
                    appContext,
                    "Verified update saved as '${apkFile.name}'. Open it in your Files app to install.",
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }
}

// --- Data Models ---

data class PendingApprovalItem(
    val requestId: String,
    val principal: String,
    val action: String,
    val targetDevice: String,
    val riskLevel: String,
    val reason: String,
    val timeRemainingSeconds: Double,
    val sanitizedParams: Map<String, Any?> = emptyMap()
)

data class DeviceEndpoint(
    val host: String,
    val port: Int,
    val lastSuccessTimestamp: Long = System.currentTimeMillis()
)

data class PendingNetworkDecision(
    val txId: String,
    val peerDeviceId: String,
    val peerDeviceName: String,
    val localNetworkId: String,
    val remoteNetworkId: String,
    val networkAction: String = "DECISION_REQUIRED",
    val localApproved: Boolean = false
)

data class SavedDevice(
    val deviceId: String,
    val deviceName: String,
    val host: String,
    val port: Int,
    val lastSeen: String? = null,
    val trustTier: String = "PEER",
    val certFingerprint: String? = null,
    val recentEndpoints: List<DeviceEndpoint> = emptyList(),
    val connectionMode: String = "auto",
    val snowId: String? = null,
    val deviceType: String = "pc",
    val permissionProfile: String = "not_allowed",
    val transferPort: Int = 8766,
    val relationship: String = "member",
    val networkId: String? = null
) {
    val isPhone: Boolean get() = deviceType.equals("phone", ignoreCase = true) || deviceType.equals("android", ignoreCase = true)
    val isPc: Boolean get() = !isPhone
}

data class ActiveTransferInfo(
    val transferId: String,
    val fileName: String,
    val direction: String,
    val bytesTransferred: Long,
    val totalBytes: Long,
    val status: String,
    val transportLabel: String = "Wi-Fi • Zero Data"
)

fun formatTransferBytes(bytes: Long): String {
    val safe = if (bytes < 0L) 0L else bytes
    return when {
        safe < 1024L -> "$safe B"
        safe < 1024L * 1024L -> String.format(java.util.Locale.US, "%.1f KB", safe / 1024.0)
        safe < 1024L * 1024L * 1024L -> String.format(java.util.Locale.US, "%.1f MB", safe / (1024.0 * 1024.0))
        else -> String.format(java.util.Locale.US, "%.2f GB", safe / (1024.0 * 1024.0 * 1024.0))
    }
}

fun resolveTransportBadge(endpoint: String?): String {
    val ep = endpoint?.trim().orEmpty()
    return when {
        ep.startsWith("127.0.0.1") || ep.startsWith("localhost") -> "USB • Zero Data"
        ep.contains("relay", ignoreCase = true) ||
            ep.contains("tunnel", ignoreCase = true) ||
            ep.contains("hub", ignoreCase = true) ||
            ep.contains(":8770") -> "Remote • Uses Data"
        else -> "Wi-Fi • Zero Data"
    }
}

data class PhoneTelemetry(
    val batteryPercent: Int,
    val isCharging: Boolean,
    val temperatureCelsius: Float?,
    val isAvailable: Boolean,
    val lastUpdated: Long,
    val ramTotalBytes: Long? = null,
    val ramAvailableBytes: Long? = null,
    val storageTotalBytes: Long? = null,
    val storageAvailableBytes: Long? = null
) {
    companion object {
        val UNAVAILABLE = PhoneTelemetry(0, false, null, false, 0L)
    }
}

data class PcTelemetry(
    val isConnected: Boolean,
    val batteryPercent: Int?,
    val isCharging: Boolean?,
    val hostname: String?,
    val os: String?,
    val cpuPercent: Double? = null,
    val memoryPercent: Double? = null,
    val isAvailable: Boolean,
    val lastUpdated: Long
) {
    companion object {
        val UNAVAILABLE = PcTelemetry(false, null, null, null, null, null, null, false, 0L)
    }
}

data class TerminalOutputLine(
    val text: String,
    val isStderr: Boolean = false,
    val isSystem: Boolean = false
)

data class TerminalExecutionState(
    val isRunning: Boolean = false,
    val activeCommand: String? = null,
    val exitCode: Int? = null,
    val outputLines: List<TerminalOutputLine> = emptyList(),
    val pendingTicket: String? = null,
    val pendingCommand: String? = null
)

sealed class TerminalResult {
    data class Success(val stdout: String, val stderr: String, val exitCode: Int) : TerminalResult()
    data class Failed(val error: String, val exitCode: Int?) : TerminalResult()
    data class Error(val message: String) : TerminalResult()
    data class ConfirmationRequired(val command: String, val ticket: String?) : TerminalResult()
}

data class PcFileItem(
    val name: String,
    val path: String,
    val isDirectory: Boolean,
    val size: Long,
    val modified: String?,
    val isHidden: Boolean
)

data class UiLogEntry(
    val timestamp: String,
    val level: String,
    val tag: String,
    val message: String
)
