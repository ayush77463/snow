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
        const val PREF_KEY_PERMISSION_PROFILE = "permission_profile"

        fun normalizeAccessProfile(raw: String): String {
            return when (raw.trim().lowercase()) {
                "files_and_clipboard", "files & clipboard", "files_only", "files & clip" -> "files_and_clipboard"
                "clipboard_only", "clipboard only", "read_only", "clip only" -> "clipboard_only"
                else -> "full_control"
            }
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
    val screenshotObserver: ScreenshotObserver by lazy { ScreenshotObserver(appContext) }

    // Persistent storage helpers
    val identity: DeviceIdentity by lazy { DeviceIdentity.getOrCreate(appContext) }
    val canonicalSnowId: String by lazy { deriveCanonicalSnowId(identity.deviceId) }
    val tokenStorage: SharedPreferencesTokenStorage by lazy { SharedPreferencesTokenStorage(appContext) }
    val certPinStorage: EncryptedCertPinStorage by lazy { EncryptedCertPinStorage(appContext) }
    val safFolderManager: SafFolderManager by lazy { SafFolderManager(appContext) }
    val pairingFlow: PairingFlow by lazy { PairingFlow(identity, tokenStorage) }

    // --- StateFlows ---

    private val _connectionState = MutableStateFlow(ConnectionState.DISCONNECTED)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _connectedEndpoint = MutableStateFlow<String?>(null)
    val connectedEndpoint: StateFlow<String?> = _connectedEndpoint.asStateFlow()
    val currentTargetHost: String get() = connectedHost.ifBlank { serviceRef?.client?.currentTargetHost ?: "" }

    private val _authState = MutableStateFlow<AuthState>(AuthState.Disconnected)
    val authState: StateFlow<AuthState> = _authState.asStateFlow()

    val pairingState: StateFlow<PairingState> get() = pairingFlow.state

    private val _discoveredPeers = MutableStateFlow<List<DiscoveredPeer>>(emptyList())
    val discoveredPeers: StateFlow<List<DiscoveredPeer>> = _discoveredPeers.asStateFlow()

    private val _savedDevices = MutableStateFlow<List<SavedDevice>>(emptyList())
    val savedDevices: StateFlow<List<SavedDevice>> = _savedDevices.asStateFlow()

    private val _activeTransfer = MutableStateFlow<ActiveTransferInfo?>(null)
    val activeTransfer: StateFlow<ActiveTransferInfo?> = _activeTransfer.asStateFlow()

    private val _pendingApprovalsCount = MutableStateFlow(0)
    val pendingApprovalsCount: StateFlow<Int> = _pendingApprovalsCount.asStateFlow()

    private val _phoneTelemetry = MutableStateFlow(PhoneTelemetry.UNAVAILABLE)
    val phoneTelemetry: StateFlow<PhoneTelemetry> = _phoneTelemetry.asStateFlow()

    private val _pcTelemetry = MutableStateFlow(PcTelemetry.UNAVAILABLE)
    val pcTelemetry: StateFlow<PcTelemetry> = _pcTelemetry.asStateFlow()

    private val _terminalState = MutableStateFlow(TerminalExecutionState())
    val terminalState: StateFlow<TerminalExecutionState> = _terminalState.asStateFlow()

    private val _logs = MutableStateFlow<List<UiLogEntry>>(emptyList())
    val logs: StateFlow<List<UiLogEntry>> = _logs.asStateFlow()

    // Phase 26A Live Screen Sharing state
    private val _screenShareState = MutableStateFlow(LiveScreenStreamHandler.StreamState.IDLE)
    val screenShareState: StateFlow<LiveScreenStreamHandler.StreamState> = _screenShareState.asStateFlow()

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

    // Phase 26B Shared Clipboard Buffer DTO & State
    data class ClipboardItemDto(
        val itemId: String,
        val type: String,
        val sourceDevice: String,
        val previewText: String,
        val sizeBytes: Long,
        val timestamp: Double,
        val isPinned: Boolean
    )

    private val _clipboardBufferItems = MutableStateFlow<List<ClipboardItemDto>>(emptyList())
    val clipboardBufferItems: StateFlow<List<ClipboardItemDto>> = _clipboardBufferItems.asStateFlow()

    // Desktop Wallpaper Preview StateFlow
    private val _desktopWallpaper = MutableStateFlow<android.graphics.Bitmap?>(null)
    val desktopWallpaper: StateFlow<android.graphics.Bitmap?> = _desktopWallpaper.asStateFlow()

    // Phase 27 Direct Phone-to-Phone Peer Host state
    private val _peerHostState = MutableStateFlow(org.snow.network.PeerHostState())
    val peerHostState: StateFlow<org.snow.network.PeerHostState> = _peerHostState.asStateFlow()
    private val _permissionProfileState = MutableStateFlow("full_control")
    val permissionProfileState: StateFlow<String> = _permissionProfileState.asStateFlow()
    private var peerHostJob: Job? = null

    // Bounded retries tracking
    private var connectionAttemptCount = 0
    private var activeDownloadJob: Job? = null
    private var clientConnectionJob: Job? = null
    private var clientAuthJob: Job? = null
    private var discoveryJob: Job? = null
    private var screenShareJob: Job? = null
    private var _fileTransferClient: FileTransferClient? = null
    var connectedHost: String = ""
        private set

    init {
        loadSavedDevices()
        refreshPhoneTelemetry()
        _permissionProfileState.value = activePermissionProfile
    }

    /**
     * Bind active background service instance to this repository.
     */
    fun bindService(service: SnowForegroundService) {
        serviceRef = service
        observeClientFlows(service.client)
        observeDiscoveryFlow(service.discoveryManager)

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
        _screenShareState.value = LiveScreenStreamHandler.StreamState.IDLE
        _peerHostState.value = org.snow.network.PeerHostState()
        serviceRef = null
    }

    private fun observeClientFlows(client: SnowWebSocketClient) {
        clientConnectionJob?.cancel()
        clientConnectionJob = repoScope.launch {
            client.connectionState.collectLatest { state ->
                _connectionState.value = state
                if (state == ConnectionState.CONNECTED) {
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
                    invalidateWallpaperCache()
                }
            }
        }

        clientAuthJob?.cancel()
        clientAuthJob = repoScope.launch {
            client.authState.collectLatest { auth ->
                _authState.value = auth
                if (auth is AuthState.Authenticated) {
                    val host = client.currentTargetHost.takeIf { it.isNotBlank() } ?: connectedHost
                    val port = client.currentTargetPort
                    if (host.isNotBlank()) {
                        connectedHost = host
                    }
                    // Initialize dedicated FileTransferClient tied to this authenticated session
                    _fileTransferClient = FileTransferClient(
                        context = appContext,
                        deviceId = identity.deviceId,
                        certPinStorage = certPinStorage,
                        tokenStorage = tokenStorage,
                        useTls = true
                    )
                    // Auto-restore Instant Sync only if enabled in preferences
                    val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
                    if (prefs.getBoolean(PREF_KEY_INSTANT_SYNC, false)) {
                        toggleInstantClipboardSync(true)
                    }
                    if (prefs.getBoolean(PREF_KEY_AUTO_SYNC_SCREENSHOTS, false)) {
                        screenshotObserver.register()
                    }
                    // Fetch latest shared clipboard buffer items
                    fetchClipboardBuffer()
                    // Update identity-first saved device history and endpoint ring buffer
                    recordSuccessfulConnection(
                        host = host,
                        port = port,
                        sessionId = auth.sessionId,
                        tier = auth.trustTier,
                        peerDeviceName = auth.peerDeviceName,
                        peerDeviceType = auth.peerDeviceType
                    )
                } else {
                    _fileTransferClient = null
                    screenshotObserver.unregister()
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

    fun connect(host: String, port: Int) {
        val cleanHost = host.trim()
        if (cleanHost.isEmpty() || port !in 1..65535) {
            appendLog("ERROR", TAG, "Invalid host or port: $cleanHost:$port")
            return
        }

        val matchingDevice = _savedDevices.value.find { it.host == cleanHost && it.port == port }
        if (matchingDevice?.connectionMode == "remote_only") {
            appendLog("WARNING", TAG, "Cannot connect locally: Policy for '${matchingDevice.deviceName}' is set to remote_only.")
            _connectionState.value = ConnectionState.DISCONNECTED
            return
        }

        val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
        prefs.edit().putString("last_connected_host", cleanHost).putInt("last_connected_port", port).apply()

        // Reset retry counter on explicit manual connection attempt
        connectionAttemptCount = 0
        connectedHost = cleanHost
        _connectedEndpoint.value = "$cleanHost:$port"
        _connectionState.value = ConnectionState.CONNECTING
        appendLog("INFO", TAG, "Connecting to $cleanHost:$port...")

        val intent = Intent(appContext, SnowForegroundService::class.java).apply {
            action = SnowForegroundService.ACTION_CONNECT
            putExtra(SnowForegroundService.EXTRA_HOST, cleanHost)
            putExtra(SnowForegroundService.EXTRA_PORT, port)
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
        val intent = Intent(appContext, SnowForegroundService::class.java).apply {
            action = SnowForegroundService.ACTION_DISCONNECT
        }
        appContext.startService(intent)
        _connectedEndpoint.value = null
        connectedHost = ""
        invalidateWallpaperCache()
        _connectionState.value = ConnectionState.DISCONNECTED
    }

    fun pairDevice(pin: String, onStateChanged: ((PairingState) -> Unit)? = null) {
        val client = serviceRef?.client
        if (client == null) {
            appendLog("WARN", TAG, "Cannot pair: WebSocket client not connected.")
            return
        }
        val cleanPin = pin.trim()
        if (!pairingFlow.validatePin(cleanPin)) {
            appendLog("WARN", TAG, "PIN must be exactly 6 numeric digits.")
            return
        }
        appendLog("INFO", TAG, "Submitting pairing request...")
        pairingFlow.submitPin(cleanPin, client) { state ->
            appendLog("INFO", TAG, "Pairing state changed: $state")
            if (state is PairingState.Paired) {
                client.setAuthenticated(state.sessionId, state.trustTier, state.desktopName, state.deviceType)
                _authState.value = AuthState.Authenticated(
                    state.sessionId,
                    state.trustTier,
                    state.desktopName,
                    state.deviceType
                )
            }
            onStateChanged?.invoke(state)
        }
    }

    fun unpairDevice() {
        appendLog("INFO", TAG, "Unpairing device and clearing auth token.")
        tokenStorage.clearToken()
        _authState.value = AuthState.Disconnected
        serviceRef?.client?.disconnect()
        _connectionState.value = ConnectionState.DISCONNECTED
    }

    fun resetTrust() {
        appendLog("INFO", TAG, "Resetting all cryptographic trust (clearing certificates and auth tokens).")
        certPinStorage.clearPinnedFingerprint()
        tokenStorage.clearToken()
        _authState.value = AuthState.Disconnected
        serviceRef?.client?.disconnect()
        _connectionState.value = ConnectionState.DISCONNECTED
        clearSavedDevices()
    }

    // --- Saved Devices (Phase 20 Identity-First Mesh & Endpoint History) ---

    fun loadSavedDevices() {
        val prefsV2 = appContext.getSharedPreferences("snow_paired_devices_v2", Context.MODE_PRIVATE)
        val rawJson = prefsV2.getString("devices_json", null)
        if (!rawJson.isNullOrBlank()) {
            _savedDevices.value = deserializeSavedDevices(rawJson)
        } else {
            // Safe migration from legacy snow_settings: discard placeholder 127.0.0.1
            val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
            val savedHost = (prefs.getString("last_connected_host", "") ?: "").trim()
            val savedPort = prefs.getInt("last_connected_port", 8765)
            val token = tokenStorage.getToken()
            val pinnedFp = certPinStorage.getPinnedFingerprint()
            if (token != null) {
                val validHost = if (savedHost.isNotBlank() && savedHost != "127.0.0.1") savedHost else ""
                val endpoints = if (validHost.isNotBlank()) listOf(DeviceEndpoint(validHost, savedPort)) else emptyList()
                val migrated = SavedDevice(
                    deviceId = token.take(8),
                    deviceName = if (validHost.isNotBlank()) "Paired Desktop ($validHost)" else "Paired Desktop Core",
                    host = validHost,
                    port = savedPort,
                    lastSeen = "Active",
                    trustTier = "OWNER",
                    certFingerprint = pinnedFp,
                    recentEndpoints = endpoints
                )
                val list = listOf(migrated)
                _savedDevices.value = list
                prefsV2.edit().putString("devices_json", serializeSavedDevices(list)).apply()
            } else {
                _savedDevices.value = emptyList()
            }
        }
    }

    fun recordSuccessfulConnection(
        host: String,
        port: Int,
        sessionId: String,
        tier: String = "PEER",
        peerDeviceName: String? = null,
        peerDeviceType: String? = null
    ) {
        val cleanHost = host.trim()
        val token = tokenStorage.getToken()
        val deviceId = token?.take(8) ?: sessionId.take(8)
        val pinnedFp = certPinStorage.getPinnedFingerprint()
        val nowStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())

        val matchedDiscovered = _discoveredPeers.value.find { it.ipAddress == cleanHost }
        val rawType = peerDeviceType?.takeIf { it.isNotBlank() }
            ?: matchedDiscovered?.deviceType?.takeIf { it.isNotBlank() }
        val resolvedType = when {
            rawType != null && (rawType.equals("android", ignoreCase = true) || rawType.equals("phone", ignoreCase = true)) -> "phone"
            rawType != null -> "pc"
            else -> null
        }
        val resolvedName = peerDeviceName?.takeIf { it.isNotBlank() }
            ?: matchedDiscovered?.deviceName?.takeIf { it.isNotBlank() }

        val current = _savedDevices.value.toMutableList()
        val existingIdx = current.indexOfFirst { it.deviceId == deviceId }

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
            val effectiveTier = if (tier.equals("PEER", ignoreCase = true) && !existing.trustTier.isNullOrBlank()) {
                existing.trustTier
            } else {
                tier.uppercase()
            }
            val effectiveType = resolvedType ?: existing.deviceType
            val effectiveName = resolvedName ?: existing.deviceName
            current[existingIdx] = existing.copy(
                deviceName = effectiveName,
                deviceType = effectiveType,
                host = if (cleanHost != "127.0.0.1" || existing.host.isBlank()) cleanHost else existing.host,
                port = port,
                lastSeen = nowStr,
                trustTier = effectiveTier,
                certFingerprint = pinnedFp ?: existing.certFingerprint,
                recentEndpoints = updatedEndpoints.take(5)
            )
        } else {
            val finalType = resolvedType ?: "pc"
            val finalName = resolvedName
                ?: if (finalType == "phone") "Android Peer ($cleanHost)" else "Desktop Core ($cleanHost)"
            current.add(
                0,
                SavedDevice(
                    deviceId = deviceId,
                    deviceName = finalName,
                    host = cleanHost,
                    port = port,
                    lastSeen = nowStr,
                    trustTier = tier,
                    certFingerprint = pinnedFp,
                    recentEndpoints = updatedEndpoints.take(5),
                    deviceType = finalType
                )
            )
        }

        _savedDevices.value = current
        val prefsV2 = appContext.getSharedPreferences("snow_paired_devices_v2", Context.MODE_PRIVATE)
        prefsV2.edit().putString("devices_json", serializeSavedDevices(current)).apply()
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
        if (v != 1) {
            val err = "Unsupported QR version: $v. Expected 1."
            appendLog("ERROR", TAG, err)
            onComplete(false, err)
            return
        }

        val nodeId = payload.optString("id", "").trim()
        val port = payload.optInt("port", 8765)
        val pin = payload.optString("pin", "").trim()
        val fp = payload.optString("fp", "").replace(":", "").replace(" ", "").trim()

        if (nodeId.isEmpty() || pin.length != 6 || !pin.all { it.isDigit() } || fp.length != 64) {
            val err = "Invalid QR payload schema (missing id, invalid 6-digit pin, or invalid fingerprint)."
            appendLog("ERROR", TAG, err)
            onComplete(false, err)
            return
        }

        val rawIps = payload.optJSONArray("ips")
        val candidateIps = mutableListOf<String>()
        if (rawIps != null) {
            for (i in 0 until rawIps.length()) {
                val ipStr = rawIps.getString(i).trim()
                if (ipStr.isNotBlank() && ipStr != "127.0.0.1" && !ipStr.startsWith("169.254.")) {
                    candidateIps.add(ipStr)
                }
            }
        }

        if (candidateIps.isEmpty()) {
            val err = "No reachable candidate LAN IPs found in QR payload."
            appendLog("ERROR", TAG, err)
            onComplete(false, err)
            return
        }

        // Pinned certificate verification
        val pinnedFp = certPinStorage.getPinnedFingerprint()
        if (pinnedFp != null) {
            val cleanPinned = pinnedFp.replace(":", "").replace(" ", "").trim()
            if (!cleanPinned.equals(fp, ignoreCase = true)) {
                val err = "CRITICAL: Certificate fingerprint in QR does not match existing pinned certificate! Mismatch blocked."
                appendLog("ERROR", TAG, err)
                _authState.value = AuthState.FingerprintMismatch(pinnedFp, fp)
                onComplete(false, err)
                return
            }
        } else {
            // TOFU initial trust from scanned QR code
            certPinStorage.pinFingerprint(fp)
            appendLog("INFO", TAG, "Pinned TLS certificate fingerprint from scanned QR code.")
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

        // Connect to first candidate IP and proceed with pairing
        val targetIp = candidateIps.first()
        appendLog("INFO", TAG, "Initiating QR onboarding connection to $targetIp:$port...")
        connect(targetIp, port)

        // Schedule pairing PIN submission once WebSocket establishes connection
        repoScope.launch {
            var attempts = 0
            while (attempts < 50) {
                kotlinx.coroutines.delay(200)
                attempts++
                val state = _connectionState.value
                val auth = _authState.value
                if (state == ConnectionState.CONNECTED && auth is AuthState.Authenticated) {
                    appendLog("INFO", TAG, "Device already authenticated with desktop. Onboarding complete.")
                    recordSuccessfulConnection(targetIp, port, auth.sessionId, auth.trustTier, auth.peerDeviceName, auth.peerDeviceType)
                    onComplete(true, null)
                    return@launch
                } else if (state == ConnectionState.CONNECTED && auth is AuthState.ConnectedUnauthenticated) {
                    appendLog("INFO", TAG, "Connection established; auto-submitting pairing PIN from QR...")
                    pairDevice(pin) { pState ->
                        when (pState) {
                            is PairingState.Paired -> {
                                appendLog("INFO", TAG, "QR pairing successful [tier=${pState.trustTier}]")
                                recordSuccessfulConnection(targetIp, port, pState.sessionId, pState.trustTier, null, pState.deviceType)
                                onComplete(true, null)
                            }
                            is PairingState.WrongPin -> {
                                appendLog("ERROR", TAG, "QR pairing failed: Invalid PIN (${pState.remainingAttempts} attempts remaining)")
                                onComplete(false, pState.message)
                            }
                            is PairingState.Expired -> {
                                appendLog("ERROR", TAG, "QR pairing failed: PIN expired")
                                onComplete(false, pState.message)
                            }
                            is PairingState.Locked -> {
                                appendLog("ERROR", TAG, "QR pairing locked: Too many failed attempts")
                                onComplete(false, pState.message)
                            }
                            is PairingState.Error -> {
                                appendLog("ERROR", TAG, "QR pairing error: ${pState.message}")
                                onComplete(false, pState.message)
                            }
                            else -> {}
                        }
                    }
                    return@launch
                } else if (state == ConnectionState.DISCONNECTED && attempts > 15) {
                    onComplete(false, "Connection to $targetIp:$port timed out or failed.")
                    return@launch
                }
            }
        }
    }

    // --- Phase 5A: Unified Connection Resolution & Relay Normalization ---

    fun normalizeRelayUrl(raw: String): String = Companion.normalizeRelayUrl(raw)

    fun connectRelay(normalizedRelayUrl: String) {
        updateRemoteRelayConfig(true, normalizedRelayUrl)
        appendLog("INFO", TAG, "Configured remote relay endpoint: $normalizedRelayUrl")
    }

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

        // 1. Check SNOW ID: Full (SNW-XXXX-XXXX) or Short (SNW-XXXX, DEV-XXXX)
        val snowIdRegex = Regex("^(SNW-[A-Z0-9]{4}-[A-Z0-9]{4}|SNW-[A-Z0-9]{4}|DEV-[A-Z0-9]{4})$", RegexOption.IGNORE_CASE)
        if (snowIdRegex.matches(input)) {
            val upperSnowId = input.uppercase()
            appendLog("INFO", TAG, "Resolving connection for SNOW ID: $upperSnowId")

            val matchedPeer = _discoveredPeers.value.find { peer ->
                peer.snowId.equals(upperSnowId, ignoreCase = true) ||
                peer.deviceId.equals(upperSnowId, ignoreCase = true) ||
                (upperSnowId.length == 8 && (peer.snowId?.startsWith(upperSnowId, ignoreCase = true) == true || peer.deviceId.startsWith(upperSnowId, ignoreCase = true)))
            }
            if (matchedPeer != null) {
                appendLog("INFO", TAG, "Found discovered peer for $upperSnowId at ${matchedPeer.ipAddress}:${matchedPeer.port}")
                connect(matchedPeer.ipAddress, matchedPeer.port)
                onResult(true, "Connecting to discovered peer for $upperSnowId", "lan")
                return
            }

            val savedDev = _savedDevices.value.find { dev ->
                dev.snowId?.equals(upperSnowId, ignoreCase = true) == true ||
                dev.deviceId.equals(upperSnowId, ignoreCase = true) ||
                (upperSnowId.length == 8 && (dev.snowId?.startsWith(upperSnowId, ignoreCase = true) == true || dev.deviceId.startsWith(upperSnowId, ignoreCase = true)))
            }
            if (savedDev != null) {
                val targetHost = savedDev.recentEndpoints.firstOrNull()?.host ?: savedDev.host
                val targetPort = savedDev.recentEndpoints.firstOrNull()?.port ?: savedDev.port
                appendLog("INFO", TAG, "Found saved device for $upperSnowId: $targetHost:$targetPort")
                connect(targetHost, targetPort)
                onResult(true, "Connecting to saved device for $upperSnowId", "saved")
                return
            }

            // Fallback: If remote relay is configured and enabled, attempt connecting via Remote Relay
            val relayEndpoint = getRemoteRelayEndpoint()
            if (isRemoteRelayEnabled() && relayEndpoint.isNotBlank()) {
                appendLog("INFO", TAG, "Local resolution failed for $upperSnowId; falling back to configured Remote Relay: $relayEndpoint")
                connectRelay(relayEndpoint)
                onResult(true, "Connecting to $upperSnowId via Remote Relay", "relay")
                return
            }

            // Transport cascade fallback: USB loopback (127.0.0.1:8765) -> LAN discovery
            appendLog("INFO", TAG, "Attempting transport cascade for $upperSnowId via USB loopback...")
            connect("127.0.0.1", 8765)
            onResult(true, "Initiated transport cascade for $upperSnowId", "cascade")
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
            val obj = org.json.JSONObject()
            obj.put("deviceId", d.deviceId)
            obj.put("deviceName", d.deviceName)
            obj.put("host", d.host)
            obj.put("port", d.port)
            obj.put("lastSeen", d.lastSeen ?: "")
            obj.put("trustTier", d.trustTier)
            obj.put("certFingerprint", d.certFingerprint ?: "")
            obj.put("connectionMode", d.connectionMode)
            obj.put("snowId", d.snowId ?: "")
            obj.put("deviceType", d.deviceType)
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
                list.add(
                    SavedDevice(
                        deviceId = obj.getString("deviceId"),
                        deviceName = obj.optString("deviceName", "Desktop Core"),
                        host = obj.getString("host"),
                        port = obj.getInt("port"),
                        lastSeen = obj.optString("lastSeen", "").takeIf { it.isNotBlank() },
                        trustTier = obj.optString("trustTier", "PEER"),
                        certFingerprint = obj.optString("certFingerprint", "").takeIf { it.isNotBlank() },
                        recentEndpoints = eps.take(5),
                        connectionMode = obj.optString("connectionMode", "auto"),
                        snowId = obj.optString("snowId", "").takeIf { it.isNotBlank() },
                        deviceType = parsedType
                    )
                )
            }
        } catch (_: Exception) {}
        return list
    }

    fun updateDeviceTrustTier(deviceId: String, tier: String) {
        val current = _savedDevices.value.toMutableList()
        val idx = current.indexOfFirst { it.deviceId == deviceId }
        if (idx >= 0) {
            current[idx] = current[idx].copy(trustTier = tier)
            _savedDevices.value = current
            val prefsV2 = appContext.getSharedPreferences("snow_paired_devices_v2", Context.MODE_PRIVATE)
            prefsV2.edit().putString("devices_json", serializeSavedDevices(current)).apply()
        }
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
                    serviceRef?.client?.disconnect()
                    val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
                    val endpoint = prefs.getString(PREF_KEY_REMOTE_RELAY_ENDPOINT, "") ?: ""
                    if (endpoint.isNotBlank()) {
                        serviceRef?.startRelay(endpoint)
                    }
                }
                "auto" -> {
                    if (_connectionState.value == ConnectionState.DISCONNECTED) {
                        val prefs = appContext.getSharedPreferences(PREFS_SETTINGS, Context.MODE_PRIVATE)
                        val endpoint = prefs.getString(PREF_KEY_REMOTE_RELAY_ENDPOINT, "") ?: ""
                        if (endpoint.isNotBlank()) {
                            serviceRef?.startRelay(endpoint)
                        }
                    }
                }
            }
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
        if (!prefs.getBoolean(PREF_KEY_INSTANT_SYNC, false)) return
        if (!isConnectedAndAuthenticated()) return

        try {
            val cm = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
            val clip = cm.primaryClip ?: return
            if (clip.itemCount == 0) return

            val item = clip.getItemAt(0)
            val uri = item.uri
            val clipDescriptionMime = clip.description?.let { desc ->
                (0 until desc.mimeTypeCount).map { desc.getMimeType(it) }.firstOrNull { it.startsWith("image/") }
            }
            val resolvedMime = clipDescriptionMime ?: uri?.let { appContext.contentResolver.getType(it) }
            val isImage = (resolvedMime?.startsWith("image/") == true) || (uri != null && (clipDescriptionMime != null || appContext.contentResolver.getType(uri)?.startsWith("image/") == true))

            if (isImage && uri != null) {
                // Image on clipboard
                pushCurrentClipboard { success, _ ->
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

    fun uploadScreenshot(uri: Uri, displayName: String, size: Long, onComplete: ((Boolean, String?) -> Unit)? = null) {
        val client = serviceRef?.client
        val targetHost = client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
        val transferClient = _fileTransferClient ?: serviceRef?.transferClient ?: if (isConnectedAndAuthenticated()) {
            FileTransferClient(
                context = appContext,
                deviceId = identity.deviceId,
                certPinStorage = certPinStorage,
                tokenStorage = tokenStorage,
                useTls = true
            ).also { _fileTransferClient = it }
        } else null

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
                val safeName = stagedFile.name
                appendLog("INFO", TAG, "Uploading screenshot '$safeName' ($actualSize bytes) to PC...")
                val upRes = transferClient.uploadFile(
                    serverHost = targetHost,
                    transferPort = 8766,
                    file = stagedFile
                )
                // Remove staged file immediately once transferClient finishes uploading
                SafeStagingManager.cleanupStagedFile(stagedFile)
                toCleanup = null

                when (upRes) {
                    is FileTransferClient.TransferResult.Success -> {
                        recordIncomingClipboardText(upRes.sha256)
                        client.sendRequest(
                            "desktop_clipboard_set",
                            mapOf(
                                "type" to "image",
                                "transfer_id" to upRes.transferId,
                                "sha256" to upRes.sha256,
                                "file_name" to safeName
                            )
                        ) { resp ->
                            repoScope.launch(Dispatchers.Main) {
                                if (resp.isSuccess) {
                                    appendLog("INFO", TAG, "Screenshot synced to PC clipboard: $safeName")
                                    Toast.makeText(appContext, "Screenshot synced to PC clipboard ❄️", Toast.LENGTH_SHORT).show()
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
                        recordIncomingClipboardText(upRes.sha256)
                        client.sendRequest(
                            "desktop_clipboard_set",
                            mapOf(
                                "type" to "image",
                                "sha256" to upRes.sha256,
                                "file_name" to safeName
                            )
                        ) { resp ->
                            repoScope.launch(Dispatchers.Main) {
                                if (resp.isSuccess) {
                                    appendLog("INFO", TAG, "Screenshot synced to PC clipboard: $safeName")
                                    Toast.makeText(appContext, "Screenshot synced to PC clipboard ❄️", Toast.LENGTH_SHORT).show()
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

    fun pushLatestRecentScreenshotIfAvailable(onComplete: (Boolean, String?) -> Unit) {
        val client = serviceRef?.client
        val targetHost = client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
        val transferClient = _fileTransferClient ?: serviceRef?.transferClient ?: if (isConnectedAndAuthenticated()) {
            FileTransferClient(
                context = appContext,
                deviceId = identity.deviceId,
                certPinStorage = certPinStorage,
                tokenStorage = tokenStorage,
                useTls = true
            ).also { _fileTransferClient = it }
        } else null

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
                    uploadScreenshot(foundUri!!, foundName!!, foundSize, onComplete)
                } else {
                    repoScope.launch(Dispatchers.Main) { onComplete(false, "No recent screenshot found.") }
                }
            } catch (e: Exception) {
                repoScope.launch(Dispatchers.Main) { onComplete(false, "Screenshot error: ${e.message}") }
            }
        }
    }

    /**
     * Start live screen streaming session via foreground service.
     */
    fun startScreenShare(resultCode: Int, data: Intent) {
        SnowForegroundService.startScreenShare(appContext, resultCode, data)
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
        val transferClient = _fileTransferClient ?: serviceRef?.transferClient ?: if (isConnectedAndAuthenticated()) {
            FileTransferClient(
                context = appContext,
                deviceId = identity.deviceId,
                certPinStorage = certPinStorage,
                tokenStorage = tokenStorage,
                useTls = true
            ).also { _fileTransferClient = it }
        } else null

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
        return prefs.getString(PREF_KEY_REMOTE_RELAY_ENDPOINT, "") ?: ""
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

    fun pushCurrentClipboard(onComplete: (Boolean, String?) -> Unit) {
        val client = serviceRef?.client
        val targetHost = client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
        val transferClient = _fileTransferClient ?: serviceRef?.transferClient ?: if (_authState.value is AuthState.Authenticated && _connectionState.value == ConnectionState.CONNECTED) {
            FileTransferClient(
                context = appContext,
                deviceId = identity.deviceId,
                certPinStorage = certPinStorage,
                tokenStorage = tokenStorage,
                useTls = true
            ).also { _fileTransferClient = it }
        } else null

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
                    if (fileSize > 20 * 1024 * 1024) {
                        repoScope.launch(Dispatchers.Main) {
                            onComplete(false, "Image exceeds 20 MB limit.")
                        }
                        return@launch
                    }
                    val upRes = transferClient.uploadFile(
                        serverHost = targetHost,
                        transferPort = 8766,
                        file = stagedFile
                    )
                    when (upRes) {
                        is FileTransferClient.TransferResult.Success -> {
                            recordIncomingClipboardText(upRes.sha256)
                            client.sendRequest(
                                "desktop_clipboard_set",
                                mapOf(
                                    "type" to "image",
                                    "sha256" to upRes.sha256,
                                    "file_name" to stagedFile.name
                                )
                            ) { resp ->
                                repoScope.launch(Dispatchers.Main) {
                                    if (resp.isSuccess) {
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
                        else -> {
                            repoScope.launch(Dispatchers.Main) {
                                onComplete(false, "Upload did not succeed.")
                            }
                        }
                    }
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

    fun pullClipboard(onComplete: (Boolean, String?) -> Unit) {
        val client = serviceRef?.client
        val targetHost = client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
        val transferClient = _fileTransferClient ?: serviceRef?.transferClient ?: if (_authState.value is AuthState.Authenticated && _connectionState.value == ConnectionState.CONNECTED) {
            FileTransferClient(
                context = appContext,
                deviceId = identity.deviceId,
                certPinStorage = certPinStorage,
                tokenStorage = tokenStorage,
                useTls = true
            ).also { _fileTransferClient = it }
        } else null

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
                                        recordIncomingClipboardText(sha256)
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
        client.sendRequest("clipboard_buffer_list", mapOf("limit" to 10)) { resp ->
            if (resp.isSuccess) {
                val data = resp.payload?.get("data") as? Map<*, *> ?: resp.payload
                val rawItems = data?.get("items") as? List<*> ?: emptyList<Any>()
                val parsed = rawItems.mapNotNull { itemMap ->
                    (itemMap as? Map<*, *>)?.let { map ->
                        ClipboardItemDto(
                            itemId = map["item_id"] as? String ?: "",
                            type = map["type"] as? String ?: "text",
                            sourceDevice = map["source_device"] as? String ?: "pc",
                            previewText = map["preview_text"] as? String ?: (map["text_content"] as? String ?: ""),
                            sizeBytes = (map["size_bytes"] as? Number)?.toLong() ?: 0L,
                            timestamp = (map["timestamp"] as? Number)?.toDouble() ?: 0.0,
                            isPinned = (map["is_pinned"] as? Boolean) ?: false
                        )
                    }
                }
                _clipboardBufferItems.value = parsed
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
        if (item.type == "image") {
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
                                        org.snow.capabilities.ClipboardHandler.postShareFallbackNotification(appContext, contentUri, resolvedMime)

                                        recordIncomingClipboardText(sha256)
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
                            onComplete(true, "Applied image to clipboard")
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
                    if (bytes.size > 65536) {
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
        val transferClient = _fileTransferClient ?: serviceRef?.transferClient ?: if (_authState.value is AuthState.Authenticated && _connectionState.value == ConnectionState.CONNECTED) {
            FileTransferClient(
                context = appContext,
                deviceId = identity.deviceId,
                certPinStorage = certPinStorage,
                tokenStorage = tokenStorage,
                useTls = true
            ).also { _fileTransferClient = it }
        } else null

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
                    val transferPort = (data?.get("transfer_port") as? Number)?.toInt() ?: 8766
                    val targetHost = client.currentTargetHost

                    val stagedFile = File(safFolderManager.getStagingDir(), "${transferId}_$fileName")

                    _activeTransfer.value = ActiveTransferInfo(
                        transferId = transferId,
                        fileName = fileName,
                        direction = "DOWNLOAD",
                        bytesTransferred = 0L,
                        totalBytes = item.size,
                        status = "IN_PROGRESS"
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
                                        } else {
                                            val commitErr = commitResult.exceptionOrNull()?.message ?: "Failed writing to SAF destination"
                                            _activeTransfer.value = _activeTransfer.value?.copy(status = "FAILED")
                                            appendLog("ERROR", TAG, "SAF commit failed: $commitErr")
                                            onComplete(false, commitErr)
                                        }
                                    }
                                    is FileTransferClient.TransferResult.Error -> {
                                        _activeTransfer.value = _activeTransfer.value?.copy(status = "FAILED")
                                        appendLog("ERROR", TAG, "Download failed: ${dlRes.message}")
                                        onComplete(false, dlRes.message)
                                    }
                                    is FileTransferClient.TransferResult.Duplicate -> {
                                        _activeTransfer.value = _activeTransfer.value?.copy(status = "DUPLICATE")
                                        appendLog("WARN", TAG, "Duplicate file: ${dlRes.fileName}")
                                        onComplete(true, dlRes.fileName)
                                    }
                                }
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

    fun startFileUpload(
        uri: android.net.Uri,
        fileName: String,
        fileSize: Long,
        onComplete: (Boolean, String?) -> Unit
    ) {
        val client = serviceRef?.client
        val targetHost = client?.currentTargetHost?.takeIf { it.isNotBlank() } ?: connectedHost
        val transferClient = _fileTransferClient ?: serviceRef?.transferClient ?: if (_authState.value is AuthState.Authenticated && _connectionState.value == ConnectionState.CONNECTED) {
            FileTransferClient(
                context = appContext,
                deviceId = identity.deviceId,
                certPinStorage = certPinStorage,
                tokenStorage = tokenStorage,
                useTls = true
            ).also { _fileTransferClient = it }
        } else null

        if (transferClient == null || targetHost.isBlank() || _connectionState.value != ConnectionState.CONNECTED) {
            onComplete(false, "Desktop or file transfer client not ready.")
            return
        }

        val transferPort = 8766 // Standard SNOW file transfer port

        appendLog("INFO", TAG, "Starting file upload to PC: $fileName ($fileSize bytes)...")
        _activeTransfer.value = ActiveTransferInfo(
            transferId = "upload_${System.currentTimeMillis()}",
            fileName = fileName,
            direction = "UPLOAD",
            bytesTransferred = 0L,
            totalBytes = fileSize,
            status = "IN_PROGRESS"
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
                        }
                        is FileTransferClient.TransferResult.Duplicate -> {
                            _activeTransfer.value = _activeTransfer.value?.copy(status = "DUPLICATE")
                            appendLog("WARN", TAG, "File already exists on PC: $fileName")
                            onComplete(true, fileName)
                        }
                        is FileTransferClient.TransferResult.Error -> {
                            _activeTransfer.value = _activeTransfer.value?.copy(status = "FAILED")
                            appendLog("ERROR", TAG, "Upload failed: ${upRes.message}")
                            onComplete(false, upRes.message)
                        }
                    }
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
        activeDownloadJob?.cancel()
        _activeTransfer.value = active.copy(status = "CANCELLED")
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

    fun fetchPendingApprovals(callback: (Result<List<PendingApprovalItem>>) -> Unit) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            callback(Result.failure(IllegalStateException("Not connected to SNOW Desktop Core.")))
            return
        }

        client.sendRequest("approval_list", emptyMap()) { resp ->
            repoScope.launch {
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
                    _pendingApprovalsCount.value = items.size
                    callback(Result.success(items))
                } else {
                    val err = resp.error?.message ?: (resp.payload?.get("error") as? String) ?: "Failed fetching approvals"
                    callback(Result.failure(RuntimeException(err)))
                }
            }
        }
    }

    fun resolveApproval(requestId: String, decision: String, callback: (Result<String>) -> Unit) {
        val client = serviceRef?.client
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            callback(Result.failure(IllegalStateException("Not connected to SNOW Desktop Core.")))
            return
        }

        val cleanDecision = decision.trim().uppercase()
        val data = mapOf("request_id" to requestId, "decision" to cleanDecision)
        client.sendRequest("approval_resolve", data) { resp ->
            repoScope.launch {
                if (resp.isSuccess) {
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

    fun generatePeerHostQrJson(): String? {
        val service = serviceRef ?: return null
        return service.peerHostManager.generatePairingQrJson(identity.deviceId)
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
        if (client == null || _connectionState.value != ConnectionState.CONNECTED) {
            onComplete(false, null, "Desktop not connected.")
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
        val transferClient = _fileTransferClient ?: serviceRef?.transferClient ?: FileTransferClient(
            context = appContext,
            deviceId = "android-client",
            certPinStorage = certPinStorage,
            tokenStorage = tokenStorage,
            useTls = true
        )
        if (host.isNullOrBlank()) {
            appendLog("WARN", TAG, "Cannot check app update: no active desktop endpoint resolved")
            onResult(null)
            return
        }

        repoScope.launch {
            try {
                val res = transferClient.getAppUpdateInfo(host, 8766)
                if (res.isSuccess) {
                    val info = res.getOrNull()
                    appendLog("INFO", TAG, "App update check result: available=${info?.available}, code=${info?.versionCode}")
                    onResult(info)
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
        val transferClient = _fileTransferClient ?: serviceRef?.transferClient ?: FileTransferClient(
            context = appContext,
            deviceId = "android-client",
            certPinStorage = certPinStorage,
            tokenStorage = tokenStorage,
            useTls = true
        )
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
    val deviceType: String = "pc"
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
    val status: String
)

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
