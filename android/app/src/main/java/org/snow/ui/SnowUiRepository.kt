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
        const val PREF_KEY_REMOTE_RELAY_ENABLED = "remote_relay_enabled"
        const val PREF_KEY_REMOTE_RELAY_ENDPOINT = "remote_relay_endpoint"

        @Volatile
        private var instance: SnowUiRepository? = null

        fun getInstance(context: Context): SnowUiRepository {
            return instance ?: synchronized(this) {
                instance ?: SnowUiRepository(context.applicationContext).also { instance = it }
            }
        }
    }

    private val repoScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var serviceRef: SnowForegroundService? = null
    val screenshotObserver: ScreenshotObserver by lazy { ScreenshotObserver(appContext) }

    // Persistent storage helpers
    val identity: DeviceIdentity by lazy { DeviceIdentity.getOrCreate(appContext) }
    val tokenStorage: SharedPreferencesTokenStorage by lazy { SharedPreferencesTokenStorage(appContext) }
    val certPinStorage: EncryptedCertPinStorage by lazy { EncryptedCertPinStorage(appContext) }
    val safFolderManager: SafFolderManager by lazy { SafFolderManager(appContext) }
    val pairingFlow: PairingFlow by lazy { PairingFlow(identity, tokenStorage) }

    // --- StateFlows ---

    private val _connectionState = MutableStateFlow(ConnectionState.DISCONNECTED)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _connectedEndpoint = MutableStateFlow<String?>(null)
    val connectedEndpoint: StateFlow<String?> = _connectedEndpoint.asStateFlow()

    private val _authState = MutableStateFlow<AuthState>(AuthState.Disconnected)
    val authState: StateFlow<AuthState> = _authState.asStateFlow()

    val pairingState: StateFlow<PairingState> get() = pairingFlow.state

    private val _discoveredPeers = MutableStateFlow<List<DiscoveredPeer>>(emptyList())
    val discoveredPeers: StateFlow<List<DiscoveredPeer>> = _discoveredPeers.asStateFlow()

    private val _savedDevices = MutableStateFlow<List<SavedDevice>>(emptyList())
    val savedDevices: StateFlow<List<SavedDevice>> = _savedDevices.asStateFlow()

    private val _activeTransfer = MutableStateFlow<ActiveTransferInfo?>(null)
    val activeTransfer: StateFlow<ActiveTransferInfo?> = _activeTransfer.asStateFlow()

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
        _screenShareState.value = LiveScreenStreamHandler.StreamState.IDLE
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
                    if (prefs.getBoolean(PREF_KEY_INSTANT_SYNC, true)) {
                        toggleInstantClipboardSync(true)
                    }
                    if (prefs.getBoolean(PREF_KEY_AUTO_SYNC_SCREENSHOTS, false)) {
                        screenshotObserver.register()
                    }
                    // Fetch latest shared clipboard buffer items
                    fetchClipboardBuffer()
                    // Update identity-first saved device history and endpoint ring buffer
                    recordSuccessfulConnection(host = host, port = port, sessionId = auth.sessionId, tier = auth.trustTier)
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
                client.setAuthenticated(state.sessionId)
                _authState.value = AuthState.Authenticated(state.sessionId)
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

    private fun loadSavedDevices() {
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

    fun recordSuccessfulConnection(host: String, port: Int, sessionId: String, tier: String = "PEER") {
        val cleanHost = host.trim()
        val token = tokenStorage.getToken()
        val deviceId = token?.take(8) ?: sessionId.take(8)
        val pinnedFp = certPinStorage.getPinnedFingerprint()
        val nowStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())

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
            current[existingIdx] = existing.copy(
                host = if (cleanHost != "127.0.0.1" || existing.host.isBlank()) cleanHost else existing.host,
                port = port,
                lastSeen = nowStr,
                trustTier = effectiveTier,
                certFingerprint = pinnedFp ?: existing.certFingerprint,
                recentEndpoints = updatedEndpoints.take(5)
            )
        } else {
            current.add(
                0,
                SavedDevice(
                    deviceId = deviceId,
                    deviceName = "Desktop Core ($cleanHost)",
                    host = cleanHost,
                    port = port,
                    lastSeen = nowStr,
                    trustTier = tier,
                    certFingerprint = pinnedFp,
                    recentEndpoints = updatedEndpoints.take(5)
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
                    recordSuccessfulConnection(targetIp, port, auth.sessionId, auth.trustTier)
                    onComplete(true, null)
                    return@launch
                } else if (state == ConnectionState.CONNECTED && auth is AuthState.ConnectedUnauthenticated) {
                    appendLog("INFO", TAG, "Connection established; auto-submitting pairing PIN from QR...")
                    pairDevice(pin) { pState ->
                        when (pState) {
                            is PairingState.Paired -> {
                                appendLog("INFO", TAG, "QR pairing successful [tier=${pState.trustTier}]")
                                recordSuccessfulConnection(targetIp, port, pState.sessionId, pState.trustTier)
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
                list.add(
                    SavedDevice(
                        deviceId = obj.getString("deviceId"),
                        deviceName = obj.optString("deviceName", "Desktop Core"),
                        host = obj.getString("host"),
                        port = obj.getInt("port"),
                        lastSeen = obj.optString("lastSeen", "").takeIf { it.isNotBlank() },
                        trustTier = obj.optString("trustTier", "PEER"),
                        certFingerprint = obj.optString("certFingerprint", "").takeIf { it.isNotBlank() },
                        recentEndpoints = eps.take(5)
                    )
                )
            }
        } catch (_: Exception) {}
        return list
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
                _phoneTelemetry.value = PhoneTelemetry(
                    batteryPercent = pct,
                    isCharging = isCharging,
                    temperatureCelsius = tempCelsius,
                    isAvailable = true,
                    lastUpdated = System.currentTimeMillis()
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
                    val os = data?.get("os") as? String
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

    fun ringPhone() {
        repoScope.launch {
            try {
                val ringer = RingerHandler(appContext)
                val res = ringer.ringPhone(5)
                appendLog("INFO", TAG, "Triggered phone ringer: ${res["status"]}")
            } catch (e: Exception) {
                appendLog("ERROR", TAG, "Phone ringer error: ${e.message}")
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
            try {
                val cacheDir = File(appContext.cacheDir, "screenshots").apply { mkdirs() }
                val safeName = if (displayName.isNotBlank()) displayName else "screenshot_${System.currentTimeMillis()}.png"
                val stagedFile = File(cacheDir, safeName)
                appContext.contentResolver.openInputStream(uri)?.use { input ->
                    stagedFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
                val actualSize = stagedFile.length()
                if (actualSize <= 0L) {
                    stagedFile.delete()
                    repoScope.launch(Dispatchers.Main) {
                        onComplete?.invoke(false, "Screenshot data unreadable or empty.")
                    }
                    return@launch
                }
                appendLog("INFO", TAG, "Uploading screenshot '$safeName' ($actualSize bytes) to PC...")
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
        _cameraDelivery.value = CameraDeliveryInfo(status = CameraDeliveryStatus.IDLE)
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
                try {
                    val cacheDir = File(appContext.cacheDir, "clipboard").apply { mkdirs() }
                    val fileName = "clip_${System.currentTimeMillis()}.png"
                    val stagedFile = File(cacheDir, fileName)
                    appContext.contentResolver.openInputStream(uri)?.use { input ->
                        stagedFile.outputStream().use { output ->
                            input.copyTo(output)
                        }
                    }
                    val fileSize = stagedFile.length()
                    if (fileSize <= 0L) {
                        stagedFile.delete()
                        repoScope.launch(Dispatchers.Main) {
                            onComplete(false, "Clipboard image is empty or inaccessible.")
                        }
                        return@launch
                    }
                    if (fileSize > 20 * 1024 * 1024) {
                        stagedFile.delete()
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
                                    "transfer_id" to upRes.transferId,
                                    "sha256" to upRes.sha256,
                                    "file_name" to fileName
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
                        is FileTransferClient.TransferResult.Duplicate -> {
                            recordIncomingClipboardText(upRes.sha256)
                            client.sendRequest(
                                "desktop_clipboard_set",
                                mapOf(
                                    "type" to "image",
                                    "sha256" to upRes.sha256,
                                    "file_name" to fileName
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
                    }
                } catch (e: Exception) {
                    repoScope.launch(Dispatchers.Main) {
                        onComplete(false, "Failed pushing image: ${e.message}")
                    }
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
        if (item.type != "text") {
            onComplete(false, "Image items must be transferred via HTTP download")
            return
        }
        val client = serviceRef?.client ?: run {
            onComplete(false, "Client disconnected or offline")
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

    // --- Terminal Console with Stage 19A Confirmation Tickets ---

    fun executeTerminalCommand(
        command: String,
        ticket: String? = null,
        onResult: (TerminalResult) -> Unit
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
    val recentEndpoints: List<DeviceEndpoint> = emptyList()
)

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
    val lastUpdated: Long
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
