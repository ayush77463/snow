package org.snow.network

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.security.AndroidSelfSignedCertGenerator
import org.snow.security.SafeLog
import org.snow.security.TokenStorage
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Live reactive state of the Android Direct Peer-Host service.
 */
data class PeerHostState(
    val isActive: Boolean = false,
    val ipAddress: String = "--",
    val port: Int = AndroidPeerHostManager.DEFAULT_HOST_PORT,
    val certFingerprint: String = "--",
    val peerCount: Int = 0,
    val pairingPin: String? = null,
    val pinExpiresInSeconds: Long = 0L,
    val errorMessage: String? = null
)

/**
 * Manages the lifecycle, reachability state, and socket bounds for Android Foreground Peer Host Mode.
 *
 * Guarantees:
 * - Thread-safe state transitions.
 * - Does not claim availability or host mode when stopped.
 * - Advertises ReachabilityProfile.FOREGROUND_HOST only when actively listening.
 * - Shuts down server sockets cleanly upon app/service lifecycle transitions.
 * - Exposes reactive [hostState] Flow for UI observation.
 * - Enforces mandatory TLS 1.2+ WSS via [AndroidSelfSignedCertGenerator].
 */
class AndroidPeerHostManager {

    companion object {
        private const val TAG = "AndroidPeerHostManager"
        const val DEFAULT_HOST_PORT = 8767
        const val PIN_VALIDITY_MS = 300_000L // 5 minutes
        const val IS_QUARANTINED = false
    }

    data class EphemeralPin(
        val pin: String,
        val expiresAtMillis: Long,
        var isConsumed: Boolean = false
    )

    private val hostModeSettingEnabled = AtomicBoolean(false)
    private val isRunning = AtomicBoolean(false)
    private var server: AndroidPeerHostServer? = null
    private var mediaServer: AndroidPeerMediaServer? = null
    private var currentEphemeralPin: EphemeralPin? = null
    private val secureRandom = java.security.SecureRandom()

    private val _hostState = MutableStateFlow(PeerHostState())
    val hostState: StateFlow<PeerHostState> = _hostState.asStateFlow()

    var activePort: Int = DEFAULT_HOST_PORT
        private set

    val activeConnectionCount: Int
        get() = server?.getActiveConnectionCount() ?: 0

    /**
     * Resolve the active non-loopback IPv4 address for Wi-Fi or Hotspot interfaces.
     */
    fun getLocalIpv4Address(): String? {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return null
            for (iface in interfaces) {
                if (iface.isLoopback || !iface.isUp) continue
                for (addr in iface.inetAddresses) {
                    if (!addr.isLoopbackAddress && addr is Inet4Address) {
                        val host = addr.hostAddress
                        if (!host.isNullOrBlank() && host != "127.0.0.1") {
                            return host
                        }
                    }
                }
            }
        } catch (_: Exception) {}
        return null
    }

    /**
     * User-controlled setting to opt into Direct Phone-to-Phone Host Mode.
     * Defaults to false (OFF). Must be explicitly enabled by user action.
     */
    fun setHostModeSettingEnabled(enabled: Boolean) {
        hostModeSettingEnabled.set(enabled)
        if (!enabled) {
            disableHostMode()
        }
        SafeLog.i(TAG, "Direct Phone-to-Phone Host Mode setting set to: $enabled")
    }

    fun isHostModeSettingEnabled(): Boolean = hostModeSettingEnabled.get()

    /**
     * Generate an ephemeral single-use 6-digit pairing PIN with a 5-minute validity window.
     * Uses cryptographically secure random number generation.
     */
    @Synchronized
    fun generatePairingPin(): String {
        val pinVal = String.format("%06d", secureRandom.nextInt(1_000_000))
        currentEphemeralPin = EphemeralPin(
            pin = pinVal,
            expiresAtMillis = System.currentTimeMillis() + PIN_VALIDITY_MS,
            isConsumed = false
        )
        _hostState.value = _hostState.value.copy(
            pairingPin = pinVal,
            pinExpiresInSeconds = 300L
        )
        SafeLog.i(TAG, "Generated ephemeral 6-digit pairing PIN (valid for 5 minutes)")
        return pinVal
    }

    @Synchronized
    internal fun setHostStateForTesting(state: PeerHostState) {
        _hostState.value = state
        activePort = state.port
    }

    /**
     * Generate standard SNOW Device Protocol v1 QR pairing payload for peer devices.
     */
    @Synchronized
    fun generatePairingQrJson(localDeviceId: String, snowId: String? = null): String? {
        val state = _hostState.value
        val cleanFp = state.certFingerprint.replace(":", "").replace(" ", "").trim()
        if (cleanFp.isBlank() || cleanFp == "--") return null

        val hostIp = if (state.ipAddress != "--" && state.ipAddress.isNotBlank()) state.ipAddress else getLocalIpv4Address()
        if (hostIp.isNullOrBlank()) return null

        val activePin = getCurrentEphemeralPinInfo()?.first ?: generatePairingPin()
        val json = org.json.JSONObject().apply {
            put("v", 1)
            put("id", localDeviceId)
            if (!snowId.isNullOrBlank()) {
                put("snow_id", snowId)
            }
            put("ips", org.json.JSONArray().put(hostIp))
            put("port", activePort)
            put("fp", cleanFp)
            put("pin", activePin)
        }
        return json.toString()
    }

    @Synchronized
    fun getCurrentEphemeralPinInfo(): Pair<String, Long>? {
        val p = currentEphemeralPin ?: return null
        if (p.isConsumed || System.currentTimeMillis() > p.expiresAtMillis) {
            return null
        }
        val remainingMs = p.expiresAtMillis - System.currentTimeMillis()
        return Pair(p.pin, remainingMs)
    }

    /**
     * Verify and consume an ephemeral pairing PIN with single-use semantics.
     */
    @Synchronized
    fun verifyAndConsumePairingPin(inputPin: String): Boolean {
        val pinObj = currentEphemeralPin ?: return false
        if (pinObj.isConsumed) {
            SafeLog.w(TAG, "Pairing PIN has already been consumed.")
            return false
        }
        if (System.currentTimeMillis() > pinObj.expiresAtMillis) {
            SafeLog.w(TAG, "Pairing PIN has expired.")
            currentEphemeralPin = null
            _hostState.value = _hostState.value.copy(pairingPin = null, pinExpiresInSeconds = 0L)
            return false
        }
        if (pinObj.pin == inputPin.trim()) {
            pinObj.isConsumed = true
            _hostState.value = _hostState.value.copy(pairingPin = null, pinExpiresInSeconds = 0L)
            SafeLog.i(TAG, "Pairing PIN successfully verified and consumed.")
            return true
        }
        SafeLog.w(TAG, "Pairing PIN mismatch.")
        return false
    }

    /**
     * Enable foreground peer host mode, starting the listening server with mandatory TLS.
     * Requires hostModeSettingEnabled == true.
     */
    @Synchronized
    fun enableHostMode(
        port: Int = DEFAULT_HOST_PORT,
        tokenStorage: TokenStorage,
        dispatcher: AndroidCapabilityDispatcher,
        localDeviceId: String,
        manifestProvider: () -> Map<String, Any?> = { emptyMap() },
        peerTokenValidator: ((String) -> Boolean)? = null,
        parentScope: CoroutineScope? = null,
        mediaPort: Int = 0
    ): Boolean {
        if (!hostModeSettingEnabled.get()) {
            SafeLog.w(
                TAG,
                "Direct Phone-to-Phone Host Mode is disabled by user setting. Refusing to start TCP server."
            )
            disableHostMode()
            return false
        }

        if (isRunning.get() && server != null && server!!.isListening()) {
            SafeLog.i(TAG, "Foreground host mode is already active on port $activePort")
            return true
        }

        disableHostMode()

        val certResult = try {
            AndroidSelfSignedCertGenerator.generate()
        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed generating TLS certificate for peer host: ${e.message}", e)
            _hostState.value = _hostState.value.copy(isActive = false, errorMessage = "TLS generation failed: ${e.message}")
            return false
        }

        val newServer = AndroidPeerHostServer(
            requestedPort = port,
            tokenStorage = tokenStorage,
            dispatcher = dispatcher,
            localDeviceId = localDeviceId,
            manifestProvider = manifestProvider,
            peerTokenValidator = peerTokenValidator,
            pinVerifier = { verifyAndConsumePairingPin(it) },
            parentScope = parentScope,
            sslContext = certResult.sslContext
        )

        val success = newServer.start()
        if (success) {
            server = newServer
            activePort = newServer.boundPort
            isRunning.set(true)
            if (mediaPort > 0) {
                val ms = AndroidPeerMediaServer(
                    requestedPort = mediaPort,
                    sslContext = certResult.sslContext,
                    tokenStorage = tokenStorage,
                    peerTokenValidator = peerTokenValidator,
                    activeProfileProvider = { dispatcher.activePermissionProfile }
                )
                if (ms.start()) {
                    mediaServer = ms
                }
            }
            val ip = getLocalIpv4Address() ?: "127.0.0.1"
            _hostState.value = PeerHostState(
                isActive = true,
                ipAddress = ip,
                port = activePort,
                certFingerprint = certResult.fingerprint,
                peerCount = 0,
                pairingPin = currentEphemeralPin?.pin,
                pinExpiresInSeconds = if (currentEphemeralPin != null) 300L else 0L,
                errorMessage = null
            )
            SafeLog.i(TAG, "Foreground host mode enabled on $ip:$activePort (TLS WSS)")
        } else {
            newServer.stop()
            server = null
            isRunning.set(false)
            _hostState.value = _hostState.value.copy(isActive = false, errorMessage = "Failed to bind port $port")
            SafeLog.e(TAG, "Failed to enable foreground host mode on port $port")
        }
        return success
    }

    /**
     * Disable foreground peer host mode and close listening sockets.
     */
    @Synchronized
    fun disableHostMode() {
        currentEphemeralPin = null
        if (!isRunning.getAndSet(false) && server == null) {
            _hostState.value = PeerHostState(isActive = false, ipAddress = "--", port = activePort)
            return
        }
        SafeLog.i(TAG, "Disabling foreground peer host mode...")
        try {
            mediaServer?.stop()
        } catch (_: Exception) {}
        mediaServer = null
        try {
            server?.stop()
        } catch (e: Exception) {
            SafeLog.w(TAG, "Error stopping peer host server: ${e.message}")
        }
        server = null
        _hostState.value = PeerHostState(
            isActive = false,
            ipAddress = "--",
            port = activePort,
            certFingerprint = "--",
            peerCount = 0,
            pairingPin = null,
            pinExpiresInSeconds = 0L,
            errorMessage = null
        )
        SafeLog.i(TAG, "Foreground peer host mode disabled.")
    }

    /**
     * Return True if foreground peer host mode is actively listening.
     */
    fun isHostModeActive(): Boolean {
        return isRunning.get() && server != null && server!!.isListening()
    }

    /**
     * Return the live reachability profile governed by host mode state.
     */
    fun getReachabilityProfile(): ReachabilityProfile {
        return if (isHostModeActive()) {
            ReachabilityProfile.FOREGROUND_HOST
        } else {
            ReachabilityProfile.ACTIVE_SESSION_PEER
        }
    }
}
