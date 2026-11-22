package org.snow.network

import kotlinx.coroutines.CoroutineScope
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.security.SafeLog
import org.snow.security.TokenStorage
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Manages the lifecycle, reachability state, and socket bounds for Android Foreground Peer Host Mode.
 *
 * Guarantees:
 * - Thread-safe state transitions.
 * - Does not claim availability or host mode when stopped.
 * - Advertises ReachabilityProfile.FOREGROUND_HOST only when actively listening.
 * - Shuts down server sockets cleanly upon app/service lifecycle transitions.
 */
class AndroidPeerHostManager {

    companion object {
        private const val TAG = "AndroidPeerHostManager"
        const val DEFAULT_HOST_PORT = 8767
        const val PIN_VALIDITY_MS = 300_000L // 5 minutes

        /**
         * Deprecated quarantine flag.
         * In Phase 27, Direct Phone-to-Phone Host Mode is governed by explicit user setting (default OFF).
         */
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
    private var currentEphemeralPin: EphemeralPin? = null
    private val secureRandom = java.security.SecureRandom()

    var activePort: Int = DEFAULT_HOST_PORT
        private set

    val activeConnectionCount: Int
        get() = server?.getActiveConnectionCount() ?: 0

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
        SafeLog.i(TAG, "Generated ephemeral 6-digit pairing PIN (valid for 5 minutes)")
        return pinVal
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
            return false
        }
        if (pinObj.pin == inputPin.trim()) {
            pinObj.isConsumed = true
            SafeLog.i(TAG, "Pairing PIN successfully verified and consumed.")
            return true
        }
        SafeLog.w(TAG, "Pairing PIN mismatch.")
        return false
    }

    /**
     * Enable foreground peer host mode, starting the listening server.
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
        parentScope: CoroutineScope? = null
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

        val newServer = AndroidPeerHostServer(
            requestedPort = port,
            tokenStorage = tokenStorage,
            dispatcher = dispatcher,
            localDeviceId = localDeviceId,
            manifestProvider = manifestProvider,
            peerTokenValidator = peerTokenValidator,
            parentScope = parentScope
        )

        val success = newServer.start()
        if (success) {
            server = newServer
            activePort = newServer.boundPort
            isRunning.set(true)
            SafeLog.i(TAG, "Foreground host mode enabled on port $activePort")
        } else {
            newServer.stop()
            server = null
            isRunning.set(false)
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
            return
        }
        SafeLog.i(TAG, "Disabling foreground peer host mode...")
        try {
            server?.stop()
        } catch (e: Exception) {
            SafeLog.w(TAG, "Error stopping peer host server: ${e.message}")
        }
        server = null
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
