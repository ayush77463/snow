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

        /**
         * Quarantine flag for Phase 19A.
         * Android operates in client-only mode until a production-grade embedded WSS
         * server is engineered and verified in Phase 20.
         */
        const val IS_QUARANTINED = true
    }

    private val isRunning = AtomicBoolean(false)
    private var server: AndroidPeerHostServer? = null
    var activePort: Int = DEFAULT_HOST_PORT
        private set

    /**
     * Enable foreground peer host mode, starting the listening server.
     * Quarantined in Phase 19A: Always fails closed and returns false.
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
        if (IS_QUARANTINED) {
            SafeLog.w(
                TAG,
                "Android Foreground Peer Host Mode is quarantined in Phase 19A (client-only until Phase 20 WSS host implementation). Refusing to start TCP server."
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
     * Always returns false while quarantined.
     */
    fun isHostModeActive(): Boolean {
        if (IS_QUARANTINED) return false
        return isRunning.get() && server != null && server!!.isListening()
    }

    /**
     * Return the live reachability profile governed by host mode state.
     * While quarantined, Android always advertises ACTIVE_SESSION_PEER.
     */
    fun getReachabilityProfile(): ReachabilityProfile {
        if (IS_QUARANTINED) return ReachabilityProfile.ACTIVE_SESSION_PEER
        return if (isHostModeActive()) {
            ReachabilityProfile.FOREGROUND_HOST
        } else {
            ReachabilityProfile.ACTIVE_SESSION_PEER
        }
    }
}
