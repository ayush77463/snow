package org.snow.security

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.snow.network.ConnectionState
import org.snow.network.DeviceNode
import org.snow.network.SnowWebSocketClient
import org.snow.protocol.ErrorCode
import org.snow.protocol.MessageType
import org.snow.protocol.SnowMessage
import java.util.concurrent.atomic.AtomicBoolean

/**
 * User-visible pairing states for the Android SNOW pairing workflow.
 */
sealed class PairingState {
    object Idle : PairingState()
    object WaitingForPin : PairingState()
    object InProgress : PairingState()

    data class Paired(
        val desktopId: String,
        val desktopName: String,
        val sessionId: String,
        val authToken: String? = null,
        val trustTier: String = "peer",
        val deviceType: String? = null,
        val permissionProfile: String? = null
    ) : PairingState()

    data class WrongPin(
        val message: String,
        val remainingAttempts: Int
    ) : PairingState()

    data class Expired(
        val message: String
    ) : PairingState()

    data class Locked(
        val message: String
    ) : PairingState()

    data class ConnectionLost(
        val message: String
    ) : PairingState()

    data class Error(
        val message: String
    ) : PairingState()
}

/**
 * Controller managing the 6-digit PIN entry and verification handshake for Android.
 */
class PairingFlow(
    private val identity: DeviceIdentity,
    val tokenStorage: TokenStorage? = null
) {
    private val _state = MutableStateFlow<PairingState>(PairingState.WaitingForPin)
    val state: StateFlow<PairingState> = _state.asStateFlow()

    private val isSubmitting = AtomicBoolean(false)
    private var lastSubmitTimeMs: Long = 0L

    /**
     * Validate whether a string is a valid 6-digit decimal PIN.
     */
    fun validatePin(pin: String?): Boolean {
        if (pin == null) return false
        val trimmed = pin.trim()
        return trimmed.length == 6 && trimmed.all { it.isDigit() }
    }

    /**
     * Submit a 6-digit PIN to the connected desktop core for verification.
     *
     * Prevents duplicate in-flight submissions and verifies connection readiness.
     *
     * @return true if the verification request was successfully dispatched.
     */
    fun submitPin(
        pin: String,
        client: SnowWebSocketClient,
        onStateChanged: ((PairingState) -> Unit)? = null
    ): Boolean {
        // Enforce 6-digit format validation
        if (!validatePin(pin)) {
            val errorState = PairingState.WrongPin(
                message = "PIN must be exactly 6 decimal digits (e.g. 004821).",
                remainingAttempts = 3
            )
            _state.value = errorState
            onStateChanged?.invoke(errorState)
            return false
        }

        // Prevent submission if pairing is already locked
        if (_state.value is PairingState.Locked) {
            return false
        }

        // Verify WebSocket connection state
        if (client.connectionState.value != ConnectionState.CONNECTED) {
            val lostState = PairingState.ConnectionLost("Cannot submit PIN: Client is not connected to desktop.")
            _state.value = lostState
            onStateChanged?.invoke(lostState)
            return false
        }

        // Prevent duplicate concurrent submissions, with 5s timeout reset for stalled requests
        val now = System.currentTimeMillis()
        if (isSubmitting.get()) {
            if (now - lastSubmitTimeMs > 5000L) {
                isSubmitting.set(false)
            } else {
                return false
            }
        }
        isSubmitting.set(true)
        lastSubmitTimeMs = now

        _state.value = PairingState.InProgress
        onStateChanged?.invoke(PairingState.InProgress)

        val cleanedPin = pin.trim()
        val manifestMap = DeviceNode.buildAndroidManifest(null).toMap()
        val host = client.currentTargetHost
        val isLoopback = host == "127.0.0.1" || host == "localhost" || host == "::1"
        val requestData = mapOf(
            "device_id" to identity.deviceId,
            "device_name" to identity.deviceName,
            "pin" to cleanedPin,
            "manifest" to manifestMap,
            "connection_mode" to if (isLoopback) "usb_adb" else "wifi_lan",
            "transport_mode" to if (isLoopback) "usb_adb" else "wifi_lan"
        )

        client.sendRequest(
            action = "pair_request",
            data = requestData
        ) { message ->
            isSubmitting.set(false)
            val newState = handlePairingResponse(message)
            _state.value = newState
            onStateChanged?.invoke(newState)
        }

        return true
    }

    /**
     * Submit a single-use QR handshake token directly to the host (zero 6-digit PIN entry).
     */
    fun submitHandshakeToken(
        handshakeToken: String,
        networkId: String? = null,
        client: SnowWebSocketClient,
        onStateChanged: ((PairingState) -> Unit)? = null
    ): Boolean {
        val cleanToken = handshakeToken.trim()
        if (cleanToken.length < 16) {
            val errorState = PairingState.Error("Invalid QR handshake token.")
            _state.value = errorState
            onStateChanged?.invoke(errorState)
            return false
        }
        if (_state.value is PairingState.Locked) {
            return false
        }
        if (client.connectionState.value != ConnectionState.CONNECTED) {
            val lostState = PairingState.ConnectionLost("Cannot complete QR handshake: Not connected.")
            _state.value = lostState
            onStateChanged?.invoke(lostState)
            return false
        }
        if (!isSubmitting.compareAndSet(false, true)) {
            return false
        }
        lastSubmitTimeMs = System.currentTimeMillis()
        _state.value = PairingState.InProgress
        onStateChanged?.invoke(PairingState.InProgress)

        val manifestMap = DeviceNode.buildAndroidManifest(null).toMap()
        val host = client.currentTargetHost
        val isLoopback = host == "127.0.0.1" || host == "localhost" || host == "::1"
        val requestData = mutableMapOf<String, Any>(
            "device_id" to identity.deviceId,
            "device_name" to identity.deviceName,
            "handshake_token" to cleanToken,
            "manifest" to manifestMap,
            "connection_mode" to if (isLoopback) "usb_adb" else "wifi_lan",
            "transport_mode" to if (isLoopback) "usb_adb" else "wifi_lan"
        )
        if (!networkId.isNullOrBlank()) {
            requestData["network_id"] = networkId.trim().uppercase()
        }

        client.sendRequest(
            action = "pair_request",
            data = requestData
        ) { message ->
            isSubmitting.set(false)
            val newState = handlePairingResponse(message)
            _state.value = newState
            onStateChanged?.invoke(newState)
        }
        return true
    }

    /**
     * Explicitly reset in-flight submission lock.
     */
    fun resetSubmitting() {
        isSubmitting.set(false)
    }

    /**
     * Request the desktop to generate and display a fresh PIN on its console.
     */
    fun requestNewPin(
        client: SnowWebSocketClient,
        onStateChanged: ((PairingState) -> Unit)? = null
    ): Boolean {
        if (client.connectionState.value != ConnectionState.CONNECTED) {
            val lostState = PairingState.ConnectionLost("Cannot request PIN: Not connected.")
            _state.value = lostState
            onStateChanged?.invoke(lostState)
            return false
        }

        val manifestMap = DeviceNode.buildAndroidManifest(null).toMap()
        val host = client.currentTargetHost
        val isLoopback = host == "127.0.0.1" || host == "localhost" || host == "::1"
        val requestData = mapOf(
            "device_id" to identity.deviceId,
            "device_name" to identity.deviceName,
            "manifest" to manifestMap,
            "connection_mode" to if (isLoopback) "usb_adb" else "wifi_lan",
            "transport_mode" to if (isLoopback) "usb_adb" else "wifi_lan"
        )

        client.sendRequest(
            action = "pair_request",
            data = requestData
        ) { message ->
            val newState = when (message.type) {
                MessageType.RESPONSE -> PairingState.WaitingForPin
                MessageType.ERROR -> PairingState.Error(message.error?.message ?: "Failed to generate PIN.")
                else -> PairingState.WaitingForPin
            }
            _state.value = newState
            onStateChanged?.invoke(newState)
        }
        return true
    }

    /**
     * Unpair this device from the connected desktop core.
     *
     * Dispatches an authenticated 'unpair_request' with the device's token.
     * On successful unpairing, clears the stored token and resets state to WaitingForPin.
     *
     * @return true if the unpair request was successfully dispatched.
     */
    fun unpair(
        client: SnowWebSocketClient,
        onStateChanged: ((PairingState) -> Unit)? = null
    ): Boolean {
        if (client.connectionState.value != ConnectionState.CONNECTED) {
            val lostState = PairingState.ConnectionLost("Cannot unpair: Not connected to desktop.")
            _state.value = lostState
            onStateChanged?.invoke(lostState)
            return false
        }

        if (!isSubmitting.compareAndSet(false, true)) {
            return false
        }

        val token = tokenStorage?.getToken() ?: ""
        val requestData = mapOf(
            "device_id" to identity.deviceId,
            "auth_token" to token
        )

        client.sendRequest(
            action = "unpair_request",
            data = requestData
        ) { message ->
            isSubmitting.set(false)
            val newState = when (message.type) {
                MessageType.RESPONSE -> {
                    tokenStorage?.clearToken()
                    PairingState.WaitingForPin
                }
                MessageType.ERROR -> {
                    val code = message.error?.code ?: ErrorCode.INTERNAL_ERROR
                    val errorMsg = message.error?.message ?: "Unpair failed."
                    if (code == ErrorCode.DEVICE_NOT_FOUND || code == ErrorCode.UNAUTHORIZED) {
                        // Device is already not recognized on desktop; clean local state
                        tokenStorage?.clearToken()
                        PairingState.WaitingForPin
                    } else {
                        PairingState.Error(errorMsg)
                    }
                }
                else -> PairingState.Error("Unexpected response type during unpair: ${message.type}")
            }
            _state.value = newState
            onStateChanged?.invoke(newState)
        }

        return true
    }

    /**
     * Reset pairing state back to WaitingForPin unless locked.
     */
    fun reset() {
        if (_state.value !is PairingState.Locked) {
            _state.value = PairingState.WaitingForPin
        }
    }

    /**
     * Mark state as Paired upon successful automatic post-connection authentication handshake.
     */
    fun setAuthenticated(
        sessionId: String,
        desktopName: String = "SNOW Desktop",
        trustTier: String = "peer",
        deviceType: String? = null,
        permissionProfile: String? = null
    ) {
        val newState = PairingState.Paired(
            desktopId = "desktop-core",
            desktopName = desktopName,
            sessionId = sessionId,
            trustTier = trustTier,
            deviceType = deviceType,
            permissionProfile = permissionProfile
        )
        _state.value = newState
    }

    internal fun handlePairingResponse(message: SnowMessage): PairingState {
        return when (message.type) {
            MessageType.RESPONSE -> {
                val payload = message.payload ?: emptyMap()
                val data = (payload["data"] as? Map<*, *>) ?: payload
                val desktopId = data?.get("device_id") as? String ?: "unknown"
                val desktopName = data?.get("device_name") as? String ?: "SNOW Desktop"
                val sessionId = data?.get("session_id") as? String ?: "session-active"
                val authToken = data?.get("auth_token") as? String
                val trustTier = data?.get("trust_tier") as? String ?: "peer"
                val permissionProfile = data?.get("permission_profile") as? String
                val manifest = data?.get("manifest") as? Map<*, *>
                val deviceType = (data?.get("device_type") as? String)
                    ?: (data?.get("platform") as? String)
                    ?: (manifest?.get("platform") as? String)
                    ?: (manifest?.get("device_type") as? String)

                if (!authToken.isNullOrBlank()) {
                    tokenStorage?.saveToken(authToken)
                }

                PairingState.Paired(
                    desktopId = desktopId,
                    desktopName = desktopName,
                    sessionId = sessionId,
                    authToken = authToken,
                    trustTier = trustTier,
                    deviceType = deviceType,
                    permissionProfile = permissionProfile
                )
            }

            MessageType.ERROR -> {
                val code = message.error?.code ?: ErrorCode.INTERNAL_ERROR
                val errorMsg = message.error?.message ?: "Pairing failed."

                when (code) {
                    ErrorCode.INVALID_PIN -> {
                        // Extract remaining attempts if present in message or default
                        val remaining = extractRemainingAttempts(errorMsg)
                        PairingState.WrongPin(message = errorMsg, remainingAttempts = remaining)
                    }

                    ErrorCode.PIN_EXPIRED -> PairingState.Expired(
                        message = if (errorMsg.isNotBlank()) errorMsg else "Pairing credential expired. Generate a fresh QR code or PIN."
                    )

                    ErrorCode.PAIRING_LOCKED -> PairingState.Locked(message = errorMsg)

                    ErrorCode.ALREADY_PAIRED -> PairingState.Paired(
                        desktopId = "already-paired",
                        desktopName = "SNOW Desktop",
                        sessionId = "existing-session"
                    )

                    else -> PairingState.Error(message = errorMsg)
                }
            }

            else -> PairingState.Error("Unexpected response type: ${message.type}")
        }
    }

    private fun extractRemainingAttempts(msg: String): Int {
        val regex = Regex("""(\d+)\s+attempt""")
        val match = regex.find(msg)
        return match?.groupValues?.get(1)?.toIntOrNull() ?: 1
    }
}
