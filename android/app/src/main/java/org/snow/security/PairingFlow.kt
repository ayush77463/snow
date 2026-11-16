package org.snow.security

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.snow.network.ConnectionState
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
        val sessionId: String
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
    private val identity: DeviceIdentity
) {
    private val _state = MutableStateFlow<PairingState>(PairingState.WaitingForPin)
    val state: StateFlow<PairingState> = _state.asStateFlow()

    private val isSubmitting = AtomicBoolean(false)

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

        // Prevent duplicate concurrent submissions
        if (!isSubmitting.compareAndSet(false, true)) {
            return false
        }

        _state.value = PairingState.InProgress
        onStateChanged?.invoke(PairingState.InProgress)

        val cleanedPin = pin.trim()
        val requestData = mapOf(
            "device_id" to identity.deviceId,
            "device_name" to identity.deviceName,
            "pin" to cleanedPin
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

        val requestData = mapOf(
            "device_id" to identity.deviceId,
            "device_name" to identity.deviceName
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
     * Reset pairing state back to WaitingForPin unless locked.
     */
    fun reset() {
        if (_state.value !is PairingState.Locked) {
            _state.value = PairingState.WaitingForPin
        }
    }

    internal fun handlePairingResponse(message: SnowMessage): PairingState {
        return when (message.type) {
            MessageType.RESPONSE -> {
                val payload = message.payload ?: emptyMap()
                val data = payload["data"] as? Map<*, *>
                val desktopId = data?.get("device_id") as? String ?: "unknown"
                val desktopName = data?.get("device_name") as? String ?: "SNOW Desktop"
                val sessionId = data?.get("session_id") as? String ?: "session-active"

                PairingState.Paired(
                    desktopId = desktopId,
                    desktopName = desktopName,
                    sessionId = sessionId
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

                    ErrorCode.PIN_EXPIRED -> PairingState.Expired(message = errorMsg)

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
