package org.snow.ui.devices

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.flow.StateFlow
import org.snow.network.AuthState
import org.snow.network.ConnectionState
import org.snow.network.DiscoveredPeer
import org.snow.ui.SavedDevice
import org.snow.ui.SnowUiRepository

class DevicesViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = SnowUiRepository.getInstance(application)

    val connectionState: StateFlow<ConnectionState> = repository.connectionState
    val connectedEndpoint: StateFlow<String?> = repository.connectedEndpoint
    val authState: StateFlow<AuthState> = repository.authState
    val discoveredPeers: StateFlow<List<DiscoveredPeer>> = repository.discoveredPeers
    val savedDevices: StateFlow<List<SavedDevice>> = repository.savedDevices

    /**
     * Validate host and port before attempting connection.
     * Returns error message string if invalid, or null if valid.
     */
    fun validateConnectionInput(host: String, portStr: String): String? {
        val cleanHost = host.trim()
        if (cleanHost.isEmpty()) {
            return "Host IP or hostname cannot be empty."
        }

        // Host validation: allow valid IPv4 or alphanumeric hostname
        val ipv4Regex = Regex("^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.){3}(25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)$")
        val hostnameRegex = Regex("^[a-zA-Z0-9][-a-zA-Z0-9_.]*[a-zA-Z0-9]$")
        if (!ipv4Regex.matches(cleanHost) && !hostnameRegex.matches(cleanHost) && cleanHost != "localhost") {
            return "Invalid host address or IP format."
        }

        val port = portStr.trim().toIntOrNull()
        if (port == null || port !in 1..65535) {
            return "Port must be an integer between 1 and 65535."
        }

        return null
    }

    fun connect(host: String, port: Int) {
        repository.connect(host, port)
    }

    fun cancelConnection() {
        repository.cancelConnection()
    }

    fun disconnect() {
        repository.disconnect()
    }

    fun pairDevice(pin: String) {
        repository.pairDevice(pin)
    }

    fun unpairDevice() {
        repository.unpairDevice()
    }

    fun resetTrust() {
        repository.resetTrust()
    }

    fun confirmAndPinCertificate(fingerprint: String) {
        repository.confirmAndPinCertificate(fingerprint)
    }

    fun connectUsbLocalhost() {
        repository.connectUsbLocalhost()
    }

    fun handleQrScanPayload(qrJson: String, onComplete: (Boolean, String?) -> Unit) {
        repository.handleQrScanPayload(qrJson, onComplete)
    }
}
