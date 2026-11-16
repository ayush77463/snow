package org.snow.ui

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.provider.OpenableColumns
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.snow.R
import org.snow.databinding.ActivityMainBinding
import org.snow.network.AuthState
import org.snow.network.ConnectionState
import org.snow.protocol.Constants
import org.snow.security.DeviceIdentity
import org.snow.security.EncryptedCertPinStorage
import org.snow.security.PairingFlow
import org.snow.security.PairingState
import org.snow.security.SharedPreferencesTokenStorage
import org.snow.service.SnowForegroundService
import org.snow.transfer.FileTransferClient
import org.snow.transfer.FileTransferClient.TransferResult

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var service: SnowForegroundService? = null
    private var isBound = false

    private lateinit var identity: DeviceIdentity
    private lateinit var tokenStorage: SharedPreferencesTokenStorage
    private lateinit var pairingFlow: PairingFlow

    private var stateJob: Job? = null
    private var logsJob: Job? = null
    private var authJob: Job? = null

    // Activity timeline events list and current filter
    private enum class ActivityFilter { ALL, CONNECTIONS, DIAGNOSTICS }
    private var currentFilter = ActivityFilter.ALL
    private val activityEvents = mutableListOf<String>()

    private val filePickerLauncher =
        registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
            uri?.let { onFileSelectedForUpload(it) }
        }

    private val requestNotificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { isGranted ->
            if (isGranted) {
                appendLog("Notification permission granted.")
            } else {
                appendLog("Warning: Notification permission denied. Background notifications may not be shown.")
            }
        }

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val localBinder = binder as? SnowForegroundService.LocalBinder
            service = localBinder?.service
            isBound = true
            observeService()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            service = null
            isBound = false
            cleanupObservers()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // Enforce Light Mode strictly before super.onCreate (Glacier Blue Design System)
        AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO)

        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Setup Window Insets handling for Android 16 keyboard & system bars
        setupWindowInsets()

        checkNotificationPermission()
        identity = DeviceIdentity.getOrCreate(this)
        tokenStorage = SharedPreferencesTokenStorage(this)
        pairingFlow = PairingFlow(identity, tokenStorage)

        setupListeners()
        setupPinFocusAndKeyboard()
        setupFilterPills()

        appendLog("Device Identity: ${identity.deviceId.take(8)}... (${identity.deviceName})")
    }

    override fun onStart() {
        super.onStart()
        val intent = Intent(this, SnowForegroundService::class.java)
        bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
    }

    override fun onStop() {
        super.onStop()
        cleanupObservers()
        if (isBound) {
            unbindService(serviceConnection)
            isBound = false
        }
    }

    /**
     * Handle window insets dynamically for Android 16 / API 36.
     * Applies the maximum of system bar bottom and IME bottom insets to the root scroll container.
     */
    private fun setupWindowInsets() {
        val initialPaddingLeft = binding.rootScrollView.paddingLeft
        val initialPaddingTop = binding.rootScrollView.paddingTop
        val initialPaddingRight = binding.rootScrollView.paddingRight
        val initialPaddingBottom = binding.rootScrollView.paddingBottom

        ViewCompat.setOnApplyWindowInsetsListener(binding.rootScrollView) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            val effectiveBottom = maxOf(systemBars.bottom, ime.bottom)

            v.setPadding(
                initialPaddingLeft,
                initialPaddingTop,
                initialPaddingRight,
                initialPaddingBottom + effectiveBottom
            )
            insets
        }
    }

    /**
     * Ensure the PIN field and Pair Device button remain fully visible when the soft keyboard opens.
     */
    private fun setupPinFocusAndKeyboard() {
        binding.editPin.setOnFocusChangeListener { _, hasFocus ->
            if (hasFocus) {
                binding.rootScrollView.post {
                    val cardTop = binding.cardPairing.top
                    binding.rootScrollView.smoothScrollTo(0, cardTop)
                }
            }
        }

        binding.editPin.setOnClickListener {
            binding.rootScrollView.post {
                val cardTop = binding.cardPairing.top
                binding.rootScrollView.smoothScrollTo(0, cardTop)
            }
        }
    }

    private fun checkNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                requestNotificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun setupListeners() {
        binding.btnConnect.setOnClickListener {
            val host = binding.editHost.text?.toString()?.trim() ?: ""
            val portStr = binding.editPort.text?.toString()?.trim() ?: ""

            if (host.isEmpty()) {
                Toast.makeText(this, "Please enter desktop IP address", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val port = portStr.toIntOrNull()
            if (port == null || port !in 1..65535) {
                Toast.makeText(this, "Invalid port number (1-65535)", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            dismissKeyboard()
            SnowForegroundService.startConnect(this, host, port)
            appendLog("Initiating connection to $host:$port ...")
        }

        binding.btnDisconnect.setOnClickListener {
            dismissKeyboard()
            SnowForegroundService.stop(this)
            appendLog("Disconnect requested.")
        }

        binding.btnPing.setOnClickListener {
            val client = service?.client
            if (client == null || client.connectionState.value != ConnectionState.CONNECTED) {
                Toast.makeText(this, "Not connected", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val startMs = System.currentTimeMillis()
            binding.tvPingLatency.text = "Pinging..."

            client.sendRequest("ping") { _ ->
                val rtt = System.currentTimeMillis() - startMs
                runOnUiThread {
                    binding.tvPingLatency.text = "${rtt}ms RTT"
                    appendLog("Ping reply: ${rtt}ms round-trip latency")
                }
            }
        }

        binding.btnClearLog.setOnClickListener {
            activityEvents.clear()
            renderActivityTimeline()
        }

        binding.btnFileDrop.setOnClickListener {
            val client = service?.client
            if (client == null || client.connectionState.value != ConnectionState.CONNECTED) {
                Toast.makeText(this, "Connect to desktop before sending files", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            if (pairingFlow.state.value !is PairingState.Paired) {
                Toast.makeText(this, "Device must be paired to transfer files", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            filePickerLauncher.launch("*/*")
        }

        binding.btnPair.setOnClickListener {
            val client = service?.client
            if (client == null || client.connectionState.value != ConnectionState.CONNECTED) {
                Toast.makeText(this, "Must be connected to desktop to pair", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            // Dismiss keyboard cleanly upon action
            dismissKeyboard()

            if (pairingFlow.state.value is PairingState.Paired) {
                appendLog("Requesting device unpair from desktop...")
                val dispatched = pairingFlow.unpair(client) { state ->
                    runOnUiThread { updatePairingUi(state) }
                }
                if (!dispatched) {
                    appendLog("Could not dispatch unpair request.")
                }
            } else {
                val pin = binding.editPin.text?.toString()?.trim() ?: ""
                val submitted = pairingFlow.submitPin(pin, client) { state ->
                    runOnUiThread { updatePairingUi(state) }
                }
                if (submitted) {
                    appendLog("Submitting PIN $pin for verification...")
                } else {
                    val currState = pairingFlow.state.value
                    if (currState is PairingState.InProgress) {
                        appendLog("Verification already in progress. Please wait...")
                    } else if (!pairingFlow.validatePin(pin)) {
                        appendLog("PIN must be 6 decimal digits.")
                    } else {
                        appendLog("Could not submit PIN at this time.")
                    }
                }
            }
        }

        binding.btnRequestPin.setOnClickListener {
            val client = service?.client
            if (client == null || client.connectionState.value != ConnectionState.CONNECTED) {
                Toast.makeText(this, "Must be connected to desktop to request PIN", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            dismissKeyboard()
            pairingFlow.requestNewPin(client) { state ->
                runOnUiThread { updatePairingUi(state) }
            }
            appendLog("Requested fresh pairing PIN on desktop console...")
        }
    }

    private fun setupFilterPills() {
        binding.filterAll.setOnClickListener {
            setFilter(ActivityFilter.ALL)
        }
        binding.filterConnections.setOnClickListener {
            setFilter(ActivityFilter.CONNECTIONS)
        }
        binding.filterDiagnostics.setOnClickListener {
            setFilter(ActivityFilter.DIAGNOSTICS)
        }
    }

    private fun setFilter(filter: ActivityFilter) {
        currentFilter = filter

        binding.filterAll.setBackgroundResource(
            if (filter == ActivityFilter.ALL) R.drawable.bg_pill_filter_selected else R.drawable.bg_pill_filter_unselected
        )
        binding.filterAll.setTextColor(
            ContextCompat.getColor(this, if (filter == ActivityFilter.ALL) R.color.primary_blue else R.color.secondary_text)
        )

        binding.filterConnections.setBackgroundResource(
            if (filter == ActivityFilter.CONNECTIONS) R.drawable.bg_pill_filter_selected else R.drawable.bg_pill_filter_unselected
        )
        binding.filterConnections.setTextColor(
            ContextCompat.getColor(this, if (filter == ActivityFilter.CONNECTIONS) R.color.primary_blue else R.color.secondary_text)
        )

        binding.filterDiagnostics.setBackgroundResource(
            if (filter == ActivityFilter.DIAGNOSTICS) R.drawable.bg_pill_filter_selected else R.drawable.bg_pill_filter_unselected
        )
        binding.filterDiagnostics.setTextColor(
            ContextCompat.getColor(this, if (filter == ActivityFilter.DIAGNOSTICS) R.color.primary_blue else R.color.secondary_text)
        )

        renderActivityTimeline()
    }

    private fun dismissKeyboard() {
        val windowInsetsController = WindowCompat.getInsetsController(window, binding.root)
        windowInsetsController.hide(WindowInsetsCompat.Type.ime())
    }

    private fun onFileSelectedForUpload(uri: Uri) {
        var fileName = "file_${System.currentTimeMillis()}"
        var fileSize = 0L

        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
            if (cursor.moveToFirst()) {
                if (nameIdx != -1) fileName = cursor.getString(nameIdx)
                if (sizeIdx != -1) fileSize = cursor.getLong(sizeIdx)
            }
        }

        val host = binding.editHost.text?.toString()?.trim() ?: "127.0.0.1"
        appendLog("Preparing file drop: $fileName (${fileSize / 1024} KB)...")

        binding.cardTransferProgress.visibility = View.VISIBLE
        binding.txtTransferFileName.text = fileName
        binding.progressTransfer.progress = 0
        binding.txtTransferPercent.text = "0%"
        binding.txtTransferDetails.text = "Starting upload..."

        lifecycleScope.launch {
            val transferClient = FileTransferClient(
                context = applicationContext,
                deviceId = identity.deviceId,
                certPinStorage = EncryptedCertPinStorage(this@MainActivity),
                tokenStorage = tokenStorage,
                useTls = true,
            )

            val result = transferClient.uploadUri(
                serverHost = host,
                transferPort = 8766,
                uri = uri,
                fileName = fileName,
                fileSize = fileSize,
                onProgress = { progress ->
                    runOnUiThread {
                        binding.progressTransfer.progress = progress.percent
                        binding.txtTransferPercent.text = "${progress.percent}%"
                        binding.txtTransferDetails.text =
                            "${progress.bytesTransferred / 1024} KB / ${progress.totalBytes / 1024} KB"
                    }
                }
            )

            when (result) {
                is TransferResult.Success -> {
                    appendLog("File drop complete: $fileName (Verified SHA-256: ${result.sha256.take(16)}...)")
                    Toast.makeText(this@MainActivity, "File Transfer Complete!", Toast.LENGTH_SHORT).show()
                    binding.txtTransferDetails.text = "Transfer Verified and Completed"
                    binding.root.postDelayed({
                        binding.cardTransferProgress.visibility = View.GONE
                    }, 2500)
                }
                is TransferResult.Duplicate -> {
                    appendLog("File $fileName already exists on desktop (SHA-256 match, duplicate skipped)")
                    Toast.makeText(this@MainActivity, "Duplicate: File already on desktop", Toast.LENGTH_SHORT).show()
                    binding.txtTransferDetails.text = "Already present on server (duplicate)"
                    binding.root.postDelayed({
                        binding.cardTransferProgress.visibility = View.GONE
                    }, 2000)
                }
                is TransferResult.Error -> {
                    appendLog("File drop failed: ${result.message}")
                    Toast.makeText(this@MainActivity, "Transfer Failed: ${result.message}", Toast.LENGTH_LONG).show()
                    binding.txtTransferDetails.text = "Failed: ${result.message}"
                    binding.root.postDelayed({
                        binding.cardTransferProgress.visibility = View.GONE
                    }, 3000)
                }
            }
        }
    }

    private fun observeService() {
        val currentService = service ?: return
        cleanupObservers()

        stateJob = lifecycleScope.launch {
            currentService.client.connectionState.collectLatest { state ->
                updateUiForState(state)
            }
        }

        logsJob = lifecycleScope.launch {
            currentService.client.logs.collectLatest { logLine ->
                appendLog(logLine)
            }
        }

        authJob = lifecycleScope.launch {
            currentService.client.authState.collectLatest { authState ->
                when (authState) {
                    is AuthState.FingerprintConfirmationRequired -> {
                        showFingerprintConfirmationDialog(authState.fingerprint, currentService.client)
                    }
                    is AuthState.FingerprintMismatch -> {
                        showFingerprintMismatchDialog(authState.pinned, authState.presented, currentService.client)
                    }
                    is AuthState.Authenticated -> {
                        pairingFlow.setAuthenticated(authState.sessionId)
                        updatePairingUi(pairingFlow.state.value)
                        appendLog("Device authenticated with desktop core (Session: ${authState.sessionId.take(8)}...)")
                    }
                    is AuthState.AuthFailed -> {
                        pairingFlow.reset()
                        updatePairingUi(pairingFlow.state.value)
                        appendLog("Authentication failed: ${authState.reason}")
                    }
                    else -> {}
                }
            }
        }
    }

    private fun showFingerprintConfirmationDialog(fingerprint: String, client: org.snow.network.SnowWebSocketClient) {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Verify Server Certificate")
            .setMessage(
                "The desktop core presented the following SHA-256 fingerprint:\n\n" +
                "$fingerprint\n\n" +
                "Verify that this matches the fingerprint displayed on your laptop terminal.\n\n" +
                "Do you trust this desktop endpoint?"
            )
            .setPositiveButton("Trust & Connect") { _, _ ->
                client.confirmAndPinCertificate(fingerprint)
                appendLog("User confirmed and pinned certificate: $fingerprint")
            }
            .setNegativeButton("Reject") { _, _ ->
                client.disconnect()
                appendLog("User rejected certificate fingerprint.")
            }
            .setCancelable(false)
            .show()
    }

    private fun showFingerprintMismatchDialog(pinned: String, presented: String, client: org.snow.network.SnowWebSocketClient) {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Security Warning: Certificate Mismatch")
            .setMessage(
                "The desktop presented a certificate that does NOT match the previously pinned identity!\n\n" +
                "Pinned:\n$pinned\n\n" +
                "Presented:\n$presented\n\n" +
                "This could indicate a Man-in-the-Middle attack or a regenerated server certificate."
            )
            .setPositiveButton("Reset Trust Decision") { _, _ ->
                client.resetCertificateTrust()
                appendLog("Certificate pin reset by user.")
            }
            .setNegativeButton("Disconnect") { _, _ ->
                client.disconnect()
            }
            .setCancelable(false)
            .show()
    }

    private fun cleanupObservers() {
        stateJob?.cancel()
        stateJob = null
        logsJob?.cancel()
        logsJob = null
        authJob?.cancel()
        authJob = null
    }

    private fun updateUiForState(state: ConnectionState) {
        binding.tvStatus.text = state.name

        when (state) {
            ConnectionState.DISCONNECTED -> {
                binding.tvStatusPill.text = "● Disconnected"
                binding.tvStatusPill.setBackgroundResource(R.drawable.bg_pill_status)
                binding.tvStatusPill.setTextColor(ContextCompat.getColor(this, R.color.status_disconnected_dark))

                binding.layoutConnectionInputs.visibility = View.VISIBLE
                binding.layoutConnectedBanner.visibility = View.GONE
                binding.btnConnect.isEnabled = true
                binding.btnDisconnect.isEnabled = false

                binding.btnPing.alpha = 0.5f
                binding.tvPingLatency.text = "Disabled"
                binding.editPin.isEnabled = false
                binding.btnPair.isEnabled = false
                binding.btnRequestPin.isEnabled = false

                pairingFlow.resetSubmitting()
                pairingFlow.reset()
                updatePairingUi(pairingFlow.state.value)
            }

            ConnectionState.CONNECTING -> {
                binding.tvStatusPill.text = "● Connecting..."
                binding.tvStatusPill.setBackgroundResource(R.drawable.bg_pill_status)
                binding.tvStatusPill.setTextColor(ContextCompat.getColor(this, R.color.status_connecting_dark))

                binding.btnConnect.isEnabled = false
                binding.btnDisconnect.isEnabled = true
                binding.btnPing.alpha = 0.5f
                binding.editPin.isEnabled = false
                binding.btnPair.isEnabled = false
                binding.btnRequestPin.isEnabled = false
            }

            ConnectionState.CONNECTED -> {
                val host = binding.editHost.text?.toString()?.trim() ?: "Desktop"
                val port = binding.editPort.text?.toString()?.trim() ?: "8765"

                binding.tvStatusPill.text = "● Connected • Local Network"
                binding.tvStatusPill.setBackgroundResource(R.drawable.bg_pill_status)
                binding.tvStatusPill.setTextColor(ContextCompat.getColor(this, R.color.status_connected_dark))

                binding.layoutConnectionInputs.visibility = View.GONE
                binding.layoutConnectedBanner.visibility = View.VISIBLE
                binding.tvConnectedEndpoint.text = "Connected to $host:$port"

                binding.btnConnect.isEnabled = false
                binding.btnDisconnect.isEnabled = true
                binding.btnPing.alpha = 1.0f
                binding.tvPingLatency.text = "Ready"

                updatePairingUi(pairingFlow.state.value)
            }

            ConnectionState.RECONNECTING -> {
                binding.tvStatusPill.text = "● Reconnecting..."
                binding.tvStatusPill.setBackgroundResource(R.drawable.bg_pill_status)
                binding.tvStatusPill.setTextColor(ContextCompat.getColor(this, R.color.status_reconnecting))

                binding.btnConnect.isEnabled = false
                binding.btnDisconnect.isEnabled = true
                binding.btnPing.alpha = 0.5f
                binding.editPin.isEnabled = false
                binding.btnPair.isEnabled = false
                binding.btnRequestPin.isEnabled = false

                pairingFlow.resetSubmitting()
            }
        }
    }

    private fun updatePairingUi(state: PairingState) {
        val isConnected = service?.client?.connectionState?.value == ConnectionState.CONNECTED

        when (state) {
            is PairingState.Idle, is PairingState.WaitingForPin -> {
                binding.btnPair.text = getString(R.string.btn_pair)
                binding.tvPairingBadge.text = getString(R.string.badge_unpaired)
                binding.tvPairingBadge.setTextColor(ContextCompat.getColor(this, R.color.secondary_text))
                binding.tvPairingStatus.text = "Enter 6-digit PIN shown on desktop console."
                binding.tvPairingStatus.setTextColor(ContextCompat.getColor(this, R.color.secondary_text))
                binding.editPin.isEnabled = isConnected
                binding.btnPair.isEnabled = isConnected
                binding.btnRequestPin.isEnabled = isConnected
            }

            is PairingState.InProgress -> {
                binding.tvPairingBadge.text = getString(R.string.badge_pairing)
                binding.tvPairingBadge.setTextColor(ContextCompat.getColor(this, R.color.status_connecting_dark))
                binding.tvPairingStatus.text = "Verifying PIN with desktop..."
                binding.tvPairingStatus.setTextColor(ContextCompat.getColor(this, R.color.status_connecting_dark))
                binding.editPin.isEnabled = false
                binding.btnPair.isEnabled = false
                binding.btnRequestPin.isEnabled = false
            }

            is PairingState.Paired -> {
                binding.btnPair.text = getString(R.string.btn_unpair)
                binding.tvPairingBadge.text = getString(R.string.badge_paired)
                binding.tvPairingBadge.setTextColor(ContextCompat.getColor(this, R.color.status_connected_dark))
                binding.tvPairingStatus.text = "✓ Paired with ${state.desktopName}"
                binding.tvPairingStatus.setTextColor(ContextCompat.getColor(this, R.color.status_connected_dark))
                binding.editPin.isEnabled = false
                binding.btnPair.isEnabled = isConnected
                binding.btnRequestPin.isEnabled = false
                appendLog("Pairing confirmed with ${state.desktopName} (Session: ${state.sessionId.take(8)}...)")
            }

            is PairingState.WrongPin -> {
                binding.btnPair.text = getString(R.string.btn_pair)
                binding.tvPairingBadge.text = "WRONG PIN"
                binding.tvPairingBadge.setTextColor(ContextCompat.getColor(this, R.color.status_disconnected_dark))
                binding.tvPairingStatus.text = "✗ ${state.message}"
                binding.tvPairingStatus.setTextColor(ContextCompat.getColor(this, R.color.status_disconnected_dark))
                binding.editPin.isEnabled = isConnected
                binding.btnPair.isEnabled = isConnected
                binding.btnRequestPin.isEnabled = isConnected
                appendLog("Pairing failed: ${state.message}")
            }

            is PairingState.Expired -> {
                binding.btnPair.text = getString(R.string.btn_pair)
                binding.tvPairingBadge.text = "EXPIRED"
                binding.tvPairingBadge.setTextColor(ContextCompat.getColor(this, R.color.status_connecting_dark))
                binding.tvPairingStatus.text = "⏳ ${state.message}"
                binding.tvPairingStatus.setTextColor(ContextCompat.getColor(this, R.color.status_connecting_dark))
                binding.editPin.isEnabled = isConnected
                binding.btnPair.isEnabled = isConnected
                binding.btnRequestPin.isEnabled = isConnected
                appendLog("Pairing PIN expired. Tap 'Request New PIN' to regenerate.")
            }

            is PairingState.Locked -> {
                binding.btnPair.text = getString(R.string.btn_pair)
                binding.tvPairingBadge.text = getString(R.string.badge_locked)
                binding.tvPairingBadge.setTextColor(ContextCompat.getColor(this, R.color.status_disconnected_dark))
                binding.tvPairingStatus.text = "🔒 ${state.message}"
                binding.tvPairingStatus.setTextColor(ContextCompat.getColor(this, R.color.status_disconnected_dark))
                binding.editPin.isEnabled = false
                binding.btnPair.isEnabled = false
                binding.btnRequestPin.isEnabled = isConnected
                appendLog("Pairing locked: ${state.message}")
            }

            is PairingState.ConnectionLost -> {
                binding.btnPair.text = getString(R.string.btn_pair)
                binding.tvPairingBadge.text = "OFFLINE"
                binding.tvPairingBadge.setTextColor(ContextCompat.getColor(this, R.color.status_disconnected_dark))
                binding.tvPairingStatus.text = "Connection lost during pairing."
                binding.tvPairingStatus.setTextColor(ContextCompat.getColor(this, R.color.status_disconnected_dark))
                binding.editPin.isEnabled = false
                binding.btnPair.isEnabled = false
                binding.btnRequestPin.isEnabled = false
            }

            is PairingState.Error -> {
                binding.btnPair.text = getString(R.string.btn_pair)
                binding.tvPairingBadge.text = "ERROR"
                binding.tvPairingBadge.setTextColor(ContextCompat.getColor(this, R.color.status_disconnected_dark))
                binding.tvPairingStatus.text = "Error: ${state.message}"
                binding.tvPairingStatus.setTextColor(ContextCompat.getColor(this, R.color.status_disconnected_dark))
                binding.editPin.isEnabled = isConnected
                binding.btnPair.isEnabled = isConnected
                binding.btnRequestPin.isEnabled = isConnected
                appendLog("Pairing error: ${state.message}")
            }
        }
    }

    private fun appendLog(line: String) {
        activityEvents.add(line)
        renderActivityTimeline()
    }

    private fun renderActivityTimeline() {
        val filtered = activityEvents.filter { event ->
            when (currentFilter) {
                ActivityFilter.ALL -> true
                ActivityFilter.CONNECTIONS -> {
                    event.contains("Connect", ignoreCase = true) ||
                    event.contains("Disconnect", ignoreCase = true) ||
                    event.contains("Heartbeat", ignoreCase = true) ||
                    event.contains("Handshake", ignoreCase = true) ||
                    event.contains("Reconnecting", ignoreCase = true)
                }
                ActivityFilter.DIAGNOSTICS -> {
                    event.contains("Ping", ignoreCase = true) ||
                    event.contains("Error", ignoreCase = true) ||
                    event.contains("Fail", ignoreCase = true) ||
                    event.contains("Warning", ignoreCase = true) ||
                    event.contains("Pairing", ignoreCase = true) ||
                    event.contains("Identity", ignoreCase = true)
                }
            }
        }

        if (filtered.isEmpty()) {
            binding.tvEmptyActivity.visibility = View.VISIBLE
            binding.tvLog.visibility = View.GONE
        } else {
            binding.tvEmptyActivity.visibility = View.GONE
            binding.tvLog.visibility = View.VISIBLE
            binding.tvLog.text = filtered.joinToString("\n")
        }
    }
}
