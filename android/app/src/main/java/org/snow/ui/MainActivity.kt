package org.snow.ui

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.Uri
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.provider.OpenableColumns
import android.app.Dialog
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.inputmethod.InputMethodManager
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.util.Locale
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.snow.R
import org.snow.databinding.ActivityMainBinding
import org.snow.network.AuthState
import org.snow.network.ConnectionState
import org.snow.network.DiscoveredPeer
import org.snow.network.DiscoveryManager
import org.snow.protocol.Constants
import org.snow.security.DeviceIdentity
import org.snow.security.EncryptedCertPinStorage
import org.snow.security.PairingFlow
import org.snow.security.PairingState
import org.snow.security.SharedPreferencesTokenStorage
import org.snow.service.SnowForegroundService
import org.snow.transfer.FileTransferClient
import org.snow.transfer.FileTransferClient.TransferResult
import java.io.File

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var service: SnowForegroundService? = null
    private var isBound = false

    private lateinit var identity: DeviceIdentity
    private lateinit var tokenStorage: SharedPreferencesTokenStorage
    private lateinit var pairingFlow: PairingFlow
    private lateinit var discoveryManager: DiscoveryManager

    private var stateJob: Job? = null
    private var logsJob: Job? = null
    private var authJob: Job? = null
    private var discoveryJob: Job? = null

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
        discoveryManager = DiscoveryManager(
            certPinStorage = EncryptedCertPinStorage(this),
            tokenStorage = tokenStorage
        )

        setupListeners()
        setupPinFocusAndKeyboard()
        setupFilterPills()

        appendLog("Device Identity: ${identity.deviceId.take(8)}... (${identity.deviceName})")
    }

    override fun onStart() {
        super.onStart()
        val intent = Intent(this, SnowForegroundService::class.java)
        bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
        discoveryManager.startListening()
        discoveryJob = lifecycleScope.launch {
            discoveryManager.peers.collectLatest { peers ->
                renderDiscoveredPeers(peers)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        org.snow.capabilities.ClipboardHandler.isAppInForeground = true
        service?.updateManifest()
    }

    override fun onPause() {
        super.onPause()
        org.snow.capabilities.ClipboardHandler.isAppInForeground = false
        org.snow.capabilities.ClipboardHandler.isUserIntentGranted = false
        service?.updateManifest()
    }

    override fun onStop() {
        super.onStop()
        cleanupObservers()
        discoveryJob?.cancel()
        discoveryJob = null
        discoveryManager.stopListening()
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

        setupRemoteDesktopListeners()
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

    private fun renderDiscoveredPeers(peers: List<DiscoveredPeer>) {
        val nonStale = peers.filter { !it.isStale }
        if (nonStale.isEmpty()) {
            binding.layoutDiscoveredPeers.visibility = View.GONE
            binding.containerDiscoveredList.removeAllViews()
            return
        }

        binding.layoutDiscoveredPeers.visibility = View.VISIBLE
        binding.containerDiscoveredList.removeAllViews()

        for (peer in nonStale) {
            val peerView = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(16, 12, 16, 12)
                setBackgroundResource(R.drawable.bg_card_glacier)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    bottomMargin = 8
                }
                isClickable = true
                isFocusable = true
                setOnClickListener {
                    binding.editHost.setText(peer.ipAddress)
                    binding.editPort.setText(peer.port.toString())
                    Toast.makeText(this@MainActivity, "Selected ${peer.deviceName} (${peer.ipAddress})", Toast.LENGTH_SHORT).show()
                }
            }

            val infoLayout = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }

            val titleView = TextView(this).apply {
                text = "${peer.deviceName} (${peer.ipAddress})"
                textSize = 13f
                setTypeface(null, Typeface.BOLD)
                setTextColor(ContextCompat.getColor(this@MainActivity, R.color.primary_text))
            }

            val statusView = TextView(this).apply {
                text = if (peer.isPaired) "Paired Core • Port ${peer.port}" else "Available Peer • Port ${peer.port}"
                textSize = 11f
                setTextColor(ContextCompat.getColor(this@MainActivity, if (peer.isPaired) R.color.primary_blue else R.color.secondary_text))
            }

            infoLayout.addView(titleView)
            infoLayout.addView(statusView)
            peerView.addView(infoLayout)

            val tapHint = TextView(this).apply {
                text = "USE"
                textSize = 11f
                setTypeface(null, Typeface.BOLD)
                setTextColor(ContextCompat.getColor(this@MainActivity, R.color.primary_blue))
            }
            peerView.addView(tapHint)

            binding.containerDiscoveredList.addView(peerView)
        }
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

                binding.btnConnect.isEnabled = true
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

                binding.btnConnect.isEnabled = true
                binding.btnDisconnect.isEnabled = true
                binding.btnPing.alpha = 0.5f
                binding.editPin.isEnabled = false
                binding.btnPair.isEnabled = false
                binding.btnRequestPin.isEnabled = false

                pairingFlow.resetSubmitting()
            }
        }
        updateRemoteDesktopUi()
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
        updateRemoteDesktopUi()
    }

    private fun updateRemoteDesktopUi() {
        val isConnected = service?.client?.connectionState?.value == ConnectionState.CONNECTED
        val isPaired = pairingFlow.state.value is PairingState.Paired
        binding.cardRemoteDesktop.visibility = if (isConnected && isPaired) View.VISIBLE else View.GONE
    }

    private fun setupRemoteDesktopListeners() {
        binding.btnPcStatus.setOnClickListener {
            val client = service?.client
            if (client == null || client.connectionState.value != ConnectionState.CONNECTED) {
                Toast.makeText(this, "Not connected to PC", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            binding.tvPcStatusInfo.text = "Querying PC telemetry..."
            client.sendRequest("desktop_status") { response ->
                runOnUiThread {
                    if (response.isSuccess) {
                        val data = response.payload?.get("data") as? Map<*, *>
                        val host = data?.get("hostname") ?: "PC"
                        val cpu = data?.get("cpu_percent") ?: 0.0
                        val mem = data?.get("memory_percent") ?: 0.0
                        val uptime = (data?.get("uptime_seconds") as? Number)?.toLong() ?: 0L
                        val battery = data?.get("battery") as? Map<*, *>
                        val batPct = battery?.get("percent")
                        val batStr = if (batPct != null) "$batPct%" else "AC / N/A"

                        val info = "Host: $host | CPU: $cpu% | RAM: $mem% | Battery: $batStr | Uptime: ${uptime}s"
                        binding.tvPcStatusInfo.text = info
                        appendLog("PC Status: $info")
                    } else {
                        val err = response.error?.message ?: "Failed querying PC status."
                        binding.tvPcStatusInfo.text = "Error: $err"
                        appendLog("PC Status error: $err")
                    }
                }
            }
        }

        binding.btnClipboardPhoneToPc.setOnClickListener {
            val client = service?.client
            if (client == null || client.connectionState.value != ConnectionState.CONNECTED) {
                Toast.makeText(this, "Not connected to PC", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
            val clip = clipboard.primaryClip
            val text = if (clip != null && clip.itemCount > 0) clip.getItemAt(0).text?.toString() else null
            if (text.isNullOrEmpty()) {
                Toast.makeText(this, "Phone clipboard is empty", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            binding.tvClipboardStatus.visibility = View.VISIBLE
            binding.tvClipboardStatus.text = "Pushing to PC clipboard..."
            client.sendRequest("desktop_clipboard_set", mapOf("text" to text)) { resp ->
                runOnUiThread {
                    if (resp.isSuccess) {
                        binding.tvClipboardStatus.text = "Pushed ${text.length} chars to PC clipboard."
                        appendLog("Phone → PC clipboard synced (${text.length} chars)")
                    } else {
                        val err = resp.error?.message ?: "Failed setting PC clipboard."
                        binding.tvClipboardStatus.text = "Error: $err"
                        appendLog("Clipboard Push error: $err")
                    }
                }
            }
        }

        binding.btnClipboardPcToPhone.setOnClickListener {
            val client = service?.client
            if (client == null || client.connectionState.value != ConnectionState.CONNECTED) {
                Toast.makeText(this, "Not connected to PC", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            binding.tvClipboardStatus.visibility = View.VISIBLE
            binding.tvClipboardStatus.text = "Fetching PC clipboard..."
            client.sendRequest("desktop_clipboard_get") { resp ->
                runOnUiThread {
                    if (resp.isSuccess) {
                        val data = resp.payload?.get("data") as? Map<*, *>
                        val text = data?.get("text") as? String ?: ""
                        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                        val clip = android.content.ClipData.newPlainText("SNOW PC Clipboard", text)
                        clipboard.setPrimaryClip(clip)
                        binding.tvClipboardStatus.text = "Copied ${text.length} chars from PC to phone."
                        appendLog("PC → Phone clipboard synced (${text.length} chars)")
                    } else {
                        val err = resp.error?.message ?: "Failed getting PC clipboard."
                        binding.tvClipboardStatus.text = "Error: $err"
                        appendLog("Clipboard Get error: $err")
                    }
                }
            }
        }

        binding.btnBrowsePcFiles.setOnClickListener {
            val client = service?.client
            if (client == null || client.connectionState.value != ConnectionState.CONNECTED) {
                Toast.makeText(this, "Not connected to PC", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            openPcFileBrowserDialog(client)
        }

        binding.btnLaunchApp.setOnClickListener {
            val client = service?.client
            if (client == null || client.connectionState.value != ConnectionState.CONNECTED) {
                Toast.makeText(this, "Not connected to PC", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val apps = arrayOf("notepad", "calc", "code", "explorer", "taskmgr", "mspaint", "chrome", "msedge", "wt", "powershell")
            AlertDialog.Builder(this)
                .setTitle("Launch Allowlisted PC App")
                .setItems(apps) { _, which ->
                    val chosen = apps[which]
                    appendLog("Launching PC app '$chosen'...")
                    client.sendRequest("desktop_app_launch", mapOf("app_name" to chosen)) { resp ->
                        runOnUiThread {
                            if (resp.isSuccess) {
                                Toast.makeText(this, "Launched $chosen on PC", Toast.LENGTH_SHORT).show()
                                appendLog("PC app '$chosen' launched successfully.")
                            } else {
                                val err = resp.error?.message ?: "Launch failed."
                                Toast.makeText(this, "Launch failed: $err", Toast.LENGTH_SHORT).show()
                                appendLog("App launch error: $err")
                            }
                        }
                    }
                }
                .setNegativeButton("Cancel", null)
                .show()
        }

        binding.btnLockPc.setOnClickListener {
            val client = service?.client
            if (client == null || client.connectionState.value != ConnectionState.CONNECTED) {
                Toast.makeText(this, "Not connected to PC", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            AlertDialog.Builder(this)
                .setTitle("Lock PC Screen?")
                .setMessage("Are you sure you want to lock the Windows PC workstation?")
                .setPositiveButton("Lock PC") { _, _ ->
                    client.sendRequest("desktop_app_launch", mapOf("app_name" to "lock_screen")) { resp ->
                        runOnUiThread {
                            if (resp.isSuccess) {
                                Toast.makeText(this, "PC locked successfully", Toast.LENGTH_SHORT).show()
                                appendLog("PC workstation locked.")
                            } else {
                                val err = resp.error?.message ?: "Failed locking PC."
                                Toast.makeText(this, "Lock failed: $err", Toast.LENGTH_SHORT).show()
                                appendLog("Lock PC error: $err")
                            }
                        }
                    }
                }
                .setNegativeButton("Cancel", null)
                .show()
        }

        binding.btnRunCommand.setOnClickListener {
            val client = service?.client
            if (client == null || client.connectionState.value != ConnectionState.CONNECTED) {
                Toast.makeText(this, "Not connected to PC", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val cmd = binding.editPcCommand.text?.toString()?.trim() ?: ""
            if (cmd.isEmpty()) {
                Toast.makeText(this, "Enter a command to execute", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            dismissKeyboard()
            confirmAndExecutePcCommand(cmd, client)
        }
    }

    private fun confirmAndExecutePcCommand(command: String, client: org.snow.network.SnowWebSocketClient) {
        AlertDialog.Builder(this)
            .setTitle("Execute PC Terminal Command?")
            .setMessage("The following command will run on your PC:\n\n$command\n\nProceed with execution?")
            .setPositiveButton("Execute") { _, _ ->
                binding.tvCommandOutput.visibility = View.VISIBLE
                binding.tvCommandOutput.text = "Executing: $command..."
                appendLog("Running PC command: $command")
                client.sendRequest("desktop_exec", mapOf("command" to command, "confirmed" to true)) { resp ->
                    runOnUiThread {
                        if (resp.isSuccess) {
                            val data = resp.payload?.get("data") as? Map<*, *>
                            val stdout = (data?.get("stdout") as? String) ?: ""
                            val stderr = (data?.get("stderr") as? String) ?: ""
                            val exitCode = data?.get("exit_code") ?: 0
                            val payloadError = resp.payload?.get("error") as? String

                            val output = buildString {
                                if (stdout.isNotBlank()) append(stdout)
                                if (stderr.isNotBlank()) {
                                    if (isNotEmpty()) append("\n[stderr]\n")
                                    append(stderr)
                                }
                                if (isEmpty()) {
                                    if (payloadError != null) {
                                        append("$payloadError (Exit code: $exitCode)")
                                    } else {
                                        append("(No output, exit code: $exitCode)")
                                    }
                                } else if (exitCode != 0 && exitCode != -1) {
                                    append("\n(Exit code: $exitCode)")
                                }
                            }
                            binding.tvCommandOutput.text = output
                            appendLog("PC command completed (exit code $exitCode)")
                        } else {
                            val err = resp.error?.message ?: "Execution failed."
                            binding.tvCommandOutput.text = "Error: $err"
                            appendLog("PC command error: $err")
                        }
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    data class PcFileItem(
        val name: String,
        val type: String,
        val sizeBytes: Long,
        val modifiedAt: String?
    )

    private fun openPcFileBrowserDialog(client: org.snow.network.SnowWebSocketClient) {
        val dialog = Dialog(this)
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE)
        dialog.setContentView(R.layout.dialog_pc_file_browser)
        dialog.window?.setLayout(
            ViewGroup.LayoutParams.MATCH_PARENT,
            (resources.displayMetrics.heightPixels * 0.90).toInt()
        )
        dialog.window?.setBackgroundDrawableResource(android.R.color.transparent)

        val tvDeviceStatus = dialog.findViewById<TextView>(R.id.tvDeviceStatus)
        val btnClose = dialog.findViewById<View>(R.id.btnCloseBrowser)
        val layoutDrives = dialog.findViewById<LinearLayout>(R.id.layoutDrives)
        val btnNavUp = dialog.findViewById<View>(R.id.btnNavUp)
        val tvCurrentPath = dialog.findViewById<TextView>(R.id.tvCurrentPath)
        val btnNavManual = dialog.findViewById<View>(R.id.btnNavManual)
        val btnNavRefresh = dialog.findViewById<View>(R.id.btnNavRefresh)
        val rvFileList = dialog.findViewById<RecyclerView>(R.id.rvFileList)
        val progressLoading = dialog.findViewById<ProgressBar>(R.id.progressLoading)
        val layoutError = dialog.findViewById<LinearLayout>(R.id.layoutError)
        val tvErrorMessage = dialog.findViewById<TextView>(R.id.tvErrorMessage)
        val btnRetry = dialog.findViewById<View>(R.id.btnRetry)
        val tvEmptyState = dialog.findViewById<TextView>(R.id.tvEmptyState)
        val tvFooterSummary = dialog.findViewById<TextView>(R.id.tvFooterSummary)

        tvDeviceStatus.text = "Host: ${client.currentTargetHost} • Connected"
        btnClose.setOnClickListener { dialog.dismiss() }

        var currentPath: String = ""
        var parentPath: String? = null
        var requestSeq: Long = 0L

        lateinit var loadDirectory: (String) -> Unit

        val adapter = PcFileAdapter { item ->
            if (item.type == "directory") {
                val nextPath = if (currentPath.endsWith("\\") || currentPath.endsWith("/")) {
                    "$currentPath${item.name}"
                } else {
                    "$currentPath\\${item.name}"
                }
                loadDirectory(nextPath)
            } else {
                val fullFilePath = if (currentPath.endsWith("\\") || currentPath.endsWith("/")) {
                    "$currentPath${item.name}"
                } else {
                    "$currentPath\\${item.name}"
                }
                confirmAndDownloadPcFile(fullFilePath, item.name, item.sizeBytes, client)
            }
        }

        rvFileList.layoutManager = LinearLayoutManager(this)
        rvFileList.adapter = adapter

        loadDirectory = { targetPath ->
            val seq = ++requestSeq
            progressLoading.visibility = View.VISIBLE
            layoutError.visibility = View.GONE
            tvEmptyState.visibility = View.GONE
            // Only hide file list if we don't already have an active directory displayed
            if (currentPath.isEmpty()) {
                rvFileList.visibility = View.GONE
                tvCurrentPath.text = if (targetPath.isEmpty()) "(loading...)" else targetPath
            }

            val reqPayload = if (targetPath.isNotEmpty()) mapOf("path" to targetPath) else emptyMap<String, Any>()
            appendLog("Listing PC files: ${if (targetPath.isEmpty()) "(root)" else targetPath}")

            client.sendRequest("desktop_file_list", reqPayload) { resp ->
                runOnUiThread {
                    if (seq != requestSeq) return@runOnUiThread
                    progressLoading.visibility = View.GONE
                    if (resp.isSuccess) {
                        val data = resp.payload?.get("data") as? Map<*, *>
                        val dir = (data?.get("directory") as? String) ?: targetPath
                        val parent = data?.get("parent") as? String
                        @Suppress("UNCHECKED_CAST")
                        val drives = (data?.get("drives") as? List<Map<*, *>>) ?: emptyList()
                        @Suppress("UNCHECKED_CAST")
                        val filesRaw = (data?.get("files") as? List<Map<String, Any?>>) ?: emptyList()

                        currentPath = dir
                        parentPath = parent
                        tvCurrentPath.text = dir

                        btnNavUp.isEnabled = (parent != null)
                        btnNavUp.alpha = if (parent != null) 1.0f else 0.35f

                        renderDriveChips(layoutDrives, drives, dir) { chosenDrive ->
                            loadDirectory(chosenDrive)
                        }

                        val fileItems = filesRaw.map { f ->
                            PcFileItem(
                                name = (f["name"] as? String) ?: "unknown",
                                type = (f["type"] as? String) ?: "file",
                                sizeBytes = (f["size_bytes"] as? Number)?.toLong() ?: 0L,
                                modifiedAt = f["modified_at"] as? String
                            )
                        }

                        if (fileItems.isEmpty()) {
                            tvEmptyState.visibility = View.VISIBLE
                            rvFileList.visibility = View.GONE
                            tvFooterSummary.text = "0 items"
                        } else {
                            tvEmptyState.visibility = View.GONE
                            rvFileList.visibility = View.VISIBLE
                            adapter.submitList(fileItems)
                            val folderCount = fileItems.count { it.type == "directory" }
                            val fileCount = fileItems.size - folderCount
                            tvFooterSummary.text = "${fileItems.size} items ($folderCount folders, $fileCount files)"
                        }
                    } else {
                        val err = resp.error?.message ?: "Failed loading directory."
                        appendLog("PC file list error: $err")
                        if (currentPath.isNotEmpty()) {
                            // Preserve existing valid directory listing and inform owner
                            tvCurrentPath.text = currentPath
                            Toast.makeText(this, "Browse failed: $err", Toast.LENGTH_LONG).show()
                            tvFooterSummary.text = "Path error: $err"
                            rvFileList.visibility = View.VISIBLE
                        } else {
                            layoutError.visibility = View.VISIBLE
                            tvErrorMessage.text = err
                            rvFileList.visibility = View.GONE
                            tvFooterSummary.text = "Error"
                        }
                    }
                }
            }
        }

        btnNavUp.setOnClickListener {
            parentPath?.let { loadDirectory(it) }
        }

        btnNavRefresh.setOnClickListener {
            loadDirectory(currentPath)
        }

        btnRetry.setOnClickListener {
            loadDirectory(currentPath)
        }

        btnNavManual.setOnClickListener {
            val input = android.widget.EditText(this).apply {
                setText(currentPath)
                setSelection(text.length)
                setSingleLine(true)
            }
            AlertDialog.Builder(this)
                .setTitle("Enter PC Path")
                .setView(input)
                .setPositiveButton("Navigate") { _, _ ->
                    val entered = input.text.toString().trim()
                    if (entered.isNotEmpty()) {
                        loadDirectory(entered)
                    }
                }
                .setNegativeButton("Cancel", null)
                .show()
        }

        dialog.show()
        loadDirectory("")
    }

    private fun renderDriveChips(
        container: LinearLayout,
        drives: List<Map<*, *>>,
        currentDir: String,
        onDriveSelected: (String) -> Unit
    ) {
        container.removeAllViews()
        val driveList = if (drives.isNotEmpty()) {
            drives
        } else {
            listOf(mapOf("drive" to "C:\\"), mapOf("drive" to "D:\\"))
        }

        for (d in driveList) {
            val drivePath = (d["drive"] as? String) ?: continue
            val freeBytes = (d["free_bytes"] as? Number)?.toLong()
            val totalBytes = (d["total_bytes"] as? Number)?.toLong()
            val label = if (freeBytes != null && totalBytes != null && totalBytes > 0) {
                "$drivePath ${formatFileSize(freeBytes)} free / ${formatFileSize(totalBytes)}"
            } else if (freeBytes != null && freeBytes > 0) {
                "$drivePath (${formatFileSize(freeBytes)} free)"
            } else {
                drivePath
            }

            val isSelected = currentDir.startsWith(drivePath, ignoreCase = true)

            val tvChip = TextView(this).apply {
                text = label
                textSize = 12f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(if (isSelected) ContextCompat.getColor(context, R.color.primary_blue) else ContextCompat.getColor(context, R.color.primary_text))
                setBackgroundResource(R.drawable.bg_drive_chip)
                if (isSelected) {
                    setBackgroundColor(ContextCompat.getColor(context, R.color.soft_blue_surface))
                }
                setPadding(32, 16, 32, 16)
                val params = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    setMargins(8, 0, 8, 0)
                }
                layoutParams = params
                setOnClickListener { onDriveSelected(drivePath) }
            }
            container.addView(tvChip)
        }
    }

    private fun confirmAndDownloadPcFile(
        fullPath: String,
        fileName: String,
        fileSizeBytes: Long,
        client: org.snow.network.SnowWebSocketClient
    ) {
        val sizeStr = formatFileSize(fileSizeBytes)
        AlertDialog.Builder(this)
            .setTitle("Download File?")
            .setMessage("Do you want to download this file from your PC?\n\nFile: $fileName\nSize: $sizeStr\nPC Path: $fullPath\n\nDestination:\nDownloads/SNOW/$fileName")
            .setPositiveButton("Download") { _, _ ->
                appendLog("Staging download for PC file '$fullPath'...")
                client.sendRequest("desktop_file_stage_download", mapOf("file_path" to fullPath)) { resp ->
                    runOnUiThread {
                        if (resp.isSuccess) {
                            val data = resp.payload?.get("data") as? Map<*, *>
                            val tid = data?.get("transfer_id") as? String ?: ""
                            val fn = data?.get("file_name") as? String ?: fileName
                            val sha = data?.get("sha256") as? String ?: ""
                            val port = (data?.get("transfer_port") as? Number)?.toInt() ?: 8766
                            if (tid.isNotEmpty() && sha.isNotEmpty()) {
                                downloadPcFile(tid, fn, sha, port)
                            } else {
                                Toast.makeText(this, "Staging response missing transfer details", Toast.LENGTH_SHORT).show()
                            }
                        } else {
                            val err = resp.error?.message ?: "Staging failed."
                            Toast.makeText(this, "Stage download failed: $err", Toast.LENGTH_SHORT).show()
                            appendLog("Stage download error: $err")
                        }
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    class PcFileAdapter(
        private val onItemClick: (PcFileItem) -> Unit
    ) : RecyclerView.Adapter<PcFileAdapter.ViewHolder>() {

        private val items = mutableListOf<PcFileItem>()

        fun submitList(newItems: List<PcFileItem>) {
            items.clear()
            items.addAll(newItems)
            notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context).inflate(R.layout.item_pc_file, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            holder.bind(items[position], onItemClick)
        }

        override fun getItemCount(): Int = items.size

        class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
            private val imgIcon: ImageView = itemView.findViewById(R.id.imgFileIcon)
            private val tvName: TextView = itemView.findViewById(R.id.tvFileName)
            private val tvMeta: TextView = itemView.findViewById(R.id.tvFileMeta)
            private val imgAction: ImageView = itemView.findViewById(R.id.imgActionIcon)

            fun bind(item: PcFileItem, onClick: (PcFileItem) -> Unit) {
                tvName.text = item.name
                if (item.type == "directory") {
                    imgIcon.setImageResource(R.drawable.ic_pc_folder)
                    tvMeta.text = "Folder"
                    imgAction.setImageResource(R.drawable.ic_pc_arrow_up)
                    imgAction.rotation = 90f
                    imgAction.alpha = 0.4f
                } else {
                    imgIcon.setImageResource(R.drawable.ic_pc_file)
                    val sizeStr = formatFileSize(item.sizeBytes)
                    val dateStr = formatIsoDate(item.modifiedAt)
                    tvMeta.text = if (dateStr.isNotEmpty()) "$sizeStr • $dateStr" else sizeStr
                    imgAction.setImageResource(R.drawable.ic_pc_download)
                    imgAction.rotation = 0f
                    imgAction.alpha = 1.0f
                }
                itemView.setOnClickListener { onClick(item) }
            }
        }
    }

    companion object {
        fun formatFileSize(bytes: Long): String {
            if (bytes <= 0) return "0 B"
            if (bytes < 1024) return "$bytes B"
            val kb = bytes / 1024.0
            if (kb < 1024) return String.format(Locale.US, "%.1f KB", kb)
            val mb = kb / 1024.0
            if (mb < 1024) return String.format(Locale.US, "%.1f MB", mb)
            val gb = mb / 1024.0
            return String.format(Locale.US, "%.2f GB", gb)
        }

        fun formatIsoDate(iso: String?): String {
            if (iso.isNullOrEmpty()) return ""
            return try {
                val parsed = java.time.OffsetDateTime.parse(iso)
                val formatter = java.time.format.DateTimeFormatter.ofPattern("MMM dd, yyyy HH:mm", Locale.US)
                parsed.format(formatter)
            } catch (e: Exception) {
                iso.take(10)
            }
        }
    }

    private fun downloadPcFile(transferId: String, fileName: String, sha256: String, transferPort: Int) {
        val currentService = service ?: return
        val host = currentService.client.currentTargetHost
        val downloadsDir = File(getExternalFilesDir(null) ?: filesDir, "Downloads/SNOW").apply { mkdirs() }
        val destFile = File(downloadsDir, fileName)

        binding.cardTransferProgress.visibility = View.VISIBLE
        binding.txtTransferFileName.text = "Downloading: $fileName"
        binding.progressTransfer.progress = 0

        lifecycleScope.launch {
            val result = currentService.transferClient.downloadFile(
                serverHost = host,
                transferPort = transferPort,
                transferId = transferId,
                destinationFile = destFile,
                expectedSha256 = sha256,
                resume = true
            ) { progress ->
                runOnUiThread {
                    binding.progressTransfer.progress = progress.percent
                    binding.txtTransferPercent.text = "${progress.percent}%"
                    binding.txtTransferDetails.text = "${progress.bytesTransferred} / ${progress.totalBytes} bytes"
                }
            }

            runOnUiThread {
                binding.cardTransferProgress.visibility = View.GONE
                when (result) {
                    is FileTransferClient.TransferResult.Success -> {
                        Toast.makeText(this@MainActivity, "Downloaded: $fileName", Toast.LENGTH_LONG).show()
                        appendLog("Downloaded PC file '$fileName' successfully to ${destFile.absolutePath}")
                    }
                    is FileTransferClient.TransferResult.Error -> {
                        Toast.makeText(this@MainActivity, "Download failed: ${result.message}", Toast.LENGTH_LONG).show()
                        appendLog("File download error: ${result.message}")
                    }
                    is FileTransferClient.TransferResult.Duplicate -> {
                        Toast.makeText(this@MainActivity, "File already exists: $fileName", Toast.LENGTH_SHORT).show()
                        appendLog("File already up-to-date: $fileName")
                    }
                }
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

    /**
     * Enable foreground peer host mode on the bound service.
     */
    fun enablePeerHostMode(port: Int = 8767): Boolean {
        val s = service ?: return false
        val tStorage = SharedPreferencesTokenStorage(applicationContext)
        val success = s.peerHostManager.enableHostMode(
            port = port,
            tokenStorage = tStorage,
            dispatcher = s.capabilityDispatcher,
            localDeviceId = identity.deviceId,
            manifestProvider = { org.snow.network.DeviceNode.buildAndroidManifest(applicationContext).toMap() }
        )
        if (success) {
            appendLog("Android Foreground Peer Host Mode enabled on port $port")
            s.updateManifest()
        }
        return success
    }

    /**
     * Disable foreground peer host mode on the bound service.
     */
    fun disablePeerHostMode() {
        val s = service ?: return
        s.peerHostManager.disableHostMode()
        appendLog("Android Foreground Peer Host Mode disabled")
        s.updateManifest()
    }

    /**
     * Check if foreground peer host mode is actively listening.
     */
    fun isPeerHostModeActive(): Boolean {
        return service?.peerHostManager?.isHostModeActive() == true
    }
}
