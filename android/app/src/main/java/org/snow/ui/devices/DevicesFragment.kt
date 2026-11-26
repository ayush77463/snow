package org.snow.ui.devices

import android.content.Context
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import org.snow.R
import org.snow.databinding.FragmentDevicesBinding
import org.snow.network.AuthState
import org.snow.network.ConnectionState
import org.snow.network.DiscoveredPeer
import org.snow.ui.SavedDevice
import org.snow.ui.SnowUiRepository

class DevicesFragment : Fragment() {

    private var _binding: FragmentDevicesBinding? = null
    private val binding get() = _binding!!

    private val viewModel: DevicesViewModel by activityViewModels()
    private var currentDeviceFilter = "all"
    private var lastSavedDevicesList: List<SavedDevice> = emptyList()

    private val qrScanLauncher = registerForActivityResult(com.journeyapps.barcodescanner.ScanContract()) { result ->
        if (result.contents != null) {
            val qrText = result.contents
            viewModel.handleQrScanPayload(qrText) { success, error ->
                if (!success && error != null) {
                    Toast.makeText(requireContext(), error, Toast.LENGTH_LONG).show()
                } else if (success) {
                    Toast.makeText(requireContext(), "QR Pairing initiated!", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentDevicesBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        try {
            val prefs = requireContext().getSharedPreferences("snow_connection_prefs", Context.MODE_PRIVATE)
            val savedHost = prefs.getString("last_host", null)
            val savedPort = prefs.getString("last_port", null)
            if (!savedHost.isNullOrBlank()) {
                binding.etHostIp.setText(savedHost)
            }
            if (!savedPort.isNullOrBlank()) {
                binding.etPort.setText(savedPort)
            }
        } catch (_: Exception) {}
        setupListeners()
        setupInlinePinInputs()
        observeViewModel()
    }

    private fun setupInlinePinInputs() {
        val pinBoxes = listOf(
            binding.etPin1,
            binding.etPin2,
            binding.etPin3,
            binding.etPin4,
            binding.etPin5,
            binding.etPin6
        )

        for (i in pinBoxes.indices) {
            val currentBox = pinBoxes[i]
            currentBox.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    val text = s?.toString() ?: ""
                    if (text.length == 6) {
                        for (j in 0 until 6) {
                            pinBoxes[j].setText(text[j].toString())
                        }
                        pinBoxes.last().requestFocus()
                        pinBoxes.last().setSelection(1)
                    } else if (text.length == 1 && i < pinBoxes.size - 1) {
                        pinBoxes[i + 1].requestFocus()
                    }
                }
                override fun afterTextChanged(s: android.text.Editable?) {}
            })

            currentBox.setOnKeyListener { _, keyCode, event ->
                if (keyCode == android.view.KeyEvent.KEYCODE_DEL && event.action == android.view.KeyEvent.ACTION_DOWN) {
                    if (currentBox.text.isNullOrEmpty() && i > 0) {
                        pinBoxes[i - 1].requestFocus()
                        pinBoxes[i - 1].setText("")
                        return@setOnKeyListener true
                    }
                }
                false
            }
        }
    }

    private fun setupListeners() {
        binding.swipeRefresh.setOnRefreshListener {
            viewModel.refreshDevices()
            binding.swipeRefresh.isRefreshing = false
        }

        binding.chipFilterAll.setOnClickListener {
            currentDeviceFilter = "all"
            renderFilteredDevices()
        }
        binding.chipFilterPcs.setOnClickListener {
            currentDeviceFilter = "pcs"
            renderFilteredDevices()
        }
        binding.chipFilterPhones.setOnClickListener {
            currentDeviceFilter = "phones"
            renderFilteredDevices()
        }

        binding.btnScanQr.setOnClickListener {
            val options = com.journeyapps.barcodescanner.ScanOptions().apply {
                setPrompt("Scan SNOW Pairing QR Code")
                setBeepEnabled(false)
                setOrientationLocked(true)
                setCaptureActivity(org.snow.ui.PortraitCaptureActivity::class.java)
                setBarcodeImageEnabled(false)
                setDesiredBarcodeFormats(com.journeyapps.barcodescanner.ScanOptions.QR_CODE)
            }
            qrScanLauncher.launch(options)
        }

        binding.btnConnectUsb.setOnClickListener {
            Toast.makeText(requireContext(), "Connecting via USB (127.0.0.1:8765)...", Toast.LENGTH_SHORT).show()
            viewModel.connectUsbLocalhost()
        }

        binding.btnConnect.setOnClickListener {
            val host = binding.etHostIp.text?.toString() ?: ""
            val portStr = binding.etPort.text?.toString() ?: ""

            val validationErr = viewModel.validateConnectionInput(host, portStr)
            if (validationErr != null) {
                binding.tilHostIp.error = validationErr
                Toast.makeText(requireContext(), validationErr, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            binding.tilHostIp.error = null

            val cleanHost = host.trim()
            val port = portStr.trim().toInt()
            try {
                requireContext().getSharedPreferences("snow_connection_prefs", Context.MODE_PRIVATE)
                    .edit()
                    .putString("last_host", cleanHost)
                    .putString("last_port", portStr.trim())
                    .apply()
            } catch (_: Exception) {}
            viewModel.connect(cleanHost, port)
        }

        binding.btnCancelConnection.setOnClickListener {
            viewModel.cancelConnection()
        }

        binding.btnDisconnect.setOnClickListener {
            viewModel.disconnect()
        }

        binding.btnPair.setOnClickListener {
            val pinBoxes = listOf(binding.etPin1, binding.etPin2, binding.etPin3, binding.etPin4, binding.etPin5, binding.etPin6)
            val inlinePin = pinBoxes.joinToString("") { it.text?.toString() ?: "" }
            val pin = if (inlinePin.length == 6) inlinePin else (binding.etPin.text?.toString() ?: "")

            if (pin.length != 6) {
                Toast.makeText(requireContext(), "Please enter all 6 digits of the PIN", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            viewModel.pairDevice(pin)
        }

        binding.btnUnpair.setOnClickListener {
            viewModel.unpairDevice()
            Toast.makeText(requireContext(), "Device unpaired", Toast.LENGTH_SHORT).show()
        }

        binding.btnRequestPin.setOnClickListener {
            Toast.makeText(requireContext(), "To generate a fresh PIN, click 'Generate Pairing QR' on your laptop Web Dashboard.", Toast.LENGTH_LONG).show()
        }

        // Phone-to-Phone Host Mode
        binding.swHostMode.isChecked = viewModel.isPeerHostEnabled()
        binding.swHostMode.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                viewModel.startPeerHost()
                val pin = viewModel.generatePeerHostPin() ?: "--"
                binding.tvHostSharePin.text = "Share PIN: $pin"
                Toast.makeText(requireContext(), "Phone Host Mode active", Toast.LENGTH_SHORT).show()
            } else {
                viewModel.stopPeerHost()
                binding.tvHostSharePin.text = "Share PIN: --"
                Toast.makeText(requireContext(), "Phone Host Mode disabled", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnHostShowQr.setOnClickListener {
            val pin = viewModel.generatePeerHostPin() ?: "--"
            binding.tvHostSharePin.text = "Share PIN: $pin"
            val qrJson = viewModel.generatePairingQrJson()
            if (!qrJson.isNullOrBlank()) {
                try {
                    val barcodeEncoder = com.journeyapps.barcodescanner.BarcodeEncoder()
                    val bitmap = barcodeEncoder.encodeBitmap(qrJson, com.google.zxing.BarcodeFormat.QR_CODE, 500, 500)
                    val iv = android.widget.ImageView(requireContext()).apply {
                        setImageBitmap(bitmap)
                        setPadding(32, 16, 32, 16)
                        adjustViewBounds = true
                    }
                    AlertDialog.Builder(requireContext())
                        .setTitle("Phone-to-Phone Host QR")
                        .setMessage("Pairing PIN: $pin\n\nScan this code from another SNOW device on your Wi-Fi:")
                        .setView(iv)
                        .setPositiveButton("Done", null)
                        .show()
                } catch (e: Exception) {
                    Toast.makeText(requireContext(), "QR generation error: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            } else {
                Toast.makeText(requireContext(), "Enable Host Mode first to generate pairing QR", Toast.LENGTH_SHORT).show()
            }
        }

        // Cross-Network Sharing (Federation)
        fun refreshFederationGrants() {
            SnowUiRepository.getInstance(requireContext()).listFederationGrants { success, grants, err ->
                activity?.runOnUiThread {
                    binding.containerFederationGrants.removeAllViews()
                    if (success && !grants.isNullOrEmpty()) {
                        for (grant in grants) {
                            val grantId = grant["grant_id"]?.toString() ?: "unknown"
                            val role = grant["role"]?.toString() ?: "PEER"
                            val exp = grant["expires_at"]?.toString() ?: "Active"
                            val row = LinearLayout(requireContext()).apply {
                                orientation = LinearLayout.HORIZONTAL
                                setPadding(0, 4, 0, 4)
                                gravity = android.view.Gravity.CENTER_VERTICAL
                            }
                            val tv = TextView(requireContext()).apply {
                                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                                text = "• Grant $grantId ($role) - Exp: $exp"
                                textSize = 12f
                                setTextColor(ContextCompat.getColor(requireContext(), R.color.primary_text))
                            }
                            val btnRevoke = com.google.android.material.button.MaterialButton(requireContext(), null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                                text = "Revoke"
                                textSize = 10f
                                setOnClickListener {
                                    SnowUiRepository.getInstance(requireContext()).revokeFederationGrant(grantId) { revOk, revErr ->
                                        activity?.runOnUiThread {
                                            if (revOk) {
                                                Toast.makeText(requireContext(), "Grant $grantId revoked", Toast.LENGTH_SHORT).show()
                                                refreshFederationGrants()
                                            } else {
                                                Toast.makeText(requireContext(), "Revoke failed: $revErr", Toast.LENGTH_SHORT).show()
                                            }
                                        }
                                    }
                                }
                            }
                            row.addView(tv)
                            row.addView(btnRevoke)
                            binding.containerFederationGrants.addView(row)
                        }
                    } else {
                        val emptyTv = TextView(requireContext()).apply {
                            text = if (err != null) "Grants unavailable: $err" else "No active federation grants."
                            textSize = 12f
                            setTextColor(ContextCompat.getColor(requireContext(), R.color.secondary_text))
                        }
                        binding.containerFederationGrants.addView(emptyTv)
                    }
                }
            }
        }

        binding.btnGenerateFederationCode.setOnClickListener {
            SnowUiRepository.getInstance(requireContext()).createFederationInvite { success, payload, err ->
                activity?.runOnUiThread {
                    if (success && payload != null) {
                        val token = payload["invite_code"]?.toString() ?: payload["code"]?.toString() ?: "--"
                        binding.tvFederationStatus.text = "Active Federation Code: $token (Valid 10m)"
                        AlertDialog.Builder(requireContext())
                            .setTitle("Cross-Network Federation")
                            .setMessage("Invite Token: $token\n\nAnti-transitive zero-trust federation code. Enter this on the remote peer to establish cross-network connection.")
                            .setPositiveButton("Copy Code") { _, _ ->
                                val cm = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as? android.content.ClipboardManager
                                cm?.setPrimaryClip(android.content.ClipData.newPlainText("federation_code", token))
                                Toast.makeText(requireContext(), "Code copied to clipboard", Toast.LENGTH_SHORT).show()
                            }
                            .setNegativeButton("Close", null)
                            .show()
                        refreshFederationGrants()
                    } else {
                        Toast.makeText(requireContext(), "Federation error: $err", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }

        binding.btnFederationConnect.setOnClickListener {
            val code = binding.etFederationInviteCode.text?.toString()?.trim() ?: ""
            if (code.length < 6) {
                Toast.makeText(requireContext(), "Please enter a valid federation invitation code", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            Toast.makeText(requireContext(), "Accepting federation invite...", Toast.LENGTH_SHORT).show()
            SnowUiRepository.getInstance(requireContext()).acceptFederationInvite(code) { success, payload, err ->
                activity?.runOnUiThread {
                    if (success) {
                        Toast.makeText(requireContext(), "Federation linked successfully!", Toast.LENGTH_LONG).show()
                        binding.etFederationInviteCode.setText("")
                        refreshFederationGrants()
                    } else {
                        Toast.makeText(requireContext(), "Federation failed: $err", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }

        binding.btnFederationKillSwitch.setOnClickListener {
            AlertDialog.Builder(requireContext())
                .setTitle("🚨 Emergency Federation Kill Switch")
                .setMessage("Are you sure you want to terminate ALL cross-network federation connections and revoke all active grants immediately?")
                .setPositiveButton("Activate Kill Switch") { _, _ ->
                    SnowUiRepository.getInstance(requireContext()).federationKillSwitch { success, err ->
                        activity?.runOnUiThread {
                            if (success) {
                                Toast.makeText(requireContext(), "All federation connections terminated", Toast.LENGTH_LONG).show()
                                refreshFederationGrants()
                            } else {
                                Toast.makeText(requireContext(), "Kill switch error: $err", Toast.LENGTH_LONG).show()
                            }
                        }
                    }
                }
                .setNegativeButton("Cancel", null)
                .show()
        }

        refreshFederationGrants()
    }

    private fun observeViewModel() {
        viewLifecycleOwner.lifecycleScope.launch {
            combine(viewModel.connectionState, viewModel.connectedEndpoint) { state, endpoint ->
                Pair(state, endpoint)
            }.collectLatest { (state, endpoint) ->
                renderConnectionState(state)
                renderActiveTransport(state, endpoint)
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.authState.collectLatest { auth ->
                renderAuthState(auth)
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.discoveredPeers.collectLatest { peers ->
                renderDiscoveredPeers(peers)
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.savedDevices.collectLatest { saved ->
                lastSavedDevicesList = saved
                renderFilteredDevices()
                renderSavedDevices(saved)
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.peerHostState.collectLatest { state ->
                binding.tvHostPeerCount.text = "${state.peerCount} peers linked"
                binding.tvHostSharePin.text = "Share PIN: ${state.pairingPin ?: "--"}"
                if (binding.swHostMode.isChecked != state.isActive) {
                    binding.swHostMode.isChecked = state.isActive
                }
            }
        }
    }

    private fun renderFilteredDevices() {
        val filtered = viewModel.filterDevices(lastSavedDevicesList, currentDeviceFilter)
        renderConnectedDevices(filtered)
    }

    private fun renderConnectedDevices(devices: List<SavedDevice>) {
        binding.containerConnectedDevices.removeAllViews()
        if (devices.isEmpty()) {
            val emptyTv = TextView(requireContext()).apply {
                text = if (lastSavedDevicesList.isEmpty()) "No connected devices." else "No devices matching filter."
                textSize = 13f
                setTextColor(ContextCompat.getColor(requireContext(), R.color.secondary_text))
            }
            binding.containerConnectedDevices.addView(emptyTv)
            return
        }

        for (device in devices) {
            val card = MaterialCardView(requireContext()).apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { setMargins(0, 0, 0, 10) }
                radius = 14f
                cardElevation = 1f
                setCardBackgroundColor(ContextCompat.getColor(requireContext(), R.color.card_surface))
                strokeWidth = 1
                setStrokeColor(ContextCompat.getColor(requireContext(), R.color.card_border))
            }

            val row = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(14, 14, 14, 14)
                gravity = android.view.Gravity.CENTER_VERTICAL
            }

            val isPhone = device.deviceName.contains("phone", ignoreCase = true) ||
                          device.deviceName.contains("pixel", ignoreCase = true) ||
                          device.deviceName.contains("android", ignoreCase = true)

            val iconTv = TextView(requireContext()).apply {
                text = if (isPhone) "📱" else "💻"
                textSize = 24f
                setPadding(0, 0, 12, 0)
            }

            val info = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }

            val title = TextView(requireContext()).apply {
                text = device.deviceName
                textSize = 15f
                setTypeface(null, android.graphics.Typeface.BOLD)
                setTextColor(ContextCompat.getColor(requireContext(), R.color.primary_text))
            }

            val effectiveHost = if (device.host.isNotBlank()) device.host else device.recentEndpoints.firstOrNull()?.host ?: ""
            val effectivePort = if (device.port in 1..65535) device.port else device.recentEndpoints.firstOrNull()?.port ?: 8765
            val currentEp = viewModel.connectedEndpoint.value ?: ""
            val isCurrentActive = viewModel.connectionState.value == ConnectionState.CONNECTED &&
                (currentEp.startsWith("$effectiveHost:") || (effectiveHost == "127.0.0.1" && currentEp.startsWith("127.0.0.1")))

            val sub = TextView(requireContext()).apply {
                val connType = if (isPhone) "Peer Phone • Wi-Fi" else "Connected • Wi-Fi"
                val normTier = SnowUiRepository.normalizeTrustTier(device.trustTier).uppercase()
                val normProfile = SnowUiRepository.normalizeAccessProfile(device.permissionProfile)
                text = "$connType • Trust: $normTier • Profile: $normProfile"
                textSize = 12f
                setTextColor(ContextCompat.getColor(requireContext(), R.color.secondary_text))
            }

            val profileBtn = MaterialButton(requireContext(), null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                val currentProfile = SnowUiRepository.normalizeAccessProfile(device.permissionProfile)
                val profileLabel = when (currentProfile) {
                    "full_control" -> "Full Control"
                    "files_and_clipboard" -> "Files & Clipboard"
                    "files_only" -> "Files Only"
                    "clipboard_only" -> "Clipboard Only"
                    else -> "Not Allowed"
                }
                text = "👤 $profileLabel"
                textSize = 11f
                setOnClickListener {
                    val profiles = arrayOf("Full Control", "Files & Clipboard", "Files Only", "Clipboard Only", "Not Allowed")
                    AlertDialog.Builder(requireContext())
                        .setTitle("Access Profile: ${device.deviceName}")
                        .setItems(profiles) { _, which ->
                            val selected = profiles[which]
                            val canonical = SnowUiRepository.normalizeAccessProfile(selected)
                            viewModel.updateDevicePermissionProfile(device.deviceId, canonical)
                            SnowUiRepository.getInstance(requireContext()).activePermissionProfile = canonical
                            renderFilteredDevices()
                            Toast.makeText(requireContext(), "Profile updated to $selected", Toast.LENGTH_SHORT).show()
                        }
                        .setNegativeButton("Cancel", null)
                        .show()
                }
            }

            info.addView(title)
            info.addView(sub)
            info.addView(profileBtn)

            val actionBtn = MaterialButton(requireContext()).apply {
                text = if (isCurrentActive) "Active" else "Control"
                textSize = 12f
                if (isCurrentActive) {
                    backgroundTintList = ContextCompat.getColorStateList(requireContext(), R.color.status_connected)
                } else {
                    setOnClickListener {
                        binding.etHostIp.setText(effectiveHost)
                        binding.etPort.setText(effectivePort.toString())
                        viewModel.connect(effectiveHost, effectivePort)
                    }
                }
            }

            row.addView(iconTv)
            row.addView(info)
            row.addView(actionBtn)
            card.addView(row)
            binding.containerConnectedDevices.addView(card)
        }
    }

    private fun renderConnectionState(state: ConnectionState) {
        when (state) {
            ConnectionState.CONNECTED -> {
                binding.btnConnect.visibility = View.GONE
                binding.btnCancelConnection.visibility = View.GONE
                binding.btnDisconnect.visibility = View.VISIBLE
            }
            ConnectionState.CONNECTING, ConnectionState.RECONNECTING -> {
                binding.btnConnect.visibility = View.GONE
                binding.btnCancelConnection.visibility = View.VISIBLE
                binding.btnDisconnect.visibility = View.GONE
            }
            ConnectionState.DISCONNECTED -> {
                binding.btnConnect.visibility = View.VISIBLE
                binding.btnCancelConnection.visibility = View.GONE
                binding.btnDisconnect.visibility = View.GONE
            }
        }
    }

    private fun renderActiveTransport(state: ConnectionState, endpoint: String?) {
        val cleanEndpoint = endpoint ?: ""
        val isUsb = cleanEndpoint.startsWith("127.0.0.1") || cleanEndpoint.startsWith("localhost")
        val isRelay = cleanEndpoint.startsWith("relay:") || cleanEndpoint.contains("tunnel") || cleanEndpoint.contains(":8770")

        when (state) {
            ConnectionState.CONNECTED -> {
                val mode = if (isRelay) "RELAY TUNNEL" else if (isUsb) "USB (Localhost)" else "WI-FI MESH"
                binding.chipActiveTransport.text = "CONNECTED"
                binding.chipActiveTransport.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connected))
                binding.chipActiveTransport.setChipBackgroundColorResource(R.color.status_connected_soft)
                binding.tvActiveTransportDetail.text = "Connected to $cleanEndpoint via $mode."
            }
            ConnectionState.CONNECTING -> {
                binding.chipActiveTransport.text = "CONNECTING..."
                binding.chipActiveTransport.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connecting))
                binding.chipActiveTransport.setChipBackgroundColorResource(R.color.status_connecting_soft)
                binding.tvActiveTransportDetail.text = "Attempting connection to $cleanEndpoint..."
            }
            ConnectionState.RECONNECTING -> {
                binding.chipActiveTransport.text = "RECONNECTING..."
                binding.chipActiveTransport.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_reconnecting))
                binding.chipActiveTransport.setChipBackgroundColorResource(R.color.status_reconnecting_soft)
                binding.tvActiveTransportDetail.text = "Reconnecting with exponential backoff..."
            }
            ConnectionState.DISCONNECTED -> {
                binding.chipActiveTransport.text = "DISCONNECTED"
                binding.chipActiveTransport.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_disconnected))
                binding.chipActiveTransport.setChipBackgroundColorResource(R.color.status_disconnected_soft)
                binding.tvActiveTransportDetail.text = getString(R.string.desc_no_active_connection)
            }
        }
    }

    private fun renderAuthState(auth: AuthState) {
        when (auth) {
            is AuthState.Authenticated -> {
                binding.cardPairing.visibility = View.GONE
                binding.tvPairingBadge.text = "PAIRED"
                binding.tvPairingBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connected))
                binding.layoutPinInput.visibility = View.GONE
                binding.layoutPairedControls.visibility = View.VISIBLE
            }
            is AuthState.ConnectedUnauthenticated -> {
                binding.cardPairing.visibility = View.VISIBLE
                binding.tvPairingBadge.text = "UNPAIRED"
                binding.tvPairingBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connecting))
                binding.layoutPinInput.visibility = View.VISIBLE
                binding.layoutPairedControls.visibility = View.GONE
            }
            is AuthState.Connecting -> {
                binding.cardPairing.visibility = View.GONE
                binding.tvPairingBadge.text = "CONNECTING..."
                binding.tvPairingBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connecting))
                binding.layoutPinInput.visibility = View.GONE
                binding.layoutPairedControls.visibility = View.GONE
            }
            is AuthState.Disconnected -> {
                binding.cardPairing.visibility = View.GONE
                binding.tvPairingBadge.text = "DISCONNECTED"
                binding.tvPairingBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_disconnected))
                binding.layoutPinInput.visibility = View.GONE
                binding.layoutPairedControls.visibility = View.GONE
            }
            is AuthState.AuthFailed -> {
                binding.cardPairing.visibility = View.VISIBLE
                binding.tvPairingBadge.text = "PAIRING REQUIRED"
                binding.tvPairingBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_disconnected))
                binding.layoutPinInput.visibility = View.VISIBLE
                binding.layoutPairedControls.visibility = View.GONE
            }
            is AuthState.FingerprintConfirmationRequired -> {
                binding.tvPairingBadge.text = "CONFIRM CERT"
                binding.tvPairingBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connecting))
                binding.layoutPinInput.visibility = View.GONE
                binding.layoutPairedControls.visibility = View.GONE
                CertConfirmDialog.show(
                    context = requireContext(),
                    fingerprint = auth.fingerprint,
                    onTrustConfirmed = {
                        viewModel.confirmAndPinCertificate(auth.fingerprint)
                    },
                    onReject = {
                        viewModel.disconnect()
                    }
                )
            }
            is AuthState.FingerprintMismatch -> {
                binding.tvPairingBadge.text = "SECURITY BLOCKED"
                binding.tvPairingBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_disconnected))
                binding.layoutPinInput.visibility = View.GONE
                binding.layoutPairedControls.visibility = View.GONE
                CertMismatchDialog.show(requireContext(), auth.pinned, auth.presented, onResetTrustConfirmed = {
                    viewModel.resetTrust()
                })
            }
        }
    }

    private fun renderDiscoveredPeers(peers: List<DiscoveredPeer>) {
        binding.containerDiscoveredPeers.removeAllViews()
        if (peers.isEmpty()) {
            val emptyTv = TextView(requireContext()).apply {
                text = "Listening for UDP discovery beacons on port 8768..."
                textSize = 13f
                setTextColor(ContextCompat.getColor(requireContext(), R.color.secondary_text))
            }
            binding.containerDiscoveredPeers.addView(emptyTv)
            return
        }

        for (peer in peers) {
            val card = MaterialCardView(requireContext()).apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { setMargins(0, 0, 0, 8) }
                radius = 12f
                cardElevation = 1f
                setCardBackgroundColor(ContextCompat.getColor(requireContext(), R.color.card_surface))
                strokeWidth = 1
                setStrokeColor(ContextCompat.getColor(requireContext(), R.color.card_border))
            }

            val row = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(12, 12, 12, 12)
                gravity = android.view.Gravity.CENTER_VERTICAL
            }

            val info = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }

            val title = TextView(requireContext()).apply {
                text = peer.deviceName
                textSize = 14f
                setTypeface(null, android.graphics.Typeface.BOLD)
                setTextColor(ContextCompat.getColor(requireContext(), R.color.primary_text))
            }

            val sub = TextView(requireContext()).apply {
                text = "${peer.ipAddress}:${peer.port} • ID: ${peer.deviceId.take(8)}"
                textSize = 12f
                setTextColor(ContextCompat.getColor(requireContext(), R.color.secondary_text))
            }

            info.addView(title)
            info.addView(sub)

            val connectBtn = MaterialButton(requireContext(), null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                text = "Connect"
                setOnClickListener {
                    binding.etHostIp.setText(peer.ipAddress)
                    binding.etPort.setText(peer.port.toString())
                    viewModel.connect(peer.ipAddress, peer.port)
                }
            }

            row.addView(info)
            row.addView(connectBtn)
            card.addView(row)
            binding.containerDiscoveredPeers.addView(card)
        }
    }

    private fun renderSavedDevices(saved: List<SavedDevice>) {
        binding.containerSavedDevices.removeAllViews()
        if (saved.isEmpty()) {
            val emptyTv = TextView(requireContext()).apply {
                text = "No previously paired devices."
                textSize = 13f
                setTextColor(ContextCompat.getColor(requireContext(), R.color.secondary_text))
            }
            binding.containerSavedDevices.addView(emptyTv)
            return
        }

        for (device in saved) {
            val card = MaterialCardView(requireContext()).apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { setMargins(0, 0, 0, 8) }
                radius = 12f
                cardElevation = 1f
                setCardBackgroundColor(ContextCompat.getColor(requireContext(), R.color.card_surface))
                strokeWidth = 1
                setStrokeColor(ContextCompat.getColor(requireContext(), R.color.card_border))
            }

            val row = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(12, 12, 12, 12)
                gravity = android.view.Gravity.CENTER_VERTICAL
            }

            val info = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }

            val title = TextView(requireContext()).apply {
                text = device.deviceName
                textSize = 14f
                setTypeface(null, android.graphics.Typeface.BOLD)
                setTextColor(ContextCompat.getColor(requireContext(), R.color.primary_text))
            }

            val effectiveHost = if (device.host.isNotBlank()) device.host else device.recentEndpoints.firstOrNull()?.host ?: ""
            val effectivePort = if (device.port in 1..65535) device.port else device.recentEndpoints.firstOrNull()?.port ?: 8765

            val currentEp = viewModel.connectedEndpoint.value ?: ""
            val isCurrentActive = viewModel.connectionState.value == ConnectionState.CONNECTED &&
                (currentEp.startsWith("$effectiveHost:") || (effectiveHost == "127.0.0.1" && currentEp.startsWith("127.0.0.1")))

            val sub = TextView(requireContext()).apply {
                val hostDisplay = if (effectiveHost.isNotBlank()) "$effectiveHost:$effectivePort" else "No active endpoint"
                val activeBadge = if (isCurrentActive) {
                    if (currentEp.startsWith("127.0.0.1")) " • ACTIVE [USB]" else " • ACTIVE [WI-FI]"
                } else ""
                val modeBadge = when (device.connectionMode) {
                    "local_only" -> " • [Local Only]"
                    "remote_only" -> " • [Remote Relay]"
                    else -> " • [Auto]"
                }
                text = "$hostDisplay • Tier: ${device.trustTier}$activeBadge$modeBadge • ID: ${device.deviceId.take(8)}"
                textSize = 12f
                setTextColor(if (isCurrentActive) ContextCompat.getColor(requireContext(), R.color.status_connected) else ContextCompat.getColor(requireContext(), R.color.secondary_text))
            }

            info.addView(title)
            info.addView(sub)

            val modeBtn = MaterialButton(requireContext(), null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                val modeLabel = when (device.connectionMode) {
                    "local_only" -> "Local"
                    "remote_only" -> "Relay"
                    else -> "Auto"
                }
                text = modeLabel
                textSize = 11f
                setOnClickListener {
                    val modes = arrayOf("Auto (Local First)", "Local Only", "Remote Relay")
                    val modeKeys = arrayOf("auto", "local_only", "remote_only")
                    val curIdx = modeKeys.indexOf(device.connectionMode).coerceAtLeast(0)
                    AlertDialog.Builder(requireContext())
                        .setTitle("Connection Mode: ${device.deviceName}")
                        .setSingleChoiceItems(modes, curIdx) { dialog, which ->
                            viewModel.updateConnectionMode(device.deviceId, modeKeys[which])
                            dialog.dismiss()
                        }
                        .setNegativeButton("Cancel", null)
                        .show()
                }
            }

            val reconnectBtn = MaterialButton(requireContext(), null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                text = "Reconnect"
                isEnabled = effectiveHost.isNotBlank()
                setOnClickListener {
                    binding.etHostIp.setText(effectiveHost)
                    binding.etPort.setText(effectivePort.toString())
                    viewModel.connect(effectiveHost, effectivePort)
                }
            }

            row.addView(info)
            row.addView(modeBtn)
            row.addView(reconnectBtn)
            card.addView(row)
            binding.containerSavedDevices.addView(card)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
