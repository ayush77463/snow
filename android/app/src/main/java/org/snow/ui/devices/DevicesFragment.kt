package org.snow.ui.devices

import android.content.Context
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
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

class DevicesFragment : Fragment() {

    private var _binding: FragmentDevicesBinding? = null
    private val binding get() = _binding!!

    private val viewModel: DevicesViewModel by activityViewModels()

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
        observeViewModel()
    }

    private fun setupListeners() {
        binding.swipeRefresh.setOnRefreshListener {
            viewModel.refreshDevices()
            binding.swipeRefresh.isRefreshing = false
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
            val pin = binding.etPin.text?.toString() ?: ""
            if (pin.length != 6) {
                binding.tilPin.error = "PIN must be 6 digits"
                return@setOnClickListener
            }
            binding.tilPin.error = null
            viewModel.pairDevice(pin)
        }

        binding.btnUnpair.setOnClickListener {
            viewModel.unpairDevice()
            Toast.makeText(requireContext(), "Device unpaired", Toast.LENGTH_SHORT).show()
        }

        binding.btnRequestPin.setOnClickListener {
            Toast.makeText(requireContext(), "To generate a fresh PIN, click 'Generate Pairing QR' on your laptop Web Dashboard.", Toast.LENGTH_LONG).show()
        }
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
            combine(viewModel.savedDevices, viewModel.connectedEndpoint, viewModel.connectionState) { saved, _, _ ->
                saved
            }.collectLatest { saved ->
                renderSavedDevices(saved)
            }
        }
    }

    private fun renderActiveTransport(state: ConnectionState, endpoint: String?) {
        val cleanEndpoint = endpoint ?: ""
        val isUsb = cleanEndpoint.startsWith("127.0.0.1") || cleanEndpoint.startsWith("localhost")
        val isRelay = cleanEndpoint.startsWith("relay:") || cleanEndpoint.contains("tunnel") || cleanEndpoint.contains(":8770")
        when (state) {
            ConnectionState.CONNECTED -> {
                if (isRelay) {
                    binding.chipActiveTransport.text = "CONNECTED • RELAY"
                    binding.chipActiveTransport.setChipBackgroundColorResource(R.color.status_connected_soft)
                    binding.chipActiveTransport.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connected_dark))
                    binding.tvActiveTransportDetail.text = "Zero-Trust TLS 1.3 fallback tunnel active."
                } else if (isUsb) {
                    binding.chipActiveTransport.text = getString(R.string.status_usb_mode)
                    binding.chipActiveTransport.setChipBackgroundColorResource(R.color.status_connected_soft)
                    binding.chipActiveTransport.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connected_dark))
                    binding.tvActiveTransportDetail.text = getString(R.string.desc_usb_connected)
                } else {
                    binding.chipActiveTransport.text = getString(R.string.status_wifi_mode)
                    binding.chipActiveTransport.setChipBackgroundColorResource(R.color.status_connected_soft)
                    binding.chipActiveTransport.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connected_dark))
                    binding.tvActiveTransportDetail.text = getString(R.string.desc_wifi_connected, cleanEndpoint)
                }
            }
            ConnectionState.CONNECTING, ConnectionState.RECONNECTING -> {
                val label = if (state == ConnectionState.CONNECTING) "CONNECTING..." else "RECONNECTING..."
                binding.chipActiveTransport.text = label
                binding.chipActiveTransport.setChipBackgroundColorResource(R.color.status_connecting_soft)
                binding.chipActiveTransport.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connecting_dark))
                binding.tvActiveTransportDetail.text = if (cleanEndpoint.isNotBlank()) "Connecting to $cleanEndpoint..." else "Locating desktop..."
            }
            ConnectionState.DISCONNECTED -> {
                binding.chipActiveTransport.text = "DISCONNECTED"
                binding.chipActiveTransport.setChipBackgroundColorResource(R.color.status_disconnected_soft)
                binding.chipActiveTransport.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_disconnected_dark))
                binding.tvActiveTransportDetail.text = getString(R.string.desc_no_active_connection)
            }
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
                binding.tvPairingBadge.text = "PAIRING REQUIRED"
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
                    androidx.appcompat.app.AlertDialog.Builder(requireContext())
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
