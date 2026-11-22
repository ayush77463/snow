package org.snow.ui.settings

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.Lifecycle
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.snow.R
import org.snow.databinding.FragmentSettingsBinding
import org.snow.ui.UiLogEntry

class SettingsFragment : Fragment() {

    private var _binding: FragmentSettingsBinding? = null
    private val binding get() = _binding!!

    private val viewModel: SettingsViewModel by activityViewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentSettingsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupThemeSelection()
        setupDeviceIdentity()
        setupNotificationSyncAccess()
        refreshStorageAccessStatus()
        setupRemoteRelayControls()
        setupPeerHostControls()
        setupTrustControls()
        setupDiagnostics()
        observeLogs()
    }

    override fun onResume() {
        super.onResume()
        refreshNotificationAccessStatus()
        refreshStorageAccessStatus()
        updatePeerHostUi()
    }

    fun isAllFilesAccessGranted(): Boolean {
        return context?.let { isAllFilesAccessGranted(it) } ?: false
    }

    fun refreshStorageAccessStatus() {
        if (_binding == null) return
        val granted = isAllFilesAccessGranted()
        if (granted) {
            binding.tvStorageAccessStatus.text = "Status: Granted — Shared Storage"
            binding.tvStorageAccessStatus.setTextColor(
                ContextCompat.getColor(requireContext(), R.color.status_connected)
            )
            binding.btnGrantStorageAccess.text = "Manage All Files Access"
            binding.btnGrantStorageAccess.setOnClickListener {
                openManageAllFilesAccessSettings()
            }
        } else {
            binding.tvStorageAccessStatus.text = "Status: Not Granted — SAF Folder Only"
            binding.tvStorageAccessStatus.setTextColor(
                ContextCompat.getColor(requireContext(), R.color.secondary_text)
            )
            binding.btnGrantStorageAccess.text = "Grant All Files Access"
            binding.btnGrantStorageAccess.setOnClickListener {
                openManageAllFilesAccessSettings()
            }
        }
    }

    fun openManageAllFilesAccessSettings(): Intent {
        val intent = createManageAllFilesAccessIntent(requireContext())
        try {
            startActivity(intent)
        } catch (e: Exception) {
            // Fallback to generic storage settings if package URI is unresolvable on some OEMs
            val fallback = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
            try {
                startActivity(fallback)
            } catch (fe: Exception) {
                Toast.makeText(
                    context,
                    "Unable to open All Files Access settings: ${fe.message}",
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
        return intent
    }

    fun isNotificationServiceEnabled(): Boolean {
        return context?.let { isNotificationServiceEnabled(it) } ?: false
    }

    fun refreshNotificationAccessStatus() {
        if (_binding == null) return
        val enabled = isNotificationServiceEnabled()
        if (enabled) {
            binding.tvNotificationAccessStatus.text = "Status: Enabled"
            binding.tvNotificationAccessStatus.setTextColor(
                ContextCompat.getColor(requireContext(), R.color.status_connected)
            )
            binding.btnGrantNotificationAccess.text = "Notification Access Granted"
            binding.btnGrantNotificationAccess.setOnClickListener {
                openNotificationListenerSettings()
            }
        } else {
            binding.tvNotificationAccessStatus.text = "Status: Not Enabled"
            binding.tvNotificationAccessStatus.setTextColor(
                ContextCompat.getColor(requireContext(), R.color.secondary_text)
            )
            binding.btnGrantNotificationAccess.text = "Grant Notification Access"
            binding.btnGrantNotificationAccess.setOnClickListener {
                openNotificationListenerSettings()
            }
        }
    }

    fun openNotificationListenerSettings(): Intent {
        val intent = createNotificationListenerSettingsIntent()
        try {
            startActivity(intent)
        } catch (e: Exception) {
            Toast.makeText(
                context,
                "Unable to open notification listener settings: ${e.message}",
                Toast.LENGTH_SHORT
            ).show()
        }
        return intent
    }

    private fun setupNotificationSyncAccess() {
        refreshNotificationAccessStatus()
    }

    companion object {
        fun createNotificationListenerSettingsIntent(): Intent {
            return Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
        }

        fun createManageAllFilesAccessIntent(ctx: Context): Intent {
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Intent(
                    Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                    Uri.parse("package:${ctx.packageName}")
                )
            } else {
                Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
            }
        }

        fun isAllFilesAccessGranted(ctx: Context): Boolean {
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Environment.isExternalStorageManager()
            } else {
                false
            }
        }

        fun isNotificationServiceEnabled(ctx: Context): Boolean {
            val packageName = ctx.packageName
            val flat = Settings.Secure.getString(
                ctx.contentResolver,
                "enabled_notification_listeners"
            )
            if (!flat.isNullOrEmpty()) {
                val names = flat.split(":")
                for (name in names) {
                    val cn = ComponentName.unflattenFromString(name)
                    if (cn != null && cn.packageName == packageName) {
                        return true
                    }
                }
            }
            return false
        }
    }

    private fun setupThemeSelection() {
        val current = viewModel.getSavedThemeMode()
        when (current) {
            SettingsViewModel.THEME_LIGHT -> binding.rbThemeLight.isChecked = true
            SettingsViewModel.THEME_DARK -> binding.rbThemeDark.isChecked = true
            else -> binding.rbThemeSystem.isChecked = true
        }

        binding.rgTheme.setOnCheckedChangeListener { _, checkedId ->
            val mode = when (checkedId) {
                R.id.rb_theme_light -> SettingsViewModel.THEME_LIGHT
                R.id.rb_theme_dark -> SettingsViewModel.THEME_DARK
                else -> SettingsViewModel.THEME_SYSTEM
            }
            viewModel.setThemeMode(mode)
        }
    }

    private fun setupDeviceIdentity() {
        val id = viewModel.deviceIdentity
        binding.tvDeviceName.text = "Name: ${id.deviceName}"
        binding.tvDeviceId.text = "ID: ${id.deviceId}"
    }

    private fun setupTrustControls() {
        binding.btnUnpairSettings.setOnClickListener {
            AlertDialog.Builder(requireContext())
                .setTitle("Unpair Desktop")
                .setMessage("Are you sure you want to disconnect and clear the active pairing token?")
                .setPositiveButton("Unpair") { dialog, _ ->
                    dialog.dismiss()
                    viewModel.unpairDevice()
                    Toast.makeText(requireContext(), "Device unpaired", Toast.LENGTH_SHORT).show()
                }
                .setNegativeButton("Cancel", null)
                .show()
        }

        binding.btnResetTrustSettings.setOnClickListener {
            AlertDialog.Builder(requireContext())
                .setTitle("Reset Cryptographic Trust")
                .setMessage("This will clear all pinned TLS certificates, security fingerprints, and tokens. You will need to re-pair with the desktop using a fresh PIN.")
                .setPositiveButton("Reset Trust") { dialog, _ ->
                    dialog.dismiss()
                    viewModel.resetTrust()
                    Toast.makeText(requireContext(), "Trust reset complete", Toast.LENGTH_SHORT).show()
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    private fun setupRemoteRelayControls() {
        val enabled = viewModel.isRemoteRelayEnabled()
        val endpoint = viewModel.getRemoteRelayEndpoint()

        binding.swRemoteRelay.isChecked = enabled
        binding.etRemoteRelayEndpoint.setText(endpoint)
        updateRemoteRelayStatusText(enabled, endpoint)

        binding.swRemoteRelay.setOnCheckedChangeListener { _, isChecked ->
            val curEndpoint = binding.etRemoteRelayEndpoint.text?.toString()?.trim() ?: ""
            updateRemoteRelayStatusText(isChecked, curEndpoint)
        }

        binding.btnSaveRemoteRelay.setOnClickListener {
            val isChecked = binding.swRemoteRelay.isChecked
            val curEndpoint = binding.etRemoteRelayEndpoint.text?.toString()?.trim() ?: ""

            if (isChecked) {
                if (curEndpoint.isBlank()) {
                    Toast.makeText(requireContext(), "Please enter a valid relay endpoint URL (e.g. wss://example.com:8770/v1/tunnel)", Toast.LENGTH_LONG).show()
                    return@setOnClickListener
                }
                if (!curEndpoint.startsWith("wss://") && !curEndpoint.startsWith("ws://")) {
                    Toast.makeText(requireContext(), "Relay endpoint must start with wss:// or ws://", Toast.LENGTH_LONG).show()
                    return@setOnClickListener
                }
            }

            viewModel.saveRemoteRelayConfig(isChecked, curEndpoint)
            updateRemoteRelayStatusText(isChecked, curEndpoint)
            Toast.makeText(requireContext(), "Relay configuration updated", Toast.LENGTH_SHORT).show()
        }
    }

    private var isProgrammaticSwitchUpdate = false

    private fun setupPeerHostControls() {
        val enabled = viewModel.isPeerHostEnabled()
        isProgrammaticSwitchUpdate = true
        binding.swPeerHostMode.isChecked = enabled
        isProgrammaticSwitchUpdate = false
        updatePeerHostUi()

        binding.swPeerHostMode.setOnCheckedChangeListener { _, isChecked ->
            if (isProgrammaticSwitchUpdate) return@setOnCheckedChangeListener
            if (isChecked) {
                viewModel.startPeerHost()
            } else {
                viewModel.stopPeerHost()
            }
            updatePeerHostUi()
        }

        binding.btnGeneratePeerPin.setOnClickListener {
            if (!viewModel.isPeerHostActive()) {
                Toast.makeText(requireContext(), "Enable Host Mode first to generate a pairing PIN", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val pin = viewModel.generatePeerHostPin()
            if (pin != null) {
                binding.tvPeerHostPin.text = "PIN: $pin"
                binding.tvPeerHostPinExpiry.text = "Validity: 5 minutes"
                binding.tvPeerHostPin.visibility = View.VISIBLE
                binding.tvPeerHostPinExpiry.visibility = View.VISIBLE
                Toast.makeText(requireContext(), "Generated temporary 6-digit PIN", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnStopPeerHost.setOnClickListener {
            isProgrammaticSwitchUpdate = true
            binding.swPeerHostMode.isChecked = false
            isProgrammaticSwitchUpdate = false
            viewModel.stopPeerHost()
            updatePeerHostUi()
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.peerHostState.collect { state ->
                    updatePeerHostStateUi(state)
                }
            }
        }
    }

    private fun updatePeerHostStateUi(state: org.snow.network.PeerHostState) {
        if (_binding == null) return
        val enabled = viewModel.isPeerHostEnabled()
        val desiredChecked = state.isActive || enabled
        if (binding.swPeerHostMode.isChecked != desiredChecked) {
            isProgrammaticSwitchUpdate = true
            binding.swPeerHostMode.isChecked = desiredChecked
            isProgrammaticSwitchUpdate = false
        }
        if (state.isActive) {
            binding.tvPeerHostStatus.text = "Status: ACTIVE (TLS/WSS)"
            binding.tvPeerHostStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connected))
            binding.tvPeerHostEndpoint.text = "Endpoint: ${state.ipAddress}:${state.port}"
            binding.tvPeerHostConnections.text = "Connected Peers: ${state.peerCount}"
            binding.btnStopPeerHost.visibility = View.VISIBLE
            binding.btnGeneratePeerPin.isEnabled = true
        } else if (enabled) {
            binding.tvPeerHostStatus.text = "Status: STARTING"
            binding.tvPeerHostStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.secondary_text))
            binding.tvPeerHostEndpoint.text = "Endpoint: Starting on port ${state.port}..."
            binding.tvPeerHostConnections.text = "Connected Peers: 0"
            binding.btnStopPeerHost.visibility = View.VISIBLE
            binding.btnGeneratePeerPin.isEnabled = false
        } else {
            binding.tvPeerHostStatus.text = "Status: OFF"
            binding.tvPeerHostStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.secondary_text))
            binding.tvPeerHostEndpoint.text = "Endpoint: --"
            binding.tvPeerHostConnections.text = "Connected Peers: 0"
            binding.btnStopPeerHost.visibility = View.GONE
            binding.btnGeneratePeerPin.isEnabled = false
            binding.tvPeerHostPin.visibility = View.GONE
            binding.tvPeerHostPinExpiry.visibility = View.GONE
        }
        if (state.pairingPin != null) {
            binding.tvPeerHostPin.text = "PIN: ${state.pairingPin}"
            binding.tvPeerHostPinExpiry.text = "Validity: 5 minutes"
            binding.tvPeerHostPin.visibility = View.VISIBLE
            binding.tvPeerHostPinExpiry.visibility = View.VISIBLE
        }
    }

    private fun updatePeerHostUi() {
        if (_binding == null) return
        updatePeerHostStateUi(viewModel.peerHostState.value)
    }

    private fun updateRemoteRelayStatusText(enabled: Boolean, endpoint: String) {
        if (_binding == null) return
        if (enabled) {
            val displayEp = if (endpoint.isNotBlank()) endpoint else "No endpoint specified"
            binding.tvRemoteRelayStatus.text = "Status: Enabled ($displayEp)"
            binding.tvRemoteRelayStatus.setTextColor(
                ContextCompat.getColor(requireContext(), R.color.status_connected)
            )
        } else {
            binding.tvRemoteRelayStatus.text = "Status: Disabled (Local-Only Mode)"
            binding.tvRemoteRelayStatus.setTextColor(
                ContextCompat.getColor(requireContext(), R.color.secondary_text)
            )
        }
    }

    private fun setupDiagnostics() {
        binding.btnClearDiagnostics.setOnClickListener {
            viewModel.clearLogs()
            Toast.makeText(requireContext(), "Logs cleared", Toast.LENGTH_SHORT).show()
        }
    }

    private fun observeLogs() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.logs.collectLatest { logEntries ->
                renderLogs(logEntries)
            }
        }
    }

    private fun renderLogs(logEntries: List<UiLogEntry>) {
        if (logEntries.isEmpty()) {
            binding.tvDiagnosticsLog.text = "No diagnostic logs yet."
            return
        }

        val sb = StringBuilder()
        for (e in logEntries) {
            sb.append("[${e.timestamp}] [${e.level}] ${e.tag}: ${e.message}\n")
        }
        binding.tvDiagnosticsLog.text = sb.toString()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
