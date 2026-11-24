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
        setupManualConnect()
        setupAppUpdate()
        setupQuickSettingsTileControl()
        setupSyncPreferences()
        setupAdvancedAccordion()
        observeLogs()
    }

    override fun onResume() {
        super.onResume()
        refreshNotificationAccessStatus()
        refreshStorageAccessStatus()
        refreshPermissionsChecklist()
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
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    showRestrictedSettingsGuideDialog()
                } else {
                    openNotificationListenerSettings()
                }
            }
        }
    }

    fun showRestrictedSettingsGuideDialog() {
        val ctx = context ?: return
        com.google.android.material.dialog.MaterialAlertDialogBuilder(ctx)
            .setTitle("Notification Access on Android 14+")
            .setMessage(
                "On Android 13 and 14+, sideloaded applications require allowing restricted settings before notification access can be toggled:\n\n" +
                "1. Tap 'Open App Info' below.\n" +
                "2. Tap the 3-dot overflow menu (⋮) in the top-right corner.\n" +
                "3. Select 'Allow restricted settings' and confirm with biometric/PIN.\n" +
                "4. Return to SNOW and tap 'Open Notification Settings' to toggle SNOW on."
            )
            .setPositiveButton("Open App Info") { _, _ ->
                openAppDetailsSettings()
            }
            .setNeutralButton("Open Notification Settings") { _, _ ->
                openNotificationListenerSettings()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    fun openAppDetailsSettings(): Intent {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.parse("package:${requireContext().packageName}")
        }
        try {
            startActivity(intent)
        } catch (e: Exception) {
            Toast.makeText(context, "Unable to open App Info: ${e.message}", Toast.LENGTH_SHORT).show()
        }
        return intent
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

    fun refreshPermissionsChecklist() {
        if (_binding == null) return
        val ctx = context ?: return

        val notifGranted = isNotificationServiceEnabled()
        val storageGranted = isAllFilesAccessGranted()
        val cameraGranted = ContextCompat.checkSelfPermission(ctx, android.Manifest.permission.CAMERA) == android.content.pm.PackageManager.PERMISSION_GRANTED
        val powerMgr = ctx.getSystemService(Context.POWER_SERVICE) as? android.os.PowerManager
        val batteryIgnored = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            powerMgr?.isIgnoringBatteryOptimizations(ctx.packageName) == true
        } else true

        if (batteryIgnored) {
            binding.tvBatteryOptimizationStatus.text = "Status: Granted (Unrestricted)"
            binding.tvBatteryOptimizationStatus.setTextColor(ContextCompat.getColor(ctx, R.color.status_connected))
            binding.btnGrantBatteryAccess.text = "Granted"
        } else {
            binding.tvBatteryOptimizationStatus.text = "Status: Standard (Optimized)"
            binding.tvBatteryOptimizationStatus.setTextColor(ContextCompat.getColor(ctx, R.color.secondary_text))
            binding.btnGrantBatteryAccess.text = "Allow"
        }

        val sb = StringBuilder()
        sb.append("• Background Connectivity: Active (Foreground Service)\n")
        sb.append("• Notification Sync: ").append(if (notifGranted) "✓ Active (Granted)" else "○ Optional (Disabled)").append("\n")
        sb.append("• All Files Access: ").append(if (storageGranted) "✓ Granted (Shared Storage)" else "○ SAF Fallback Mode").append("\n")
        sb.append("• Camera Capability: ").append(if (cameraGranted) "✓ Granted" else "○ Optional (Tap Camera in Dashboard)").append("\n")
        sb.append("• Battery Optimization: ").append(if (batteryIgnored) "✓ Unrestricted" else "○ Standard (Optimized)")

        binding.tvPermissionsChecklist.text = sb.toString()
    }

    private fun setupSyncPreferences() {
        val prefs = requireContext().getSharedPreferences(org.snow.ui.SnowUiRepository.PREFS_SETTINGS, Context.MODE_PRIVATE)
        binding.swAutoConnectNearby.isChecked = prefs.getBoolean(org.snow.ui.SnowUiRepository.PREF_KEY_AUTO_CONNECT_ENABLED, true)
        binding.swAutoSyncScreenshots.isChecked = prefs.getBoolean(org.snow.ui.SnowUiRepository.PREF_KEY_AUTO_SYNC_SCREENSHOTS, true)

        binding.swAutoConnectNearby.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean(org.snow.ui.SnowUiRepository.PREF_KEY_AUTO_CONNECT_ENABLED, isChecked).apply()
        }
        binding.swAutoSyncScreenshots.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean(org.snow.ui.SnowUiRepository.PREF_KEY_AUTO_SYNC_SCREENSHOTS, isChecked).apply()
        }

        binding.btnGrantBatteryAccess.setOnClickListener {
            openBatteryOptimizationSettings()
        }
    }

    private fun setupAdvancedAccordion() {
        binding.headerAdvancedDiagnostics.setOnClickListener {
            val isGone = binding.layoutAdvancedDiagnosticsBody.visibility == View.GONE
            binding.layoutAdvancedDiagnosticsBody.visibility = if (isGone) View.VISIBLE else View.GONE
            binding.tvToggleAdvancedDiagnostics.text = if (isGone) "▲ Collapse" else "▼ Expand"
        }
    }

    private fun openBatteryOptimizationSettings() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                data = Uri.parse("package:${requireContext().packageName}")
            }
            try {
                startActivity(intent)
            } catch (_: Exception) {
                try {
                    startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                } catch (_: Exception) {}
            }
        }
    }

    private fun setupQuickSettingsTileControl() {
        binding.btnAddQsTile.setOnClickListener {
            requestAddQuickSettingsTile()
        }
    }

    private fun requestAddQuickSettingsTile() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val statusBarManager = requireContext().getSystemService(android.app.StatusBarManager::class.java)
            val componentName = android.content.ComponentName(
                requireContext(),
                org.snow.service.AutoConnectTileService::class.java
            )
            val executor = ContextCompat.getMainExecutor(requireContext())
            statusBarManager?.requestAddTileService(
                componentName,
                "SNOW Connect",
                android.graphics.drawable.Icon.createWithResource(requireContext(), R.drawable.ic_qs_snow),
                executor
            ) { resultCode ->
                val msg = when (resultCode) {
                    android.app.StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ADDED -> "SNOW Tile added to Quick Settings!"
                    android.app.StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ALREADY_ADDED -> "SNOW Tile is already in Quick Settings."
                    else -> "Tile request dismissed."
                }
                Toast.makeText(requireContext(), msg, Toast.LENGTH_SHORT).show()
            }
        } else {
            Toast.makeText(
                requireContext(),
                "Swipe down twice from top of screen, tap Edit (pencil), and drag SNOW Connect tile into your panel.",
                Toast.LENGTH_LONG
            ).show()
        }
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
        val devName = if (id.deviceName.isNotBlank()) id.deviceName else Build.MODEL
        binding.tvDeviceName.text = "Name: $devName"
        binding.tvDeviceId.text = "ID: ${id.deviceId}"

        binding.headerDeviceIdentity.setOnClickListener {
            val isGone = binding.layoutDeviceIdentityBody.visibility == View.GONE
            binding.layoutDeviceIdentityBody.visibility = if (isGone) View.VISIBLE else View.GONE
            binding.tvToggleDeviceIdentity.text = if (isGone) "▲ Collapse" else "▼ Expand"
        }
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
            binding.tvDiagnosticsLog.text = "No diagnostic logs yet."
            Toast.makeText(requireContext(), "Logs cleared", Toast.LENGTH_SHORT).show()
        }

        binding.btnCopyDiagnostics.setOnClickListener {
            val logs = binding.tvDiagnosticsLog.text.toString()
            val redacted = logs.replace(Regex("(?i)(token|secret|ticket|key)\\s*[=:]\\s*['\"]?[a-zA-Z0-9_-]{12,}['\"]?"), "$1=[REDACTED]")
            val clipboard = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
            val clip = android.content.ClipData.newPlainText("SNOW Diagnostics", redacted)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(requireContext(), "Diagnostic logs copied to clipboard (tokens redacted)", Toast.LENGTH_SHORT).show()
        }

        binding.headerDiagnostics.setOnClickListener {
            val isGone = binding.layoutDiagnosticsBody.visibility == View.GONE
            binding.layoutDiagnosticsBody.visibility = if (isGone) View.VISIBLE else View.GONE
            binding.tvToggleDiagnostics.text = if (isGone) "▲ Collapse" else "▼ Expand"
        }
    }

    private fun setupManualConnect() {
        binding.btnSettingsManualConnect.setOnClickListener {
            val host = binding.etSettingsManualHost.text?.toString()?.trim() ?: ""
            val portStr = binding.etSettingsManualPort.text?.toString()?.trim() ?: ""
            val port = portStr.toIntOrNull() ?: 8765

            if (host.isBlank()) {
                Toast.makeText(requireContext(), "Please enter an IP address or hostname", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            Toast.makeText(requireContext(), "Connecting to $host:$port...", Toast.LENGTH_SHORT).show()
            org.snow.ui.SnowUiRepository.getInstance(requireContext()).connect(host, port)
        }
    }

    private fun setupAppUpdate() {
        val repo = org.snow.ui.SnowUiRepository.getInstance(requireContext())
        binding.btnCheckAppUpdate.setOnClickListener {
            binding.tvAppUpdateStatus.text = "Status: Checking paired desktop..."
            binding.tvAppUpdateStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.secondary_text))

            repo.checkAppUpdate { info ->
                activity?.runOnUiThread {
                    if (_binding == null) return@runOnUiThread
                    if (info == null) {
                        binding.tvAppUpdateStatus.text = "Status: Could not reach desktop or not connected"
                        binding.tvAppUpdateStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_disconnected))
                        Toast.makeText(requireContext(), "Could not retrieve update information from desktop", Toast.LENGTH_SHORT).show()
                        return@runOnUiThread
                    }

                    val currentCode = org.snow.BuildConfig.VERSION_CODE
                    val currentName = org.snow.BuildConfig.VERSION_NAME
                    if (!info.available || info.versionCode <= currentCode) {
                        binding.tvAppUpdateStatus.text = "Status: Up to date (v$currentName, build $currentCode)"
                        binding.tvAppUpdateStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connected))
                        Toast.makeText(requireContext(), "SNOW is up to date (v$currentName)", Toast.LENGTH_SHORT).show()
                    } else {
                        binding.tvAppUpdateStatus.text = "Status: Update available (v${info.versionName}, build ${info.versionCode})"
                        binding.tvAppUpdateStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.primary_blue))

                        AlertDialog.Builder(requireContext())
                            .setTitle("Direct App Update Available")
                            .setMessage("Version ${info.versionName} (Build ${info.versionCode}) is staged on your paired PC.\n\nSize: ${info.sizeBytes / 1024} KB\nSHA-256: ${info.sha256.take(16)}...\n\nDownload and install now?")
                            .setPositiveButton("Download & Install") { _, _ ->
                                binding.tvAppUpdateStatus.text = "Status: Downloading update (0%)..."
                                repo.downloadAndInstallUpdate(
                                    updateInfo = info,
                                    onProgress = { pct ->
                                        activity?.runOnUiThread {
                                            if (_binding != null) {
                                                binding.tvAppUpdateStatus.text = "Status: Downloading update ($pct%)..."
                                            }
                                        }
                                    },
                                    onComplete = { success, errorMsg ->
                                        activity?.runOnUiThread {
                                            if (_binding != null) {
                                                if (success) {
                                                    binding.tvAppUpdateStatus.text = "Status: Installer launched"
                                                    binding.tvAppUpdateStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connected))
                                                } else {
                                                    binding.tvAppUpdateStatus.text = "Status: Update failed: $errorMsg"
                                                    binding.tvAppUpdateStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_disconnected))
                                                    Toast.makeText(requireContext(), "Update failed: $errorMsg", Toast.LENGTH_LONG).show()
                                                }
                                            }
                                        }
                                    }
                                )
                            }
                            .setNegativeButton("Later", null)
                            .show()
                    }
                }
            }
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
