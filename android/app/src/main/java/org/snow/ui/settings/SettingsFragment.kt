package org.snow.ui.settings

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Bundle
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
        setupTrustControls()
        setupDiagnostics()
        observeLogs()
    }

    override fun onResume() {
        super.onResume()
        refreshNotificationAccessStatus()
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
