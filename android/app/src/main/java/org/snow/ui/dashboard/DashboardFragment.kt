package org.snow.ui.dashboard

import android.Manifest
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.snow.R
import org.snow.capabilities.ClipboardHandler
import org.snow.databinding.FragmentDashboardBinding
import org.snow.network.ConnectionState
import org.snow.ui.MainActivity
import org.snow.ui.SnowUiRepository
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class DashboardFragment : Fragment() {

    private var _binding: FragmentDashboardBinding? = null
    private val binding get() = _binding!!

    private val viewModel: DashboardViewModel by activityViewModels()

    private var isRefreshingTelemetry = false
    private var clipListener: ClipboardManager.OnPrimaryClipChangedListener? = null

    companion object {
        private const val PREFS_NAME = SnowUiRepository.PREFS_SETTINGS
        private const val KEY_INSTANT_CLIPBOARD = SnowUiRepository.PREF_KEY_INSTANT_SYNC
        private const val KEY_AUTO_SCREENSHOT = SnowUiRepository.PREF_KEY_AUTO_SYNC_SCREENSHOTS
    }

    private val requestMediaPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { isGranted ->
            if (isGranted) {
                val prefs = requireContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                prefs.edit().putBoolean(KEY_AUTO_SCREENSHOT, true).apply()
                SnowUiRepository.getInstance(requireContext()).screenshotObserver.register()
                binding.switchAutoScreenshot.isChecked = true
                Toast.makeText(requireContext(), "Auto screenshot sync enabled ❄️", Toast.LENGTH_SHORT).show()
            } else {
                binding.switchAutoScreenshot.isChecked = false
                Toast.makeText(requireContext(), "Media permission denied for screenshot sync", Toast.LENGTH_SHORT).show()
            }
        }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentDashboardBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupListeners()
        setupInstantClipboardSync()
        observeViewModel()
        startTelemetryPolling()
    }

    private fun setupListeners() {
        binding.btnRefreshTelemetry.setOnClickListener {
            viewModel.refreshTelemetry()
        }

        binding.btnGotoDevices.setOnClickListener {
            (activity as? MainActivity)?.selectTab(R.id.nav_devices)
        }

        binding.btnBrowseFiles.setOnClickListener {
            (activity as? MainActivity)?.selectTab(R.id.nav_files)
        }

        binding.btnSendFile.setOnClickListener {
            (activity as? MainActivity)?.selectTab(R.id.nav_files)
        }

        binding.btnLockPc.setOnClickListener {
            viewModel.lockPc { success, err ->
                activity?.runOnUiThread {
                    if (success) {
                        Toast.makeText(requireContext(), "PC screen locked", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(requireContext(), "Failed to lock PC: $err", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }

        binding.btnPushClipboard.setOnClickListener {
            ClipboardHandler.isAppInForeground = true
            ClipboardHandler.isUserIntentGranted = true
            viewModel.pushCurrentClipboard { success, resultOrErr ->
                activity?.runOnUiThread {
                    if (success) {
                        Toast.makeText(requireContext(), "Pushed clipboard to PC", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(requireContext(), "Clipboard push failed: $resultOrErr", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }

        binding.btnPullClipboard.setOnClickListener {
            viewModel.pullClipboard { success, resultOrErr ->
                activity?.runOnUiThread {
                    if (success) {
                        Toast.makeText(requireContext(), resultOrErr ?: "Copied PC clipboard to phone", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(requireContext(), "Clipboard pull failed: $resultOrErr", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }

        binding.btnLaunchAppSheet.setOnClickListener {
            val sheet = AppLauncherBottomSheet { target, friendlyName ->
                viewModel.launchWindowsApp(target) { success, err ->
                    activity?.runOnUiThread {
                        if (success) {
                            Toast.makeText(requireContext(), "Launched $friendlyName on PC", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(requireContext(), "Failed to launch $friendlyName: $err", Toast.LENGTH_LONG).show()
                        }
                    }
                }
            }
            sheet.show(parentFragmentManager, AppLauncherBottomSheet.TAG)
        }

        binding.btnCancelTransfer.setOnClickListener {
            viewModel.cancelActiveTransfer()
        }

        binding.btnPushScreenshot.setOnClickListener {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.READ_MEDIA_IMAGES) != PackageManager.PERMISSION_GRANTED) {
                    requestMediaPermissionLauncher.launch(Manifest.permission.READ_MEDIA_IMAGES)
                    return@setOnClickListener
                }
            } else {
                if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
                    requestMediaPermissionLauncher.launch(Manifest.permission.READ_EXTERNAL_STORAGE)
                    return@setOnClickListener
                }
            }
            Toast.makeText(requireContext(), "Looking for recent screenshot...", Toast.LENGTH_SHORT).show()
            viewModel.pushLatestScreenshot { success, resOrErr ->
                activity?.runOnUiThread {
                    if (success) {
                        Toast.makeText(requireContext(), "Synced screenshot to PC: $resOrErr ❄️", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(requireContext(), "Screenshot sync: ${resOrErr ?: "None found"}", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    private fun setupInstantClipboardSync() {
        val prefs = requireContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val isSyncEnabled = prefs.getBoolean(KEY_INSTANT_CLIPBOARD, false)
        binding.switchInstantSync.isChecked = isSyncEnabled

        if (isSyncEnabled) {
            attachClipboardListener()
            viewModel.toggleInstantClipboardSync(true)
        }

        binding.switchInstantSync.setOnCheckedChangeListener { buttonView, isChecked ->
            if (viewModel.connectionState.value != ConnectionState.CONNECTED) {
                buttonView.isChecked = !isChecked
                Toast.makeText(requireContext(), "Connect to desktop before enabling Instant Sync", Toast.LENGTH_SHORT).show()
                return@setOnCheckedChangeListener
            }
            viewModel.toggleInstantClipboardSync(isChecked) { success ->
                activity?.runOnUiThread {
                    if (success) {
                        prefs.edit().putBoolean(KEY_INSTANT_CLIPBOARD, isChecked).apply()
                        if (isChecked) {
                            attachClipboardListener()
                            Toast.makeText(requireContext(), "Instant Clipboard Sync enabled ❄️", Toast.LENGTH_SHORT).show()
                        } else {
                            detachClipboardListener()
                            Toast.makeText(requireContext(), "Instant Clipboard Sync disabled", Toast.LENGTH_SHORT).show()
                        }
                    } else {
                        buttonView.isChecked = !isChecked
                        Toast.makeText(requireContext(), "Failed to update Instant Sync on PC", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }

        // Auto screenshot sync toggle
        val isAutoScreenshot = prefs.getBoolean(KEY_AUTO_SCREENSHOT, false)
        binding.switchAutoScreenshot.isChecked = isAutoScreenshot
        binding.switchAutoScreenshot.setOnCheckedChangeListener { buttonView, isChecked ->
            if (isChecked) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.READ_MEDIA_IMAGES) != PackageManager.PERMISSION_GRANTED) {
                        buttonView.isChecked = false
                        requestMediaPermissionLauncher.launch(Manifest.permission.READ_MEDIA_IMAGES)
                        return@setOnCheckedChangeListener
                    }
                } else {
                    if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
                        buttonView.isChecked = false
                        requestMediaPermissionLauncher.launch(Manifest.permission.READ_EXTERNAL_STORAGE)
                        return@setOnCheckedChangeListener
                    }
                }
                prefs.edit().putBoolean(KEY_AUTO_SCREENSHOT, true).apply()
                SnowUiRepository.getInstance(requireContext()).screenshotObserver.register()
                Toast.makeText(requireContext(), "Auto screenshot sync enabled ❄️", Toast.LENGTH_SHORT).show()
            } else {
                prefs.edit().putBoolean(KEY_AUTO_SCREENSHOT, false).apply()
                SnowUiRepository.getInstance(requireContext()).screenshotObserver.unregister()
                Toast.makeText(requireContext(), "Auto screenshot sync disabled", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun attachClipboardListener() {
        if (clipListener != null) return
        val cm = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val listener = ClipboardManager.OnPrimaryClipChangedListener {
            if (binding.switchInstantSync.isChecked) {
                ClipboardHandler.isAppInForeground = true
                ClipboardHandler.isUserIntentGranted = true
                val clip = cm.primaryClip
                if (clip != null && clip.itemCount > 0) {
                    val item = clip.getItemAt(0)
                    val uri = item.uri
                    val mimeType = clip.description?.let { desc ->
                        (0 until desc.mimeTypeCount).map { desc.getMimeType(it) }.firstOrNull { it.startsWith("image/") }
                    }
                    if (uri != null && mimeType != null) {
                        viewModel.pushCurrentClipboard { success, _ ->
                            if (success) {
                                activity?.runOnUiThread {
                                    Toast.makeText(requireContext(), "Synced image to PC ❄️", Toast.LENGTH_SHORT).show()
                                }
                            }
                        }
                    } else {
                        val text = item?.coerceToText(requireContext())?.toString()
                        if (!text.isNullOrEmpty() && text.toByteArray(Charsets.UTF_8).size <= 65536) {
                            if (!viewModel.isDuplicateClipboard(text)) {
                                viewModel.pushClipboard(text) { success, _ ->
                                    if (success) {
                                        activity?.runOnUiThread {
                                            Toast.makeText(requireContext(), "Synced text to PC ❄️", Toast.LENGTH_SHORT).show()
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        cm.addPrimaryClipChangedListener(listener)
        clipListener = listener
    }

    private fun detachClipboardListener() {
        clipListener?.let {
            val cm = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            cm?.removePrimaryClipChangedListener(it)
            clipListener = null
        }
    }

    override fun onResume() {
        super.onResume()
    }

    private fun startTelemetryPolling() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                while (isActive) {
                    if (viewModel.connectionState.value == ConnectionState.CONNECTED && !isRefreshingTelemetry) {
                        isRefreshingTelemetry = true
                        viewModel.refreshTelemetry {
                            isRefreshingTelemetry = false
                        }
                    }
                    delay(30000L)
                }
            }
        }
    }

    private fun observeViewModel() {
        viewLifecycleOwner.lifecycleScope.launch {
            combine(viewModel.connectionState, viewModel.connectedEndpoint) { state, endpoint ->
                Pair(state, endpoint)
            }.collectLatest { (state, endpoint) ->
                renderConnectionState(state, endpoint)
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.phoneTelemetry.collectLatest { phone ->
                if (phone.isAvailable) {
                    binding.tvPhoneBattery.text = "${phone.batteryPercent}%"
                    binding.tvPhoneCharging.text = if (phone.isCharging) "Charging" else "Discharging"
                    binding.tvBatteryTemp.text = if (phone.temperatureCelsius != null) {
                        String.format(Locale.getDefault(), "%.1f°C", phone.temperatureCelsius)
                    } else {
                        "N/A"
                    }
                } else {
                    binding.tvPhoneBattery.text = "--%"
                    binding.tvPhoneCharging.text = "Unavailable"
                }
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.pcTelemetry.collectLatest { pc ->
                if (pc.isAvailable && pc.isConnected) {
                    binding.tvPcBattery.text = if (pc.batteryPercent != null) "${pc.batteryPercent}%" else "AC Power"
                    binding.tvPcCharging.text = if (pc.isCharging == true) "Charging" else if (pc.batteryPercent != null) "Battery" else "Plugged in"
                    if (pc.hostname != null) {
                        val endpoint = viewModel.connectedEndpoint.value ?: ""
                        val transportSuffix = if (endpoint.startsWith("127.0.0.1") || endpoint.startsWith("localhost")) " • USB" else " • Wi-Fi"
                        binding.tvHeroPeerName.text = "${pc.hostname} (${pc.os ?: "Windows"})$transportSuffix"
                    }
                    binding.tvPcCpu.text = if (pc.cpuPercent != null) String.format(Locale.getDefault(), "%.1f%%", pc.cpuPercent) else "0.0%"
                    binding.tvPcRam.text = if (pc.memoryPercent != null) String.format(Locale.getDefault(), "%.1f%%", pc.memoryPercent) else "0.0%"
                    val timeStr = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(pc.lastUpdated))
                    binding.tvTelemetryUpdated.text = "Last updated: $timeStr"
                } else {
                    binding.tvPcBattery.text = "--%"
                    binding.tvPcCharging.text = "Disconnected"
                    binding.tvPcCpu.text = "--%"
                    binding.tvPcRam.text = "--%"
                    binding.tvTelemetryUpdated.text = "Last updated: Disconnected"
                }
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.activeTransfer.collectLatest { transfer ->
                if (transfer != null && (transfer.status == "IN_PROGRESS" || transfer.status == "STARTING")) {
                    binding.cardActiveTransfer.visibility = View.VISIBLE
                    binding.tvTransferFilename.text = "${transfer.direction}: ${transfer.fileName}"
                    binding.tvTransferStatus.text = "${transfer.bytesTransferred} / ${transfer.totalBytes} bytes (${transfer.status})"
                    if (transfer.totalBytes > 0) {
                        val pct = ((transfer.bytesTransferred * 100) / transfer.totalBytes).toInt()
                        binding.pbTransfer.isIndeterminate = false
                        binding.pbTransfer.progress = pct
                    } else {
                        binding.pbTransfer.isIndeterminate = true
                    }
                } else {
                    binding.cardActiveTransfer.visibility = View.GONE
                }
            }
        }
    }

    private fun renderConnectionState(state: ConnectionState, endpoint: String?) {
        val cleanEndpoint = endpoint ?: ""
        val isUsb = cleanEndpoint.startsWith("127.0.0.1") || cleanEndpoint.startsWith("localhost")
        when (state) {
            ConnectionState.CONNECTED -> {
                binding.tvHeroStatusPill.text = if (isUsb) "CONNECTED • USB" else if (cleanEndpoint.isNotBlank()) "CONNECTED • WI-FI" else "CONNECTED"
                binding.tvHeroStatusPill.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connected))
                binding.btnGotoDevices.visibility = View.GONE
            }
            ConnectionState.CONNECTING -> {
                binding.tvHeroStatusPill.text = "CONNECTING..."
                binding.tvHeroStatusPill.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connecting))
                binding.btnGotoDevices.visibility = View.VISIBLE
            }
            ConnectionState.RECONNECTING -> {
                binding.tvHeroStatusPill.text = "RECONNECTING..."
                binding.tvHeroStatusPill.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_reconnecting))
                binding.btnGotoDevices.visibility = View.VISIBLE
            }
            ConnectionState.DISCONNECTED -> {
                binding.tvHeroStatusPill.text = "DISCONNECTED"
                binding.tvHeroStatusPill.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_disconnected))
                binding.tvHeroPeerName.text = getString(R.string.desc_no_connected_device)
                binding.btnGotoDevices.visibility = View.VISIBLE
            }
        }
    }

    override fun onDestroyView() {
        detachClipboardListener()
        super.onDestroyView()
        _binding = null
    }
}
