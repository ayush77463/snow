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
import org.snow.capabilities.CameraCaptureHandler
import org.snow.capabilities.ClipboardHandler
import org.snow.capabilities.LiveScreenStreamHandler
import org.snow.capabilities.ScreenCaptureHandler
import org.snow.databinding.FragmentDashboardBinding
import org.snow.network.ConnectionState
import org.snow.ui.MainActivity
import org.snow.ui.PendingApprovalItem
import org.snow.ui.SnowUiRepository
import androidx.core.content.FileProvider
import java.io.File
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

    private val mediaProjectionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == android.app.Activity.RESULT_OK && result.data != null) {
                Toast.makeText(requireContext(), "Screen sharing consent granted 🛡️ Starting stream...", Toast.LENGTH_SHORT).show()
                org.snow.service.SnowForegroundService.startScreenShare(
                    requireContext(),
                    result.resultCode,
                    result.data!!
                )
            } else {
                Toast.makeText(requireContext(), "Screen capture consent cancelled", Toast.LENGTH_SHORT).show()
            }
        }

    private var pendingCameraCaptureFile: File? = null

    private val takePhotoLauncher =
        registerForActivityResult(ActivityResultContracts.TakePicture()) { success ->
            val capturedFile = pendingCameraCaptureFile
            if (success && capturedFile != null && capturedFile.exists() && capturedFile.length() > 0) {
                CameraCaptureHandler.stagedPhotoFile = capturedFile
                CameraCaptureHandler.isUserInteractionActive = true
                Toast.makeText(requireContext(), "Photo captured! Delivering to PC 📸", Toast.LENGTH_SHORT).show()
                viewModel.uploadCameraPhoto { uploadSuccess, resOrErr ->
                    activity?.runOnUiThread {
                        if (uploadSuccess) {
                            Toast.makeText(requireContext(), "Photo delivered to PC: $resOrErr ✅", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(requireContext(), "Photo delivery failed: $resOrErr", Toast.LENGTH_LONG).show()
                        }
                    }
                }
            } else {
                CameraCaptureHandler.isUserInteractionActive = false
                capturedFile?.delete()
                pendingCameraCaptureFile = null
                viewModel.dismissCameraDelivery()
                Toast.makeText(requireContext(), "Photo capture cancelled", Toast.LENGTH_SHORT).show()
            }
        }

    private val requestCameraPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { isGranted ->
            if (isGranted) {
                launchCameraCapture()
            } else {
                Toast.makeText(requireContext(), "Camera permission required to capture photos", Toast.LENGTH_SHORT).show()
            }
        }

    private fun launchCameraCapture() {
        viewModel.setCameraCapturing()
        val cacheDir = File(requireContext().cacheDir, "camera_captures").apply { mkdirs() }
        val timeStamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val file = File(cacheDir, "manual_photo_${timeStamp}.jpg")
        pendingCameraCaptureFile = file
        val uri = FileProvider.getUriForFile(
            requireContext(),
            "${requireContext().packageName}.fileprovider",
            file
        )
        takePhotoLauncher.launch(uri)
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
        binding.swipeRefresh.setOnRefreshListener {
            viewModel.refreshTelemetry()
            binding.swipeRefresh.isRefreshing = false
        }

        binding.btnRefreshTelemetry.setOnClickListener {
            viewModel.refreshTelemetry()
        }

        binding.btnHeroLockPc.setOnClickListener {
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

        binding.btnHeroSendFiles.setOnClickListener {
            (activity as? MainActivity)?.selectTab(R.id.nav_files)
        }

        binding.btnGotoDevices.setOnClickListener {
            (activity as? MainActivity)?.selectTab(R.id.nav_devices)
        }

        binding.btnOpenTerminal.setOnClickListener {
            val dialog = org.snow.ui.terminal.TerminalBottomSheetDialog()
            dialog.show(parentFragmentManager, org.snow.ui.terminal.TerminalBottomSheetDialog.TAG)
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

        binding.btnScreenConsent.setOnClickListener {
            val currentState = viewModel.screenShareState.value
            if (currentState == LiveScreenStreamHandler.StreamState.STREAMING || currentState == LiveScreenStreamHandler.StreamState.STARTING) {
                viewModel.stopScreenShare()
                Toast.makeText(requireContext(), "Stopping screen share...", Toast.LENGTH_SHORT).show()
            } else {
                val projectionManager =
                    requireContext().getSystemService(Context.MEDIA_PROJECTION_SERVICE) as? android.media.projection.MediaProjectionManager
                if (projectionManager != null) {
                    mediaProjectionLauncher.launch(projectionManager.createScreenCaptureIntent())
                } else {
                    Toast.makeText(requireContext(), "MediaProjection service unavailable", Toast.LENGTH_SHORT).show()
                }
            }
        }

        binding.btnStopScreenSharing.setOnClickListener {
            viewModel.stopScreenShare()
            Toast.makeText(requireContext(), "Stopping screen share...", Toast.LENGTH_SHORT).show()
        }

        binding.btnCameraCapture.setOnClickListener {
            if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                launchCameraCapture()
            } else {
                requestCameraPermissionLauncher.launch(Manifest.permission.CAMERA)
            }
        }

        binding.btnRetryCameraUpload.setOnClickListener {
            viewModel.retryCameraUpload { success, resOrErr ->
                activity?.runOnUiThread {
                    if (success) {
                        Toast.makeText(requireContext(), "Photo delivered to PC: $resOrErr ✅", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(requireContext(), "Retry failed: $resOrErr", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }

        binding.btnDismissCameraDelivery.setOnClickListener {
            viewModel.dismissCameraDelivery()
        }

        binding.btnRefreshApprovals.setOnClickListener {
            refreshPendingApprovals()
        }

        binding.btnRefreshClipboardBuffer.setOnClickListener {
            viewModel.refreshClipboardBuffer { success, msg ->
                activity?.runOnUiThread {
                    if (success) {
                        Toast.makeText(requireContext(), "Refreshed clipboard buffer ❄️", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(requireContext(), "Refresh failed: $msg", Toast.LENGTH_SHORT).show()
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
        refreshPendingApprovals()
    }

    private fun startTelemetryPolling() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                while (isActive) {
                    if (viewModel.connectionState.value == ConnectionState.CONNECTED && !isRefreshingTelemetry) {
                        isRefreshingTelemetry = true
                        refreshPendingApprovals()
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
                    val isAndroid = pc.os?.contains("Android", ignoreCase = true) == true
                    binding.tvWallpaperDeviceBadge.text = if (isAndroid) "📱 Android Phone" else "🖥️ Windows PC"
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

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.screenShareState.collectLatest { state ->
                when (state) {
                    LiveScreenStreamHandler.StreamState.STREAMING -> {
                        binding.btnScreenConsent.text = "Stop Sharing"
                        binding.cardScreenSharing.visibility = View.VISIBLE
                        binding.tvScreenShareStatus.text = "STREAMING"
                    }
                    LiveScreenStreamHandler.StreamState.STARTING -> {
                        binding.btnScreenConsent.text = "Starting..."
                        binding.cardScreenSharing.visibility = View.VISIBLE
                        binding.tvScreenShareStatus.text = "STARTING"
                    }
                    LiveScreenStreamHandler.StreamState.REVOKED -> {
                        binding.btnScreenConsent.text = "Share Screen"
                        binding.cardScreenSharing.visibility = View.GONE
                        Toast.makeText(requireContext(), "Screen sharing was stopped by system", Toast.LENGTH_SHORT).show()
                    }
                    else -> {
                        binding.btnScreenConsent.text = "Share Screen"
                        binding.cardScreenSharing.visibility = View.GONE
                    }
                }
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.cameraDelivery.collectLatest { info ->
                when (info.status) {
                    SnowUiRepository.CameraDeliveryStatus.IDLE -> {
                        binding.cardCameraDelivery.visibility = View.GONE
                    }
                    SnowUiRepository.CameraDeliveryStatus.CAPTURING -> {
                        binding.cardCameraDelivery.visibility = View.VISIBLE
                        binding.tvCameraDeliveryBadge.text = "CAPTURING"
                        binding.tvCameraDeliveryBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.secondary_cyan))
                        binding.tvCameraDeliveryDetails.text = "Taking photo with camera..."
                        binding.btnRetryCameraUpload.visibility = View.GONE
                    }
                    SnowUiRepository.CameraDeliveryStatus.UPLOADING -> {
                        binding.cardCameraDelivery.visibility = View.VISIBLE
                        binding.tvCameraDeliveryBadge.text = "UPLOADING"
                        binding.tvCameraDeliveryBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.primary_blue))
                        binding.tvCameraDeliveryDetails.text = "Uploading photo to PC over HTTPS..."
                        binding.btnRetryCameraUpload.visibility = View.GONE
                    }
                    SnowUiRepository.CameraDeliveryStatus.DELIVERED -> {
                        binding.cardCameraDelivery.visibility = View.VISIBLE
                        binding.tvCameraDeliveryBadge.text = "DELIVERED"
                        binding.tvCameraDeliveryBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connected))
                        binding.tvCameraDeliveryDetails.text = "Photo delivered to PC successfully: ${info.fileName ?: "photo.jpg"}"
                        binding.btnRetryCameraUpload.visibility = View.GONE
                    }
                    SnowUiRepository.CameraDeliveryStatus.FAILED -> {
                        binding.cardCameraDelivery.visibility = View.VISIBLE
                        binding.tvCameraDeliveryBadge.text = "FAILED"
                        binding.tvCameraDeliveryBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_disconnected))
                        binding.tvCameraDeliveryDetails.text = "Upload failed: ${info.error ?: "Network error"}"
                        binding.btnRetryCameraUpload.visibility = View.VISIBLE
                    }
                }
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.clipboardBufferItems.collectLatest { items ->
                    renderClipboardBufferItems(items)
                }
            }
        }
    }

    private fun renderClipboardBufferItems(items: List<SnowUiRepository.ClipboardItemDto>) {
        if (_binding == null) return
        val container = binding.layoutBufferItems
        container.removeAllViews()

        if (items.isEmpty()) {
            binding.tvBufferEmpty.visibility = View.VISIBLE
            binding.tvBufferEmpty.text = "Buffer empty or offline."
            return
        }

        binding.tvBufferEmpty.visibility = View.GONE
        items.take(10).forEach { item ->
            val row = android.widget.LinearLayout(requireContext()).apply {
                orientation = android.widget.LinearLayout.HORIZONTAL
                layoutParams = android.widget.LinearLayout.LayoutParams(
                    android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                    android.widget.LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = 8
                }
                gravity = android.view.Gravity.CENTER_VERTICAL
                setPadding(8, 8, 8, 8)
                setBackgroundResource(R.drawable.bg_card_glacier)
            }

            val tvText = android.widget.TextView(requireContext()).apply {
                layoutParams = android.widget.LinearLayout.LayoutParams(
                    0,
                    android.widget.LinearLayout.LayoutParams.WRAP_CONTENT,
                    1f
                )
                val deviceTag = if (item.sourceDevice.lowercase().contains("phone")) "📱" else "💻"
                val pinTag = if (item.isPinned) "📌 " else ""
                val preview = item.previewText.take(60)
                text = "$deviceTag $pinTag$preview"
                textSize = 12f
                setTextColor(ContextCompat.getColor(requireContext(), R.color.primary_text))
            }
            row.addView(tvText)

            val btnCopy = com.google.android.material.button.MaterialButton(
                requireContext(),
                null,
                com.google.android.material.R.attr.materialButtonOutlinedStyle
            ).apply {
                text = "Copy"
                textSize = 10f
                setPadding(12, 4, 12, 4)
                setTextColor(ContextCompat.getColor(requireContext(), R.color.primary_text))
                strokeColor = android.content.res.ColorStateList.valueOf(
                    ContextCompat.getColor(requireContext(), R.color.card_border)
                )
                setOnClickListener {
                    viewModel.applyBufferItem(item) { success, msg ->
                        activity?.runOnUiThread {
                            Toast.makeText(requireContext(), msg ?: "Copied", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            }
            row.addView(btnCopy)

            container.addView(row)
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
                refreshPendingApprovals()
                viewLifecycleOwner.lifecycleScope.launch {
                    val bitmap = SnowUiRepository.getInstance(requireContext()).loadDesktopWallpaper()
                    if (_binding != null) {
                        if (bitmap != null) {
                            binding.ivDesktopWallpaper.setImageBitmap(bitmap)
                            binding.ivDesktopWallpaper.imageTintList = null
                            binding.ivDesktopWallpaper.scaleType = android.widget.ImageView.ScaleType.CENTER_CROP
                            binding.cardWallpaperPreview.visibility = View.VISIBLE
                        } else {
                            // Polished SNOW Light/Dark fallback surface
                            binding.ivDesktopWallpaper.setImageResource(R.drawable.ic_snow_logo)
                            binding.ivDesktopWallpaper.scaleType = android.widget.ImageView.ScaleType.CENTER_INSIDE
                            binding.cardWallpaperPreview.visibility = View.VISIBLE
                        }
                    }
                }
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
                binding.cardWallpaperPreview.visibility = View.GONE
            }
        }
    }

    private fun refreshPendingApprovals() {
        if (_binding == null) return
        if (viewModel.connectionState.value != ConnectionState.CONNECTED) {
            binding.cardPendingApprovals.visibility = View.GONE
            return
        }
        viewModel.fetchPendingApprovals { result ->
            activity?.runOnUiThread {
                result.onSuccess { items ->
                    renderPendingApprovals(items)
                }.onFailure {
                    binding.cardPendingApprovals.visibility = View.GONE
                }
            }
        }
    }

    private fun renderPendingApprovals(items: List<PendingApprovalItem>) {
        if (_binding == null) return
        if (items.isEmpty()) {
            binding.cardPendingApprovals.visibility = View.GONE
            return
        }
        binding.cardPendingApprovals.visibility = View.VISIBLE
        binding.tvApprovalsCount.text = items.size.toString()
        binding.layoutApprovalsItems.removeAllViews()

        val inflater = LayoutInflater.from(requireContext())
        for (item in items) {
            val itemView = inflater.inflate(R.layout.item_pending_approval, binding.layoutApprovalsItems, false)
            val tvOp = itemView.findViewById<android.widget.TextView>(R.id.tv_approval_op)
            val tvRisk = itemView.findViewById<android.widget.TextView>(R.id.tv_approval_risk)
            val tvPrincipal = itemView.findViewById<android.widget.TextView>(R.id.tv_approval_principal)
            val tvReason = itemView.findViewById<android.widget.TextView>(R.id.tv_approval_reason)
            val tvTtl = itemView.findViewById<android.widget.TextView>(R.id.tv_approval_ttl)
            val btnApprove = itemView.findViewById<com.google.android.material.button.MaterialButton>(R.id.btn_approve)
            val btnDeny = itemView.findViewById<com.google.android.material.button.MaterialButton>(R.id.btn_deny)

            tvOp.text = item.action
            tvRisk.text = item.riskLevel.uppercase(Locale.US)
            tvPrincipal.text = "Caller: ${item.principal} • Target: ${item.targetDevice}"
            tvReason.text = item.reason
            val remSec = item.timeRemainingSeconds.toInt()
            tvTtl.text = if (remSec > 0) "⏳ ${remSec}s remaining" else "⛔ Expired"

            btnApprove.setOnClickListener {
                btnApprove.isEnabled = false
                btnDeny.isEnabled = false
                viewModel.resolveApproval(item.requestId, "APPROVE") { res ->
                    activity?.runOnUiThread {
                        res.onSuccess {
                            Toast.makeText(requireContext(), "Approved request ${item.action} 🛡️", Toast.LENGTH_SHORT).show()
                            refreshPendingApprovals()
                        }.onFailure { err ->
                            Toast.makeText(requireContext(), "Approval failed: ${err.message}", Toast.LENGTH_SHORT).show()
                            btnApprove.isEnabled = true
                            btnDeny.isEnabled = true
                        }
                    }
                }
            }

            btnDeny.setOnClickListener {
                btnApprove.isEnabled = false
                btnDeny.isEnabled = false
                viewModel.resolveApproval(item.requestId, "DENY") { res ->
                    activity?.runOnUiThread {
                        res.onSuccess {
                            Toast.makeText(requireContext(), "Denied request ${item.action}", Toast.LENGTH_SHORT).show()
                            refreshPendingApprovals()
                        }.onFailure { err ->
                            Toast.makeText(requireContext(), "Deny failed: ${err.message}", Toast.LENGTH_SHORT).show()
                            btnApprove.isEnabled = true
                            btnDeny.isEnabled = true
                        }
                    }
                }
            }

            binding.layoutApprovalsItems.addView(itemView)
        }
    }

    override fun onDestroyView() {
        detachClipboardListener()
        super.onDestroyView()
        _binding = null
    }
}
