package org.snow.ui

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.Uri
import android.os.Bundle
import android.os.IBinder
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.setValue
import androidx.core.view.WindowCompat
import androidx.lifecycle.lifecycleScope
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.snow.security.SafeLog
import org.snow.service.SnowForegroundService
import org.snow.ui.settings.SettingsViewModel

/**
 * Primary host activity providing Material 3 Jetpack Compose Flagship UI.
 */
class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "MainActivity"
    }

    private lateinit var repository: SnowUiRepository
    private var service: SnowForegroundService? = null
    private var isBound = false

    private var currentThemeMode by mutableIntStateOf(SettingsViewModel.THEME_SYSTEM)

    private val screenCaptureLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK && result.data != null) {
            SafeLog.i(TAG, "MediaProjection screen capture consent granted by user; delegating to ForegroundService.")
            SnowForegroundService.startOneTimeScreenCapture(this, result.resultCode, result.data!!)
        } else {
            org.snow.capabilities.ScreenCaptureHandler.resetConsent()
            SafeLog.w(TAG, "MediaProjection screen capture consent cancelled or denied.")
        }
    }

    private val qrScanLauncher = registerForActivityResult(ScanContract()) { result ->
        val qrText = result.contents
        if (!qrText.isNullOrBlank()) {
            repository.connectByInput(qrText) { success, message, _ ->
                runOnUiThread {
                    if (success) {
                        Toast.makeText(this, "Pairing connected successfully!", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(this, "Pairing failed: $message", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    private val safFolderPickerLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri: Uri? ->
        if (uri != null) {
            val success = repository.safFolderManager.persistFolderUri(uri)
            if (success) {
                Toast.makeText(this, "Download destination set to: ${repository.safFolderManager.getDestinationDisplayName()}", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Failed to persist SAF folder permission", Toast.LENGTH_LONG).show()
            }
        }
    }

    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            val (fileName, fileSize) = resolveUriMetadata(uri)
            repository.startFileUpload(uri, fileName, fileSize) { success, errOrName ->
                runOnUiThread {
                    if (success) {
                        Toast.makeText(this, "Upload complete: $errOrName", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(this, "Upload failed: $errOrName", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val localBinder = binder as? SnowForegroundService.LocalBinder
            service = localBinder?.service
            isBound = true
            service?.let { repository.bindService(it) }
            SafeLog.i(TAG, "SnowForegroundService bound successfully.")
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            repository.unbindService()
            service = null
            isBound = false
            SafeLog.i(TAG, "SnowForegroundService disconnected.")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // Apply persisted appearance preference before super.onCreate
        val prefs = getSharedPreferences("snow_settings", Context.MODE_PRIVATE)
        currentThemeMode = prefs.getInt(SettingsViewModel.KEY_THEME_MODE, SettingsViewModel.THEME_SYSTEM)
        AppCompatDelegate.setDefaultNightMode(currentThemeMode)

        super.onCreate(savedInstanceState)
        repository = SnowUiRepository.getInstance(applicationContext)

        setupWindowInsets()

        setContent {
            SnowApp(
                repository = repository,
                onLaunchQrScanner = {
                    val options = ScanOptions().apply {
                        setPrompt("Scan SNOW Pairing QR Code")
                        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                        setCameraId(0)
                        setBeepEnabled(false)
                        setOrientationLocked(true)
                        setCaptureActivity(PortraitCaptureActivity::class.java)
                    }
                    qrScanLauncher.launch(options)
                },
                onPickFilesToUpload = {
                    filePickerLauncher.launch(arrayOf("*/*"))
                },
                onPickSafFolder = {
                    safFolderPickerLauncher.launch(null)
                },
                onToggleScreenShareConsent = {
                    val projMgr = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as? android.media.projection.MediaProjectionManager
                    val captureIntent = projMgr?.createScreenCaptureIntent()
                    if (captureIntent != null) {
                        screenCaptureLauncher.launch(captureIntent)
                    }
                },
                themeMode = currentThemeMode,
                onThemeModeChanged = { mode ->
                    currentThemeMode = mode
                }
            )
        }

        checkScreenCaptureRequest(intent)
    }

    fun selectTab(tabId: Int) {
        // Legacy fragment callback compatibility
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        checkScreenCaptureRequest(intent)
    }

    private fun checkScreenCaptureRequest(intent: Intent?) {
        if (intent?.getBooleanExtra("request_screen_capture", false) == true) {
            val projMgr = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as? android.media.projection.MediaProjectionManager
            val captureIntent = projMgr?.createScreenCaptureIntent()
            if (captureIntent != null) {
                screenCaptureLauncher.launch(captureIntent)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        org.snow.capabilities.ClipboardHandler.onActivityResumed("MainActivity")
        org.snow.capabilities.ClipboardHandler.isUserIntentGranted = true
        lifecycleScope.launch {
            delay(150)
            repository.checkAndSyncForegroundClipboard()
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) {
            org.snow.capabilities.ClipboardHandler.onActivityResumed("MainActivity")
            org.snow.capabilities.ClipboardHandler.isUserIntentGranted = true
            lifecycleScope.launch {
                // 150ms delay required on Android 10+ / Android 17 (ColorOS) for window focus
                // to settle before primary clipboard read is permitted by the OS.
                delay(150)
                repository.checkAndSyncForegroundClipboard()
            }
        }
    }

    override fun onPause() {
        super.onPause()
        org.snow.capabilities.ClipboardHandler.onActivityPaused("MainActivity")
    }

    override fun onStart() {
        super.onStart()
        val intent = Intent(this, SnowForegroundService::class.java)
        bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
        if (!SnowForegroundService.isDisconnectedByUser(this)) {
            val autoConnectEnabled = getSharedPreferences(SnowUiRepository.PREFS_SETTINGS, Context.MODE_PRIVATE)
                .getBoolean(SnowUiRepository.PREF_KEY_AUTO_CONNECT_ENABLED, true)
            if (autoConnectEnabled) {
                SnowForegroundService.startAutoConnect(this)
            }
        }
    }

    override fun onStop() {
        super.onStop()
        if (isBound) {
            unbindService(serviceConnection)
            isBound = false
        }
    }

    private fun setupWindowInsets() {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val isNight = (resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK) == android.content.res.Configuration.UI_MODE_NIGHT_YES
        val insetsController = WindowCompat.getInsetsController(window, window.decorView)
        insetsController.isAppearanceLightStatusBars = !isNight
        insetsController.isAppearanceLightNavigationBars = !isNight
    }

    private fun resolveUriMetadata(uri: Uri): Pair<String, Long> {
        var name = "upload_file"
        var size = 0L
        try {
            contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                if (cursor.moveToFirst()) {
                    if (nameIdx != -1) name = cursor.getString(nameIdx) ?: name
                    if (sizeIdx != -1) size = cursor.getLong(sizeIdx)
                }
            }
        } catch (_: Exception) { }
        return Pair(name, size)
    }
}
