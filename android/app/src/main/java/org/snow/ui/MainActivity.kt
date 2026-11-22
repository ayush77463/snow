package org.snow.ui

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import org.snow.R
import org.snow.databinding.ActivityMainBinding
import org.snow.network.ConnectionState
import org.snow.security.SafeLog
import org.snow.service.SnowForegroundService
import org.snow.ui.dashboard.DashboardFragment
import org.snow.ui.devices.DevicesFragment
import org.snow.ui.files.FilesFragment
import org.snow.ui.settings.SettingsFragment
import org.snow.ui.settings.SettingsViewModel
import org.snow.ui.terminal.TerminalFragment

/**
 * Primary host activity providing Material 3 five-tab navigation across:
 * 1. Dashboard
 * 2. Devices
 * 3. Files
 * 4. Terminal
 * 5. Settings
 */
class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "MainActivity"
        private const val KEY_ACTIVE_TAB = "key_active_tab"
        private const val TAG_DASHBOARD = "tag_dashboard"
        private const val TAG_DEVICES = "tag_devices"
        private const val TAG_FILES = "tag_files"
        private const val TAG_TERMINAL = "tag_terminal"
        private const val TAG_SETTINGS = "tag_settings"
    }

    private lateinit var binding: ActivityMainBinding
    private lateinit var repository: SnowUiRepository

    private var activeTabId: Int = R.id.nav_dashboard
    private var activeFragment: Fragment? = null
    private lateinit var dashboardFragment: Fragment
    private lateinit var devicesFragment: Fragment
    private lateinit var filesFragment: Fragment
    private lateinit var terminalFragment: Fragment
    private lateinit var settingsFragment: Fragment

    private var service: SnowForegroundService? = null
    private var isBound = false

    private val screenCaptureLauncher = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK && result.data != null) {
            SafeLog.i(TAG, "MediaProjection screen capture consent granted by user; delegating to ForegroundService.")
            org.snow.service.SnowForegroundService.startOneTimeScreenCapture(this, result.resultCode, result.data!!)
        } else {
            org.snow.capabilities.ScreenCaptureHandler.resetConsent()
            SafeLog.w(TAG, "MediaProjection screen capture consent cancelled or denied.")
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
        val savedTheme = prefs.getInt(SettingsViewModel.KEY_THEME_MODE, SettingsViewModel.THEME_SYSTEM)
        AppCompatDelegate.setDefaultNightMode(savedTheme)

        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        repository = SnowUiRepository.getInstance(applicationContext)

        setupWindowInsets()
        setupBottomNavigation(savedInstanceState)
        observeGlobalState()
        checkScreenCaptureRequest(intent)
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
            kotlinx.coroutines.delay(150)
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
                kotlinx.coroutines.delay(150)
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

        ViewCompat.setOnApplyWindowInsetsListener(binding.rootLayout) { _, insets ->
            val systemBars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            binding.appHeader.setPadding(
                binding.appHeader.paddingLeft,
                systemBars.top + 12,
                binding.appHeader.paddingRight,
                binding.appHeader.paddingBottom
            )
            binding.bottomNavigation.setPadding(
                binding.bottomNavigation.paddingLeft,
                binding.bottomNavigation.paddingTop,
                binding.bottomNavigation.paddingRight,
                systemBars.bottom
            )
            insets
        }
    }

    private fun setupBottomNavigation(savedInstanceState: Bundle?) {
        val fm = supportFragmentManager

        if (savedInstanceState == null) {
            dashboardFragment = DashboardFragment()
            devicesFragment = DevicesFragment()
            filesFragment = FilesFragment()
            terminalFragment = TerminalFragment()
            settingsFragment = SettingsFragment()

            fm.beginTransaction()
                .add(R.id.fragment_container, dashboardFragment, TAG_DASHBOARD)
                .add(R.id.fragment_container, devicesFragment, TAG_DEVICES).hide(devicesFragment)
                .add(R.id.fragment_container, filesFragment, TAG_FILES).hide(filesFragment)
                .add(R.id.fragment_container, terminalFragment, TAG_TERMINAL).hide(terminalFragment)
                .add(R.id.fragment_container, settingsFragment, TAG_SETTINGS).hide(settingsFragment)
                .commit()

            activeTabId = R.id.nav_dashboard
            activeFragment = dashboardFragment
        } else {
            activeTabId = savedInstanceState.getInt(KEY_ACTIVE_TAB, R.id.nav_dashboard)
            dashboardFragment = fm.findFragmentByTag(TAG_DASHBOARD) ?: DashboardFragment()
            devicesFragment = fm.findFragmentByTag(TAG_DEVICES) ?: DevicesFragment()
            filesFragment = fm.findFragmentByTag(TAG_FILES) ?: FilesFragment()
            terminalFragment = fm.findFragmentByTag(TAG_TERMINAL) ?: TerminalFragment()
            settingsFragment = fm.findFragmentByTag(TAG_SETTINGS) ?: SettingsFragment()

            activeFragment = when (activeTabId) {
                R.id.nav_devices -> devicesFragment
                R.id.nav_files -> filesFragment
                R.id.nav_terminal -> terminalFragment
                R.id.nav_settings -> settingsFragment
                else -> dashboardFragment
            }
        }

        binding.bottomNavigation.selectedItemId = activeTabId
        binding.bottomNavigation.setOnItemSelectedListener { item ->
            val target = when (item.itemId) {
                R.id.nav_dashboard -> dashboardFragment
                R.id.nav_devices -> devicesFragment
                R.id.nav_files -> filesFragment
                R.id.nav_terminal -> terminalFragment
                R.id.nav_settings -> settingsFragment
                else -> null
            }
            if (target != null) {
                activeTabId = item.itemId
                switchFragment(target)
                true
            } else {
                false
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt(KEY_ACTIVE_TAB, activeTabId)
    }

    private fun switchFragment(target: Fragment) {
        if (activeFragment == target) return
        val tx = supportFragmentManager.beginTransaction()
        activeFragment?.let { tx.hide(it) }
        tx.show(target).commit()
        activeFragment = target
    }

    fun selectTab(tabId: Int) {
        binding.bottomNavigation.selectedItemId = tabId
    }

    private fun observeGlobalState() {
        lifecycleScope.launch {
            combine(repository.connectionState, repository.connectedEndpoint) { state, endpoint ->
                Pair(state, endpoint)
            }.collectLatest { (state, endpoint) ->
                renderHeaderStatus(state, endpoint)
            }
        }
    }

    private fun renderHeaderStatus(state: ConnectionState, endpoint: String?) {
        val cleanEndpoint = endpoint ?: ""
        val isUsb = cleanEndpoint.startsWith("127.0.0.1") || cleanEndpoint.startsWith("localhost")
        val isRelay = cleanEndpoint.startsWith("relay:") || cleanEndpoint.contains("tunnel") || cleanEndpoint.contains(":8770")
        when (state) {
            ConnectionState.CONNECTED -> {
                binding.headerStatusPill.text = if (isRelay) "CONNECTED • RELAY" else if (isUsb) "CONNECTED • USB" else if (cleanEndpoint.isNotBlank()) "CONNECTED • WI-FI" else "CONNECTED"
                binding.headerStatusPill.setTextColor(ContextCompat.getColor(this, R.color.status_connected))
            }
            ConnectionState.CONNECTING -> {
                binding.headerStatusPill.text = "CONNECTING..."
                binding.headerStatusPill.setTextColor(ContextCompat.getColor(this, R.color.status_connecting))
            }
            ConnectionState.RECONNECTING -> {
                binding.headerStatusPill.text = "RECONNECTING..."
                binding.headerStatusPill.setTextColor(ContextCompat.getColor(this, R.color.status_reconnecting))
            }
            ConnectionState.DISCONNECTED -> {
                binding.headerStatusPill.text = "DISCONNECTED"
                binding.headerStatusPill.setTextColor(ContextCompat.getColor(this, R.color.status_disconnected))
            }
        }
    }
}
