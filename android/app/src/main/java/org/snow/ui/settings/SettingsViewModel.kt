package org.snow.ui.settings

import android.app.Application
import android.content.Context
import androidx.appcompat.app.AppCompatDelegate
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.flow.StateFlow
import org.snow.network.AuthState
import org.snow.ui.SnowUiRepository
import org.snow.ui.UiLogEntry

class SettingsViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = SnowUiRepository.getInstance(application)
    private val prefs = application.getSharedPreferences("snow_settings", Context.MODE_PRIVATE)

    companion object {
        const val KEY_THEME_MODE = "theme_mode"
        const val THEME_SYSTEM = AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
        const val THEME_LIGHT = AppCompatDelegate.MODE_NIGHT_NO
        const val THEME_DARK = AppCompatDelegate.MODE_NIGHT_YES
    }

    val authState: StateFlow<AuthState> = repository.authState
    val logs: StateFlow<List<UiLogEntry>> = repository.logs

    val deviceIdentity = repository.identity
    val safFolderManager = repository.safFolderManager

    fun getSavedThemeMode(): Int {
        return prefs.getInt(KEY_THEME_MODE, THEME_SYSTEM)
    }

    fun setThemeMode(mode: Int) {
        prefs.edit().putInt(KEY_THEME_MODE, mode).apply()
        AppCompatDelegate.setDefaultNightMode(mode)
    }

    fun unpairDevice() {
        repository.unpairDevice()
    }

    fun resetTrust() {
        repository.resetTrust()
    }

    fun clearLogs() {
        repository.clearLogs()
    }

    fun isRemoteRelayEnabled(): Boolean = repository.isRemoteRelayEnabled()
    fun getRemoteRelayEndpoint(): String = repository.getRemoteRelayEndpoint()
    fun saveRemoteRelayConfig(enabled: Boolean, endpoint: String) {
        repository.updateRemoteRelayConfig(enabled, endpoint)
    }
}
