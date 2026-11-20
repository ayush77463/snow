package org.snow.ui.dashboard

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.flow.StateFlow
import org.snow.network.AuthState
import org.snow.network.ConnectionState
import org.snow.ui.ActiveTransferInfo
import org.snow.ui.PcTelemetry
import org.snow.ui.PhoneTelemetry
import org.snow.ui.SnowUiRepository

class DashboardViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = SnowUiRepository.getInstance(application)

    val connectionState: StateFlow<ConnectionState> = repository.connectionState
    val connectedEndpoint: StateFlow<String?> = repository.connectedEndpoint
    val authState: StateFlow<AuthState> = repository.authState
    val phoneTelemetry: StateFlow<PhoneTelemetry> = repository.phoneTelemetry
    val pcTelemetry: StateFlow<PcTelemetry> = repository.pcTelemetry
    val activeTransfer: StateFlow<ActiveTransferInfo?> = repository.activeTransfer

    fun refreshTelemetry(onComplete: ((Boolean) -> Unit)? = null) {
        repository.refreshPhoneTelemetry()
        repository.queryPcStatus(onComplete)
    }

    fun isDuplicateClipboard(text: String): Boolean {
        return repository.isDuplicateClipboard(text)
    }

    fun toggleInstantClipboardSync(enabled: Boolean, onComplete: ((Boolean) -> Unit)? = null) {
        repository.toggleInstantClipboardSync(enabled, onComplete)
    }

    fun ringPhone() {
        repository.ringPhone()
    }

    fun lockPc(onComplete: (Boolean, String?) -> Unit) {
        repository.lockPc(onComplete)
    }

    fun launchWindowsApp(appName: String, onComplete: (Boolean, String?) -> Unit) {
        repository.launchWindowsApp(appName, onComplete)
    }

    fun pushClipboard(text: String, onComplete: (Boolean, String?) -> Unit) {
        repository.pushClipboard(text, onComplete)
    }

    fun pushCurrentClipboard(onComplete: (Boolean, String?) -> Unit) {
        repository.pushCurrentClipboard(onComplete)
    }

    fun pushLatestScreenshot(onComplete: (Boolean, String?) -> Unit) {
        repository.pushLatestRecentScreenshotIfAvailable(onComplete)
    }

    fun pullClipboard(onComplete: (Boolean, String?) -> Unit) {
        repository.pullClipboard(onComplete)
    }

    fun cancelActiveTransfer() {
        repository.cancelActiveTransfer()
    }
}
