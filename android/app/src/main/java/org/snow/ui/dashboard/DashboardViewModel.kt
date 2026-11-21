package org.snow.ui.dashboard

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.flow.StateFlow
import org.snow.capabilities.LiveScreenStreamHandler
import org.snow.network.AuthState
import org.snow.network.ConnectionState
import org.snow.ui.ActiveTransferInfo
import org.snow.ui.PcTelemetry
import org.snow.ui.PendingApprovalItem
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
    val screenShareState: StateFlow<LiveScreenStreamHandler.StreamState> = repository.screenShareState
    val cameraDelivery: StateFlow<SnowUiRepository.CameraDeliveryInfo> = repository.cameraDelivery
    val clipboardBufferItems: StateFlow<List<SnowUiRepository.ClipboardItemDto>> = repository.clipboardBufferItems

    fun startScreenShare(resultCode: Int, data: android.content.Intent) {
        repository.startScreenShare(resultCode, data)
    }

    fun stopScreenShare() {
        repository.stopScreenShare()
    }

    fun setCameraCapturing() {
        repository.setCameraCapturing()
    }

    fun uploadCameraPhoto(onComplete: ((Boolean, String?) -> Unit)? = null) {
        repository.uploadCameraPhoto { success, resOrErr ->
            onComplete?.invoke(success, resOrErr)
        }
    }

    fun retryCameraUpload(onComplete: ((Boolean, String?) -> Unit)? = null) {
        repository.retryCameraUpload { success, resOrErr ->
            onComplete?.invoke(success, resOrErr)
        }
    }

    fun dismissCameraDelivery() {
        repository.dismissCameraDelivery()
    }

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

    fun refreshClipboardBuffer(onComplete: ((Boolean, String?) -> Unit)? = null) {
        repository.fetchClipboardBuffer(onComplete)
    }

    fun applyBufferItem(item: SnowUiRepository.ClipboardItemDto, onComplete: (Boolean, String?) -> Unit) {
        repository.applyBufferItemToClipboard(item, onComplete)
    }

    fun fetchPendingApprovals(callback: (Result<List<PendingApprovalItem>>) -> Unit) {
        repository.fetchPendingApprovals(callback)
    }

    fun resolveApproval(requestId: String, decision: String, callback: (Result<String>) -> Unit) {
        repository.resolveApproval(requestId, decision, callback)
    }
}
