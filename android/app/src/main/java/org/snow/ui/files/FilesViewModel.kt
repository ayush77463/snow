package org.snow.ui.files

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.snow.network.ConnectionState
import org.snow.ui.ActiveTransferInfo
import org.snow.ui.PcFileItem
import org.snow.ui.SnowUiRepository

class FilesViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = SnowUiRepository.getInstance(application)

    val connectionState: StateFlow<ConnectionState> = repository.connectionState
    val activeTransfer: StateFlow<ActiveTransferInfo?> = repository.activeTransfer

    private val _currentPath = MutableStateFlow("")
    val currentPath: StateFlow<String> = _currentPath.asStateFlow()

    private val _fileItems = MutableStateFlow<List<PcFileItem>>(emptyList())
    val fileItems: StateFlow<List<PcFileItem>> = _fileItems.asStateFlow()

    private val _hideHidden = MutableStateFlow(true)
    val hideHidden: StateFlow<Boolean> = _hideHidden.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    val safFolderManager = repository.safFolderManager

    fun setHideHidden(hide: Boolean) {
        _hideHidden.value = hide
        loadDirectory(_currentPath.value)
    }

    fun loadDirectory(path: String) {
        _isLoading.value = true
        _errorMessage.value = null
        repository.listPcDirectory(path, _hideHidden.value) { items, err ->
            _isLoading.value = false
            if (items != null) {
                _currentPath.value = path
                _fileItems.value = items
            } else {
                _errorMessage.value = err ?: "Failed listing directory"
            }
        }
    }

    fun navigateUp() {
        val current = _currentPath.value.trimEnd('\\', '/')
        val lastSlash = maxOf(current.lastIndexOf('\\'), current.lastIndexOf('/'))
        if (lastSlash > 0) {
            val parent = current.substring(0, lastSlash)
            val target = if (parent.length == 2 && parent[1] == ':') "$parent\\" else parent
            loadDirectory(target)
        } else if (lastSlash == 0 || (current.length == 2 && current[1] == ':')) {
            loadDirectory("")
        } else {
            loadDirectory("")
        }
    }

    fun startDownload(item: PcFileItem, onComplete: (Boolean, String?) -> Unit) {
        repository.startFileDownload(item, onComplete)
    }

    fun uploadFileUri(uri: Uri, fileName: String, fileSize: Long, onComplete: (Boolean, String?) -> Unit) {
        repository.startFileUpload(uri, fileName, fileSize, onComplete)
    }

    fun cancelTransfer() {
        repository.cancelActiveTransfer()
    }

    fun persistDestinationUri(uri: Uri): Boolean {
        return safFolderManager.persistFolderUri(uri)
    }

    fun getDestinationDisplayName(): String {
        return safFolderManager.getDestinationDisplayName()
    }
}
