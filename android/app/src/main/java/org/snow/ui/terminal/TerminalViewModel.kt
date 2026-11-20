package org.snow.ui.terminal

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.flow.StateFlow
import org.snow.network.ConnectionState
import org.snow.ui.SnowUiRepository
import org.snow.ui.TerminalExecutionState
import org.snow.ui.TerminalResult

class TerminalViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = SnowUiRepository.getInstance(application)

    val connectionState: StateFlow<ConnectionState> = repository.connectionState
    val terminalState: StateFlow<TerminalExecutionState> = repository.terminalState

    fun executeCommand(
        command: String,
        ticket: String? = null,
        onResult: (TerminalResult) -> Unit
    ) {
        repository.executeTerminalCommand(command, ticket, onResult)
    }

    fun cancelCommand() {
        repository.cancelTerminalCommand()
    }
}
