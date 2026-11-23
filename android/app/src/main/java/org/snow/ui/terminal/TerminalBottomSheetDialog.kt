package org.snow.ui.terminal

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.text.SpannableStringBuilder
import android.text.style.ForegroundColorSpan
import android.transition.TransitionManager
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.snow.R
import org.snow.databinding.DialogTerminalBottomSheetBinding
import org.snow.network.ConnectionState
import org.snow.ui.TerminalExecutionState
import org.snow.ui.TerminalOutputLine
import org.snow.ui.TerminalResult

class TerminalBottomSheetDialog : BottomSheetDialogFragment() {

    private var _binding: DialogTerminalBottomSheetBinding? = null
    private val binding get() = _binding!!

    private val viewModel: TerminalViewModel by activityViewModels()

    companion object {
        const val TAG = "TerminalBottomSheetDialog"
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = DialogTerminalBottomSheetBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupListeners()
        observeViewModel()
    }

    private fun setupListeners() {
        binding.btnTerminalRun.setOnClickListener {
            val cmd = binding.etTerminalCmd.text?.toString() ?: ""
            if (cmd.isBlank()) {
                Toast.makeText(requireContext(), "Enter a command to run", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            runCommand(cmd.trim())
        }

        binding.btnTerminalCancel.setOnClickListener {
            viewModel.cancelCommand()
        }

        binding.btnCopyTerminalOutput.setOnClickListener {
            val text = binding.tvTerminalOutput.text?.toString() ?: ""
            if (text.isNotBlank()) {
                val cm = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                cm?.setPrimaryClip(ClipData.newPlainText("terminal_output", text))
                Toast.makeText(requireContext(), "Output copied to clipboard", Toast.LENGTH_SHORT).show()
            }
        }

        // Quick command chips
        binding.chipWhoami.setOnClickListener { executeFromChip("whoami") }
        binding.chipDir.setOnClickListener { executeFromChip("dir") }
        binding.chipIpconfig.setOnClickListener { executeFromChip("ipconfig") }
        binding.chipSysteminfo.setOnClickListener { executeFromChip("systeminfo") }
        binding.chipGitStatus.setOnClickListener { executeFromChip("git status") }
    }

    private fun executeFromChip(cmd: String) {
        binding.etTerminalCmd.setText(cmd)
        runCommand(cmd)
    }

    private fun runCommand(cmd: String, ticket: String? = null) {
        // Slide open the output container if hidden
        if (binding.layoutTerminalOutputContainer.visibility != View.VISIBLE) {
            TransitionManager.beginDelayedTransition(binding.root as ViewGroup)
            binding.layoutTerminalOutputContainer.visibility = View.VISIBLE
        }

        viewModel.executeCommand(cmd, ticket) { result ->
            activity?.runOnUiThread {
                when (result) {
                    is TerminalResult.ConfirmationRequired -> {
                        CommandConfirmDialog.show(
                            context = requireContext(),
                            command = result.command,
                            action = "windows_terminal_exec",
                            onConfirmed = {
                                runCommand(result.command, ticket = result.ticket)
                            },
                            onCancelled = {
                                viewModel.cancelCommand()
                                Toast.makeText(requireContext(), "Command confirmation cancelled", Toast.LENGTH_SHORT).show()
                            }
                        )
                    }
                    is TerminalResult.Success -> {
                        // Handled by state observer
                    }
                    is TerminalResult.Failed -> {
                        Toast.makeText(requireContext(), "Exit code ${result.exitCode ?: -1}: ${result.error}", Toast.LENGTH_SHORT).show()
                    }
                    is TerminalResult.Error -> {
                        Toast.makeText(requireContext(), result.message, Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    private fun observeViewModel() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.connectionState.collectLatest { conn ->
                val connected = conn == ConnectionState.CONNECTED
                binding.btnTerminalRun.isEnabled = connected
                binding.etTerminalCmd.isEnabled = connected
                if (!connected) {
                    binding.tvTerminalExitBadge.text = "OFFLINE"
                    binding.tvTerminalExitBadge.setTextColor(
                        ContextCompat.getColor(requireContext(), R.color.status_disconnected)
                    )
                }
            }
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.terminalState.collectLatest { state ->
                renderTerminalState(state)
            }
        }
    }

    private fun renderTerminalState(state: TerminalExecutionState) {
        if (_binding == null) return

        if (state.isRunning) {
            binding.btnTerminalRun.visibility = View.GONE
            binding.btnTerminalCancel.visibility = View.VISIBLE
            binding.tvTerminalExitBadge.text = "RUNNING"
            binding.tvTerminalExitBadge.setTextColor(
                ContextCompat.getColor(requireContext(), R.color.status_connecting)
            )
            if (binding.layoutTerminalOutputContainer.visibility != View.VISIBLE) {
                TransitionManager.beginDelayedTransition(binding.root as ViewGroup)
                binding.layoutTerminalOutputContainer.visibility = View.VISIBLE
            }
        } else {
            binding.btnTerminalRun.visibility = View.VISIBLE
            binding.btnTerminalCancel.visibility = View.GONE

            if (state.exitCode != null) {
                if (state.exitCode == 0) {
                    binding.tvTerminalExitBadge.text = "EXIT: 0"
                    binding.tvTerminalExitBadge.setTextColor(
                        ContextCompat.getColor(requireContext(), R.color.status_connected)
                    )
                } else {
                    binding.tvTerminalExitBadge.text = "EXIT: ${state.exitCode}"
                    binding.tvTerminalExitBadge.setTextColor(
                        ContextCompat.getColor(requireContext(), R.color.status_disconnected)
                    )
                }
            } else {
                binding.tvTerminalExitBadge.text = "IDLE"
                binding.tvTerminalExitBadge.setTextColor(
                    ContextCompat.getColor(requireContext(), R.color.status_connected)
                )
            }
        }

        if (state.outputLines.isNotEmpty()) {
            if (binding.layoutTerminalOutputContainer.visibility != View.VISIBLE) {
                TransitionManager.beginDelayedTransition(binding.root as ViewGroup)
                binding.layoutTerminalOutputContainer.visibility = View.VISIBLE
            }
            renderOutputLines(state.outputLines)
        }
    }

    private fun renderOutputLines(lines: List<TerminalOutputLine>) {
        val ssb = SpannableStringBuilder()
        val stdoutColor = ContextCompat.getColor(requireContext(), R.color.primary_blue)
        val stderrColor = ContextCompat.getColor(requireContext(), R.color.status_disconnected)
        val metaColor = ContextCompat.getColor(requireContext(), R.color.secondary_text)

        for (line in lines) {
            val start = ssb.length
            ssb.append(line.text).append("\n")
            val end = ssb.length

            val color = when {
                line.isSystem -> metaColor
                line.isStderr -> stderrColor
                else -> stdoutColor
            }
            ssb.setSpan(
                ForegroundColorSpan(color),
                start,
                end,
                android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
        }

        binding.tvTerminalOutput.text = ssb
        binding.svTerminalOutput.post {
            _binding?.svTerminalOutput?.fullScroll(View.FOCUS_DOWN)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
