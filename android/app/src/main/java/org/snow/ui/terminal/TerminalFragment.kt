package org.snow.ui.terminal

import android.os.Bundle
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.snow.R
import org.snow.databinding.FragmentTerminalBinding
import org.snow.network.ConnectionState
import org.snow.ui.TerminalExecutionState
import org.snow.ui.TerminalOutputLine
import org.snow.ui.TerminalResult

class TerminalFragment : Fragment() {

    private var _binding: FragmentTerminalBinding? = null
    private val binding get() = _binding!!

    private val viewModel: TerminalViewModel by activityViewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentTerminalBinding.inflate(inflater, container, false)
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

        // Quick Command History Chips
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
        viewModel.executeCommand(cmd, ticket) { result ->
            activity?.runOnUiThread {
                when (result) {
                    is TerminalResult.ConfirmationRequired -> {
                        // Stage 19A Two-Step Confirmation Ticket Handshake
                        CommandConfirmDialog.show(
                            context = requireContext(),
                            command = result.command,
                            action = "windows_terminal_exec",
                            onConfirmed = {
                                // Re-submit with exact server-issued single-use confirmation ticket
                                runCommand(result.command, ticket = result.ticket)
                            },
                            onCancelled = {
                                viewModel.cancelCommand()
                                Toast.makeText(requireContext(), "Command confirmation cancelled", Toast.LENGTH_SHORT).show()
                            }
                        )
                    }
                    is TerminalResult.Success -> {
                        // Result captured in outputLines state
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
            viewModel.connectionState.collectLatest { state ->
                if (state != ConnectionState.CONNECTED) {
                    binding.tvTerminalExitBadge.text = "OFFLINE"
                    binding.tvTerminalExitBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_disconnected))
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
        if (state.isRunning) {
            binding.btnTerminalRun.visibility = View.GONE
            binding.btnTerminalCancel.visibility = View.VISIBLE
            binding.tvTerminalExitBadge.text = "RUNNING..."
            binding.tvTerminalExitBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_connecting))
        } else {
            binding.btnTerminalRun.visibility = View.VISIBLE
            binding.btnTerminalCancel.visibility = View.GONE
            if (state.exitCode != null) {
                val isSuccess = state.exitCode == 0
                binding.tvTerminalExitBadge.text = "Exit: ${state.exitCode}"
                val colorRes = if (isSuccess) R.color.status_connected else R.color.status_disconnected
                binding.tvTerminalExitBadge.setTextColor(ContextCompat.getColor(requireContext(), colorRes))
            } else {
                binding.tvTerminalExitBadge.text = "IDLE"
                binding.tvTerminalExitBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.secondary_text))
            }
        }

        // Render console output lines with syntax highlighting
        val ssb = SpannableStringBuilder()
        for (line in state.outputLines) {
            val start = ssb.length
            ssb.append(line.text).append("\n")
            val end = ssb.length

            val color = when {
                line.isSystem -> 0xFF2DD4BF.toInt() // Arctic Teal
                line.isStderr -> 0xFFF87171.toInt() // Red
                else -> 0xFF38BDF8.toInt()          // Sky Blue / Glacier
            }
            ssb.setSpan(ForegroundColorSpan(color), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        }

        binding.tvTerminalOutput.text = ssb
        binding.svTerminalOutput.post {
            binding.svTerminalOutput.fullScroll(View.FOCUS_DOWN)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
