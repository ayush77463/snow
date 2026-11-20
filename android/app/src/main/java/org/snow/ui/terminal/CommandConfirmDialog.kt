package org.snow.ui.terminal

import android.content.Context
import androidx.appcompat.app.AlertDialog
import org.snow.R

/**
 * Confirmation dialog for Tier C terminal commands implementing Stage 19A ticket-based authorization.
 *
 * Displays the exact command that requires owner approval without ever exposing or logging
 * the single-use cryptographic confirmation ticket.
 */
object CommandConfirmDialog {

    fun show(
        context: Context,
        command: String,
        action: String = "windows_terminal_exec",
        onConfirmed: () -> Unit,
        onCancelled: () -> Unit = {}
    ) {
        val message = StringBuilder()
            .append("The following command requires explicit owner confirmation before execution:\n\n")
            .append("Command:\n  $command\n\n")
            .append("Action:\n  $action\n\n")
            .append("Execution is restricted to protect system integrity. Confirm only if you recognize and approve this command.")
            .toString()

        AlertDialog.Builder(context)
            .setTitle(context.getString(R.string.title_confirm_command))
            .setMessage(message)
            .setIcon(android.R.drawable.ic_dialog_alert)
            .setCancelable(false)
            .setPositiveButton(context.getString(R.string.btn_authorize_run)) { dialog, _ ->
                dialog.dismiss()
                onConfirmed()
            }
            .setNegativeButton(android.R.string.cancel) { dialog, _ ->
                dialog.dismiss()
                onCancelled()
            }
            .show()
    }
}
