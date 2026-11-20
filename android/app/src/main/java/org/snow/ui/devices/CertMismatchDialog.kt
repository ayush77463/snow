package org.snow.ui.devices

import android.content.Context
import androidx.appcompat.app.AlertDialog
import org.snow.R

/**
 * Hard security modal displayed when a TLS certificate mismatch is detected.
 *
 * Enforces TOFU security principles: blocks the connection and strictly provides
 * NO bypass or "continue anyway" action. Guides the user to safe dismissal or
 * deliberate cryptographic trust reset.
 */
object CertMismatchDialog {

    fun show(
        context: Context,
        pinnedFingerprint: String,
        presentedFingerprint: String,
        onResetTrustConfirmed: () -> Unit,
        onDismiss: () -> Unit = {}
    ) {
        val message = StringBuilder()
            .append("A cryptographic mismatch was detected during TLS connection to the desktop.\n\n")
            .append("• Pinned Fingerprint:\n  $pinnedFingerprint\n\n")
            .append("• Presented Fingerprint:\n  $presentedFingerprint\n\n")
            .append("Connection has been BLOCKED to prevent network spoofing or eavesdropping (MitM attack).\n\n")
            .append("If the desktop certificate was intentionally regenerated, you must explicitly reset device trust.")
            .toString()

        AlertDialog.Builder(context)
            .setTitle(context.getString(R.string.title_cert_mismatch))
            .setMessage(message)
            .setIcon(android.R.drawable.ic_dialog_alert)
            .setCancelable(false)
            .setPositiveButton(context.getString(R.string.btn_dismiss)) { dialog, _ ->
                dialog.dismiss()
                onDismiss()
            }
            .setNegativeButton(context.getString(R.string.btn_reset_trust)) { dialog, _ ->
                dialog.dismiss()
                showResetTrustConfirmation(context, onResetTrustConfirmed)
            }
            .show()
    }

    private fun showResetTrustConfirmation(context: Context, onConfirmed: () -> Unit) {
        AlertDialog.Builder(context)
            .setTitle("Confirm Trust Reset")
            .setMessage("Are you sure you want to clear all pinned certificate fingerprints and authentication tokens? You will need to pair again using a fresh desktop PIN.")
            .setPositiveButton("Reset Trust") { dialog, _ ->
                dialog.dismiss()
                onConfirmed()
            }
            .setNegativeButton("Cancel") { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }
}
