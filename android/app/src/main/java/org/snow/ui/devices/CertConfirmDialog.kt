package org.snow.ui.devices

import android.content.Context
import androidx.appcompat.app.AlertDialog

/**
 * Trust-On-First-Use (TOFU) confirmation dialog displayed when a desktop
 * presents its TLS SHA-256 certificate fingerprint for the first time.
 */
object CertConfirmDialog {

    fun show(
        context: Context,
        fingerprint: String,
        onTrustConfirmed: () -> Unit,
        onReject: () -> Unit = {}
    ) {
        val message = StringBuilder()
            .append("The desktop core presented the following SHA-256 TLS certificate fingerprint:\n\n")
            .append("• Fingerprint:\n  $fingerprint\n\n")
            .append("Verify this matches the fingerprint displayed in your laptop terminal banner.\n\n")
            .append("Do you trust this desktop endpoint?")
            .toString()

        AlertDialog.Builder(context)
            .setTitle("Verify Server Certificate")
            .setMessage(message)
            .setIcon(android.R.drawable.ic_dialog_info)
            .setCancelable(false)
            .setPositiveButton("Trust & Connect") { dialog, _ ->
                dialog.dismiss()
                onTrustConfirmed()
            }
            .setNegativeButton("Reject") { dialog, _ ->
                dialog.dismiss()
                onReject()
            }
            .show()
    }
}
