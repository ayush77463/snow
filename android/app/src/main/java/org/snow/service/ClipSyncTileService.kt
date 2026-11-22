package org.snow.service

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import org.snow.security.SafeLog
import org.snow.ui.ClipSyncActivity

/**
 * Quick Settings tile providing one-tap instant clipboard pull/push via foreground ClipSyncActivity.
 */
class ClipSyncTileService : TileService() {

    companion object {
        private const val TAG = "ClipSyncTile"
    }

    override fun onStartListening() {
        super.onStartListening()
        val tile = qsTile ?: return
        tile.state = Tile.STATE_INACTIVE
        tile.label = "SNOW Clip"
        tile.updateTile()
    }

    override fun onClick() {
        super.onClick()
        SafeLog.i(TAG, "ClipSync Quick Settings tile tapped; launching ClipSyncActivity...")

        val intent = Intent(this, ClipSyncActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }

        try {
            if (Build.VERSION.SDK_INT >= 34) {
                val pendingIntent = PendingIntent.getActivity(
                    this,
                    0,
                    intent,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
                startActivityAndCollapse(pendingIntent)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
        } catch (e: Exception) {
            SafeLog.w(TAG, "Could not launch ClipSyncActivity from tile: ${e.message}")
            try {
                startActivity(intent)
            } catch (_: Exception) {}
        }
    }
}
