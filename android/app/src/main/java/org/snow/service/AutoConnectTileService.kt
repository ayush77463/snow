package org.snow.service

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import org.snow.network.ConnectionState
import org.snow.security.SafeLog
import org.snow.ui.AutoConnectTrampolineActivity
import org.snow.ui.SnowUiRepository

/**
 * Quick Settings tile providing one-tap toggle for the SNOW Capability Bridge:
 * - When disconnected: invokes SnowForegroundService auto-connect cascade via AutoConnectTrampolineActivity.
 * - When connected: invokes SnowForegroundService.ACTION_DISCONNECT and sets userDisconnected = true.
 * Reflects authoritative connection state in Tile.state and dynamic subtitle.
 */
class AutoConnectTileService : TileService() {

    companion object {
        private const val TAG = "AutoConnectTile"
    }

    override fun onStartListening() {
        super.onStartListening()
        updateTileState()
    }

    override fun onClick() {
        super.onClick()
        val repo = SnowUiRepository.getInstance(applicationContext)
        val state = repo.connectionState.value
        val isConnected = state == ConnectionState.CONNECTED

        if (isConnected) {
            SafeLog.i(TAG, "Tile clicked while CONNECTED; stopping connection...")
            SnowForegroundService.isUserDisconnected = true
            SnowForegroundService.stop(this)
            updateTileDisplay(Tile.STATE_INACTIVE, "SNOW Connect", "Off")
        } else if (state == ConnectionState.CONNECTING || state == ConnectionState.RECONNECTING) {
            SafeLog.i(TAG, "Tile clicked while already connecting; ignoring duplicate tap.")
        } else {
            SafeLog.i(TAG, "Tile clicked while disconnected; launching trampoline for auto-connect...")
            SnowForegroundService.isUserDisconnected = false

            val intent = Intent(this, AutoConnectTrampolineActivity::class.java).apply {
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
                SafeLog.w(TAG, "Could not launch trampoline via startActivityAndCollapse: ${e.message}; falling back to direct service start")
                try {
                    SnowForegroundService.startAutoConnect(this)
                } catch (se: Exception) {
                    SafeLog.e(TAG, "Fallback service start failed: ${se.message}")
                }
            }

            updateTileDisplay(Tile.STATE_INACTIVE, "SNOW Connecting", "Connecting...")
        }
    }

    private fun updateTileDisplay(state: Int, label: String, subtitle: String) {
        val tile = qsTile ?: return
        tile.state = state
        tile.label = label
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = subtitle
        }
        tile.updateTile()
    }

    private fun updateTileState() {
        val repo = SnowUiRepository.getInstance(applicationContext)
        val state = repo.connectionState.value
        val endpoint = repo.connectedEndpoint.value ?: ""

        when (state) {
            ConnectionState.CONNECTED -> {
                val sub = if (endpoint.contains("relay", ignoreCase = true) || endpoint.contains("/v1/tunnel", ignoreCase = true) || endpoint.contains(":8770")) {
                    "Connected \u2022 Remote"
                } else if (endpoint.contains("127.0.0.1") || endpoint.contains("usb", ignoreCase = true)) {
                    "Connected \u2022 USB"
                } else {
                    "Connected \u2022 Wi-Fi"
                }
                updateTileDisplay(Tile.STATE_ACTIVE, "SNOW Connected", sub)
            }
            ConnectionState.CONNECTING, ConnectionState.RECONNECTING -> {
                updateTileDisplay(Tile.STATE_INACTIVE, "SNOW Connecting", "Connecting...")
            }
            ConnectionState.DISCONNECTED -> {
                updateTileDisplay(Tile.STATE_INACTIVE, "SNOW Connect", "Off")
            }
        }
    }
}
