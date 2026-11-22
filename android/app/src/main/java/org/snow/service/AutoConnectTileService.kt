package org.snow.service

import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import org.snow.network.ConnectionState
import org.snow.security.SafeLog
import org.snow.ui.SnowUiRepository

/**
 * Quick Settings tile providing one-tap toggle for the SNOW Capability Bridge:
 * - When disconnected: invokes SnowForegroundService.ACTION_AUTO_CONNECT cascade.
 * - When connected: invokes SnowForegroundService.ACTION_DISCONNECT.
 * Reflects real service connection state in Tile.state.
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
        val isConnected = repo.connectionState.value == ConnectionState.CONNECTED

        if (isConnected) {
            SafeLog.i(TAG, "Tile clicked while CONNECTED; stopping SnowForegroundService...")
            SnowForegroundService.stop(this)
        } else {
            SafeLog.i(TAG, "Tile clicked while disconnected; starting auto-connect cascade...")
            SnowForegroundService.startAutoConnect(this)
        }

        val tile = qsTile ?: return
        tile.state = if (isConnected) Tile.STATE_INACTIVE else Tile.STATE_ACTIVE
        tile.label = if (isConnected) "SNOW Disconnecting..." else "SNOW Connecting..."
        tile.updateTile()
    }

    private fun updateTileState() {
        val tile = qsTile ?: return
        val repo = SnowUiRepository.getInstance(applicationContext)
        val state = repo.connectionState.value

        when (state) {
            ConnectionState.CONNECTED -> {
                tile.state = Tile.STATE_ACTIVE
                tile.label = "SNOW Connected"
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = repo.connectedEndpoint.value ?: "Active"
                }
            }
            ConnectionState.CONNECTING, ConnectionState.RECONNECTING -> {
                tile.state = Tile.STATE_INACTIVE
                tile.label = "SNOW Connecting"
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = "Connecting..."
                }
            }
            ConnectionState.DISCONNECTED -> {
                tile.state = Tile.STATE_INACTIVE
                tile.label = "SNOW Connect"
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = "Disconnected"
                }
            }
        }
        tile.updateTile()
    }
}
