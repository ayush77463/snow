package org.snow.ui

import android.app.Activity
import android.os.Bundle
import org.snow.security.SafeLog
import org.snow.service.SnowForegroundService

/**
 * Transparent, no-history trampoline activity to reliably launch SnowForegroundService
 * from AutoConnectTileService on Android 14+ (API 34+) without background-start restrictions.
 */
class AutoConnectTrampolineActivity : Activity() {

    companion object {
        private const val TAG = "AutoConnectTrampoline"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            SafeLog.i(TAG, "Trampoline triggered; starting SnowForegroundService auto-connect...")
            SnowForegroundService.startAutoConnect(this)
        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed launching service from trampoline: ${e.message}")
        } finally {
            finish()
        }
    }
}
