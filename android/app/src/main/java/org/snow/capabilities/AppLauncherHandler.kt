package org.snow.capabilities

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snow.security.SafeLog

/**
 * Android application enumeration and launching capability handler.
 *
 * Implements Sub-Milestone 6.4:
 * - Lists launchable applications with package names and human-readable labels.
 * - Launches authorized apps via getLaunchIntentForPackage with FLAG_ACTIVITY_NEW_TASK.
 * - Bounded results and safe error handling without shell execution.
 */
class AppLauncherHandler(private val context: Context) {

    companion object {
        private const val TAG = "AppLauncherHandler"
        const val DEFAULT_APP_LIMIT = 50
        const val MAX_APP_LIMIT = 100
    }

    suspend fun listApps(limit: Int = DEFAULT_APP_LIMIT): Map<String, Any?> = withContext(Dispatchers.IO) {
        val boundedLimit = limit.coerceIn(1, MAX_APP_LIMIT)
        val pm: PackageManager = context.packageManager

        val intent = Intent(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_LAUNCHER)
        }

        try {
            val activities = pm.queryIntentActivities(intent, 0)
            val appList = activities
                .mapNotNull { resolveInfo ->
                    val pkgName = resolveInfo.activityInfo?.packageName
                    if (pkgName.isNullOrBlank()) null
                    else {
                        val label = resolveInfo.loadLabel(pm).toString().takeIf { it.isNotBlank() }
                            ?: pkgName
                        mapOf(
                            "package_name" to pkgName,
                            "label" to label
                        )
                    }
                }
                .distinctBy { it["package_name"] }
                .sortedBy { (it["label"] as? String)?.lowercase() ?: "" }
                .take(boundedLimit)

            SafeLog.i(TAG, "Enumerated ${appList.size} launchable application(s).")
            return@withContext mapOf(
                "status" to "success",
                "count" to appList.size,
                "apps" to appList
            )
        } catch (e: Exception) {
            SafeLog.e(TAG, "Error enumerating applications: ${e.message}", e)
            return@withContext mapOf(
                "status" to "error",
                "error" to "Failed listing applications: ${e.message}"
            )
        }
    }

    suspend fun launchApp(packageName: String?): Map<String, Any?> = withContext(Dispatchers.Main) {
        if (packageName.isNullOrBlank()) {
            return@withContext mapOf(
                "status" to "error",
                "error" to "Package name cannot be empty."
            )
        }

        val cleanPackage = packageName.trim()
        val pm: PackageManager = context.packageManager

        val launchIntent = pm.getLaunchIntentForPackage(cleanPackage)
        if (launchIntent == null) {
            SafeLog.w(TAG, "No launchable activity found for package '$cleanPackage'")
            return@withContext mapOf(
                "status" to "error",
                "error" to "Application '$cleanPackage' not found or is not launchable."
            )
        }

        launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

        try {
            context.startActivity(launchIntent)
            SafeLog.i(TAG, "Successfully launched application '$cleanPackage'")
            return@withContext mapOf(
                "status" to "success",
                "package_name" to cleanPackage,
                "message" to "Successfully launched application '$cleanPackage'."
            )
        } catch (e: ActivityNotFoundException) {
            SafeLog.w(TAG, "ActivityNotFoundException launching '$cleanPackage': ${e.message}")
            return@withContext mapOf(
                "status" to "error",
                "error" to "Application '$cleanPackage' activity not found."
            )
        } catch (e: SecurityException) {
            SafeLog.w(TAG, "SecurityException launching '$cleanPackage': ${e.message}")
            return@withContext mapOf(
                "status" to "error",
                "error" to "Permission denied launching '$cleanPackage': ${e.message}"
            )
        } catch (e: Exception) {
            SafeLog.e(TAG, "Unexpected error launching '$cleanPackage': ${e.message}", e)
            return@withContext mapOf(
                "status" to "error",
                "error" to "Failed launching '$cleanPackage': ${e.message}"
            )
        }
    }
}
