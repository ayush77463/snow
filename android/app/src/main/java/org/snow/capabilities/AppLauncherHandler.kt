package org.snow.capabilities

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snow.security.SafeLog

/**
 * Policy governing application launch authorization.
 *
 * Enforces an explicit, user-controlled allowlist for remote AI application launches.
 * Prevents arbitrary package launch and restricts launches to approved applications.
 */
object AppAllowlistPolicy {
    private const val PREFS_NAME = "snow_app_allowlist"
    private const val KEY_ALLOWED_PACKAGES = "allowed_packages"

    val DEFAULT_ALLOWED_PACKAGES = setOf(
        "com.google.android.calculator",
        "com.android.calculator2",
        "com.google.android.deskclock",
        "com.android.deskclock",
        "com.google.android.calendar",
        "com.android.calendar"
    )

    private val PACKAGE_REGEX = Regex("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+$")

    @Volatile
    private var customAllowlist: Set<String>? = null

    fun isValidPackageSyntax(packageName: String): Boolean {
        return PACKAGE_REGEX.matches(packageName)
    }

    fun getAllowedPackages(context: Context): Set<String> {
        customAllowlist?.let { return it }
        return try {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val saved = prefs?.getStringSet(KEY_ALLOWED_PACKAGES, null)
            saved ?: DEFAULT_ALLOWED_PACKAGES
        } catch (_: Exception) {
            DEFAULT_ALLOWED_PACKAGES
        }
    }

    fun isAllowed(context: Context, packageName: String): Boolean {
        return getAllowedPackages(context).contains(packageName)
    }

    fun setAllowedPackages(context: Context, packages: Set<String>) {
        try {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs?.edit()?.putStringSet(KEY_ALLOWED_PACKAGES, packages)?.apply()
        } catch (_: Exception) {
            // Context without prefs (e.g. mock test context)
        }
        customAllowlist = packages
    }

    fun setCustomAllowlistForTesting(packages: Set<String>?) {
        customAllowlist = packages
    }

    fun resetForTesting() {
        customAllowlist = null
    }
}

/**
 * Android application enumeration and launching capability handler.
 *
 * Implements Sub-Milestone 6.4 and Phase 19A security hardening:
 * - Lists launchable applications with package names and human-readable labels.
 * - Enforces explicit allowlist policy on application launches (rejects unapproved packages).
 * - Validates package identifier syntax against regex.
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
                .sortedBy { it["label"]?.lowercase() ?: "" }
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
                "success" to false,
                "status" to "error",
                "error" to "Package name cannot be empty."
            )
        }

        val cleanPackage = packageName.trim()

        // 1. Syntax validation
        if (!AppAllowlistPolicy.isValidPackageSyntax(cleanPackage)) {
            SafeLog.w(TAG, "Malformed package name: '$cleanPackage'")
            return@withContext mapOf(
                "success" to false,
                "status" to "MALFORMED_PACKAGE_NAME",
                "error" to "MALFORMED_PACKAGE_NAME",
                "message" to "Package name '$cleanPackage' is malformed."
            )
        }

        // 2. Allowlist authorization
        if (!AppAllowlistPolicy.isAllowed(context, cleanPackage)) {
            SafeLog.w(TAG, "Package '$cleanPackage' rejected by allowlist policy.")
            return@withContext mapOf(
                "success" to false,
                "status" to "POLICY_DENIED",
                "error" to "POLICY_DENIED",
                "message" to "Application '$cleanPackage' is not on the user-approved allowlist for remote launch.",
                "remediation_hint" to "Add '$cleanPackage' to the approved application allowlist in SNOW settings."
            )
        }

        // 3. Application existence and launchability check
        val pm: PackageManager? = try {
            context.packageManager
        } catch (_: Exception) {
            null
        }
        val launchIntent = try {
            pm?.getLaunchIntentForPackage(cleanPackage)
        } catch (e: Exception) {
            null
        }

        if (launchIntent == null) {
            SafeLog.w(TAG, "No launchable activity found for package '$cleanPackage'")
            return@withContext mapOf(
                "success" to false,
                "status" to "error",
                "error" to "Application '$cleanPackage' not found or is not launchable."
            )
        }

        launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

        val inForeground = ClipboardHandler.isAppInForeground
        if (inForeground) {
            try {
                context.startActivity(launchIntent)
                SafeLog.i(TAG, "Successfully launched application '$cleanPackage' directly in foreground.")
                return@withContext mapOf(
                    "success" to true,
                    "status" to "success",
                    "delivery_mode" to "DIRECT_FOREGROUND",
                    "package_name" to cleanPackage,
                    "message" to "Successfully launched application '$cleanPackage'."
                )
            } catch (e: ActivityNotFoundException) {
                SafeLog.w(TAG, "ActivityNotFoundException launching '$cleanPackage': ${e.message}")
                return@withContext mapOf(
                    "success" to false,
                    "status" to "error",
                    "error" to "Application '$cleanPackage' activity not found."
                )
            } catch (e: SecurityException) {
                SafeLog.w(TAG, "SecurityException launching '$cleanPackage': ${e.message}")
                return@withContext mapOf(
                    "success" to false,
                    "status" to "PERMISSION_DENIED",
                    "error" to "Permission denied launching '$cleanPackage': ${e.message}",
                    "remediation_hint" to "Check application permissions in Android Settings."
                )
            } catch (e: Exception) {
                SafeLog.e(TAG, "Unexpected error launching '$cleanPackage': ${e.message}", e)
                return@withContext mapOf(
                    "success" to false,
                    "status" to "error",
                    "error" to "Failed launching '$cleanPackage': ${e.message}"
                )
            }
        } else {
            // Android background activity launch restriction: require user tap via notification
            if (ActionNotificationHelper.canPostNotifications(context)) {
                val label = try {
                    pm?.getApplicationLabel(pm.getApplicationInfo(cleanPackage, 0))?.toString() ?: cleanPackage
                } catch (_: Exception) {
                    cleanPackage
                }

                val posted = ActionNotificationHelper.postActionNotification(
                    context = context,
                    title = "SNOW: Tap to open $label",
                    content = "Tap to open application on this device.",
                    intent = launchIntent
                )

                if (posted) {
                    SafeLog.i(TAG, "Posted action notification for background launch of '$cleanPackage'.")
                    return@withContext mapOf(
                        "success" to true,
                        "status" to "success",
                        "delivery_mode" to "NOTIFICATION_TAP_REQUIRED",
                        "package_name" to cleanPackage,
                        "message" to "Application is in background. Tap the notification on your phone to open '$label'."
                    )
                }
            }

            SafeLog.w(TAG, "Background launch rejected for '$cleanPackage': notifications disabled or unavailable.")
            return@withContext mapOf(
                "success" to false,
                "status" to "FOREGROUND_REQUIRED",
                "error" to "Background activity launch restricted by Android OS. Notification permission is required to deliver tap action.",
                "remediation_hint" to "Open SNOW on your phone or grant Notification permission in Android Settings to launch applications."
            )
        }
    }
}
