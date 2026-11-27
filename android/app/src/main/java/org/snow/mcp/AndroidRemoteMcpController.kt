package org.snow.mcp

import android.content.Context
import android.content.Intent
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.snow.capabilities.ActionNotificationHelper
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.protocol.SnowError
import org.snow.security.DeviceIdentity
import org.snow.security.DeviceKeyIdentity
import org.snow.security.DeviceKeyManager
import org.snow.security.SafeLog
import org.snow.security.SecretKeyProvider
import org.snow.ui.MainActivity
import org.snow.ui.PendingApprovalItem

/**
 * Coordinates SNOW's standalone Android Native MCP subsystem:
 * - [AndroidOAuthManager] (OAuth 2.1 + PKCE + consent queueing)
 * - [AndroidMcpResponder] (Streamable HTTP JSON-RPC + local approvals + peer routing)
 * - [AndroidMcpRelayForwarder] (outbound Render Hub `/v1/tunnel` connection)
 *
 * Persisted toggle `PREF_KEY_ANDROID_REMOTE_MCP_ENABLED` defaults to `true` so Android
 * remains remotely addressable via `/u/<android_snow_id>/mcp` independently of Windows PC.
 */
class AndroidRemoteMcpController(
    private val appContext: Context,
    private val capabilityDispatcher: AndroidCapabilityDispatcher,
    private val settingsPrefsName: String,
    private val deviceKeyProvider: () -> DeviceKeyIdentity,
    private val hubHttpUrlProvider: () -> String,
    private val networkIdProvider: () -> String?,
    private val peerDirectoryProvider: () -> List<McpPeerDescriptor>,
    private val peerActionForwarder: suspend (targetDeviceId: String, action: String, params: Map<String, Any?>, originClientId: String) -> Pair<Map<String, Any?>?, String?>,
    private val localActionExecutor: (suspend (action: String, params: Map<String, Any?>?) -> Pair<Map<String, Any?>?, SnowError?>)? = null,
    oauthKeyProvider: SecretKeyProvider? = null,
    allowInsecureLocalhostForTest: Boolean = false,
    autoReconnect: Boolean = true,
    private val onLocalApprovalsUpdated: () -> Unit = {}
) {
    companion object {
        private const val TAG = "AndroidRemoteMcpCtrl"
        const val PREF_KEY_ANDROID_REMOTE_MCP_ENABLED = "android_remote_mcp_enabled"
    }

    private val settingsPrefs = appContext.getSharedPreferences(settingsPrefsName, Context.MODE_PRIVATE)
    private val localDeviceIdentity = DeviceIdentity.getOrCreate(appContext)

    private val _enabled = MutableStateFlow(
        settingsPrefs.getBoolean(PREF_KEY_ANDROID_REMOTE_MCP_ENABLED, true)
    )
    val enabled: StateFlow<Boolean> = _enabled.asStateFlow()

    private val _authorizedClients = MutableStateFlow<List<AuthorizedOAuthClientSummary>>(emptyList())
    val authorizedClients: StateFlow<List<AuthorizedOAuthClientSummary>> = _authorizedClients.asStateFlow()

    @Volatile
    private var mcpResponderRef: AndroidMcpResponder? = null

    val oauthManager: AndroidOAuthManager = AndroidOAuthManager(
        context = appContext,
        deviceSnowIdProvider = {
            try {
                deviceKeyProvider().snowId
            } catch (_: Exception) {
                ""
            }
        },
        defaultPublicBaseUrlProvider = hubHttpUrlProvider,
        keyProvider = oauthKeyProvider
            ?: org.snow.security.AndroidKeyStoreKeyProvider(AndroidOAuthManager.OAUTH_KEYSTORE_ALIAS),
        onPendingConsentChanged = {
            refreshAuthorizedClients()
            onLocalApprovalsUpdated()
        },
        onNotificationRequested = { consent ->
            try {
                    ActionNotificationHelper.postApprovalNotification(
                        context = appContext,
                        requestId = consent.requestId,
                        principal = consent.clientName,
                        operation = "OAuth Authorize (${consent.scope})",
                        riskLevel = if (consent.networkRoutingAllowed) "HIGH" else "MEDIUM"
                    )
            } catch (_: Throwable) {}
        },
        onNotificationCancelled = { reqId ->
            try {
                ActionNotificationHelper.cancelApprovalNotification(appContext, reqId)
            } catch (_: Throwable) {}
        },
        onClientRevokedCallback = { clientId ->
            mcpResponderRef?.dropSessionsForClient(clientId)
            refreshAuthorizedClients()
        }
    )

    val mcpResponder: AndroidMcpResponder = AndroidMcpResponder(
        oauthManager = oauthManager,
        localDeviceIdProvider = { localDeviceIdentity.deviceId },
        localSnowIdProvider = {
            try {
                deviceKeyProvider().snowId
            } catch (_: Exception) {
                localDeviceIdentity.deviceId
            }
        },
        localDeviceNameProvider = { localDeviceIdentity.deviceName },
        localNetworkIdProvider = networkIdProvider,
        remoteMcpEnabledProvider = { isEnabled() },
        localCapabilityDispatcher = capabilityDispatcher,
        localActionExecutor = localActionExecutor,
        peerDirectoryProvider = peerDirectoryProvider,
        peerActionForwarder = peerActionForwarder,
        onPendingToolApprovalsChanged = { onLocalApprovalsUpdated() },
        onToolApprovalNotification = { app ->
            try {
                    ActionNotificationHelper.postApprovalNotification(
                        context = appContext,
                        requestId = app.requestId,
                        principal = app.clientName,
                        operation = app.toolName,
                        riskLevel = app.riskLevel
                    )
            } catch (_: Throwable) {}
        },
        onToolApprovalCancelled = { reqId ->
            try {
                ActionNotificationHelper.cancelApprovalNotification(appContext, reqId)
            } catch (_: Throwable) {}
        }
    ).also {
        mcpResponderRef = it
        refreshAuthorizedClients()
    }

    val relayForwarder: AndroidMcpRelayForwarder = AndroidMcpRelayForwarder(
        hubHttpUrlProvider = hubHttpUrlProvider,
        deviceIdProvider = { localDeviceIdentity.deviceId },
        deviceKeyProvider = deviceKeyProvider,
        networkIdProvider = networkIdProvider,
        responder = mcpResponder,
        enabledProvider = { isEnabled() },
        allowInsecureLocalhostForTest = allowInsecureLocalhostForTest,
        autoReconnect = autoReconnect
    )

    val tunnelState: StateFlow<RelayMcpForwarderState> = relayForwarder.state

    fun isEnabled(): Boolean = settingsPrefs.getBoolean(PREF_KEY_ANDROID_REMOTE_MCP_ENABLED, true)

    fun setEnabled(enable: Boolean, recoveryTakeover: Boolean = false) {
        settingsPrefs.edit().putBoolean(PREF_KEY_ANDROID_REMOTE_MCP_ENABLED, enable).apply()
        _enabled.value = enable
        if (enable) {
            relayForwarder.start(recoveryTakeover = recoveryTakeover)
        } else {
            relayForwarder.stop()
        }
        SafeLog.i(TAG, "Android Standalone Remote MCP setEnabled=$enable")
    }

    fun startIfEnabled(recoveryTakeover: Boolean = false) {
        refreshAuthorizedClients()
        val curEnabled = isEnabled()
        _enabled.value = curEnabled
        if (curEnabled) {
            relayForwarder.start(recoveryTakeover = recoveryTakeover)
        } else {
            relayForwarder.stop()
        }
    }

    fun stop() {
        relayForwarder.stop()
    }

    fun onDeviceIdentityRecovered() {
        oauthManager.clearAllOnRecovery()
        refreshAuthorizedClients()
        if (isEnabled()) {
            relayForwarder.stop()
            relayForwarder.start(recoveryTakeover = true)
        }
        onLocalApprovalsUpdated()
    }

    fun refreshAuthorizedClients() {
        _authorizedClients.value = oauthManager.listAuthorizedClients()
    }

    fun revokeAuthorizedClient(clientId: String): Boolean {
        val ok = oauthManager.revokeClient(clientId)
        refreshAuthorizedClients()
        return ok
    }

    fun listLocalApprovalItems(): List<PendingApprovalItem> {
        val now = System.currentTimeMillis()
        val consentItems = oauthManager.listPendingConsents().map { c ->
            val remSec = ((c.expiresAtMs - now).coerceAtLeast(0L)) / 1000.0
            PendingApprovalItem(
                requestId = c.requestId,
                principal = "AI OAuth (${c.clientName})",
                action = "oauth_authorize",
                targetDevice = c.targetSnowId.ifBlank { "This Android Device" },
                riskLevel = if (c.networkRoutingAllowed) "HIGH" else "MEDIUM",
                reason = "Allow '${c.clientName}' to access '${c.resource}' with scopes [${c.scope}]. " +
                    if (c.networkRoutingAllowed) "Includes write/routing permissions." else "Read-only scope.",
                timeRemainingSeconds = remSec,
                sanitizedParams = mapOf(
                    "client_id" to c.clientId,
                    "scope" to c.scope,
                    "endpoint" to c.resource,
                    "network_routing" to c.networkRoutingAllowed
                )
            )
        }
        val toolItems = mcpResponder.listPendingToolApprovals().map { a ->
            val remSec = ((a.expiresAtMs - now).coerceAtLeast(0L)) / 1000.0
            PendingApprovalItem(
                requestId = a.requestId,
                principal = "AI_MCP (${a.clientName})",
                action = a.toolName,
                targetDevice = a.targetDeviceId,
                riskLevel = a.riskLevel,
                reason = a.reason,
                timeRemainingSeconds = remSec,
                sanitizedParams = a.sanitizedSummary
            )
        }
        return consentItems + toolItems
    }

    fun tryResolveLocalApproval(requestId: String, decision: String): Boolean? {
        val approve = decision.trim().equals("APPROVE", ignoreCase = true)
        val isConsent = oauthManager.listPendingConsents().any { it.requestId == requestId }
        if (isConsent) {
            val handled = if (approve) {
                oauthManager.approveAuthorization(requestId)
            } else {
                oauthManager.rejectAuthorization(requestId)
            }
            refreshAuthorizedClients()
            onLocalApprovalsUpdated()
            return handled
        }
        val isTool = mcpResponder.listPendingToolApprovals().any { it.requestId == requestId }
        if (isTool) {
            val handled = if (approve) {
                mcpResponder.approveToolRequest(requestId)
            } else {
                mcpResponder.rejectToolRequest(requestId)
            }
            onLocalApprovalsUpdated()
            return handled
        }
        return null
    }
}
