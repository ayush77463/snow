package org.snow.mcp

import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONArray
import org.json.JSONObject
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.protocol.SnowError
import org.snow.security.SafeLog
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

data class McpPeerDescriptor(
    val deviceId: String,
    val snowId: String = "",
    val deviceName: String = "",
    val deviceType: String = "android",
    val networkId: String = "",
    val isOnline: Boolean = false,
    val transport: String = "offline",
    val isFederated: Boolean = false,
    val supportedActions: Set<String> = emptySet()
)

data class PendingToolApprovalSnapshot(
    val requestId: String,
    val clientId: String,
    val clientName: String,
    val toolName: String,
    val action: String,
    val targetDeviceId: String,
    val riskLevel: String,
    val reason: String,
    val paramsHash: String,
    val sanitizedSummary: Map<String, Any?>,
    val createdAtMs: Long,
    val expiresAtMs: Long
)

data class McpAuditEntry(
    val timestampMs: Long,
    val clientId: String,
    val action: String,
    val targetDeviceId: String,
    val outcome: String
)

/**
 * Native Streamable HTTP MCP (JSON-RPC 2.0) + OAuth HTTP sub-router running locally inside Android.
 *
 * Security invariants:
 * - Every `/mcp` (`POST`, `GET`, `DELETE`) request enforces Bearer OAuth authentication first;
 *   unauthenticated `initialize`, `tools/list`, and `tools/call` fail closed with 401 + `WWW-Authenticate`.
 * - Strict `Mcp-Session-Id` ownership per `(clientId, familyId)`: no session fixation or cross-client reuse.
 * - `tools/call` independently re-validates OAuth bearer/resource/scopes, enabled toggle, target online/network state,
 *   5-tier `AI_MCP` permission profile, and owner approval (zero reliance on prior `tools/list`).
 * - Cross-device routing never silently falls back to another peer and never forwards across disconnected networks.
 * - Secret-redacted audit logging: never logs raw bearer tokens, clipboard text, or file contents.
 */
class AndroidMcpResponder(
    private val oauthManager: AndroidOAuthManager,
    private val localDeviceIdProvider: () -> String,
    private val localSnowIdProvider: () -> String,
    private val localDeviceNameProvider: () -> String = { android.os.Build.MODEL ?: "Android" },
    private val localNetworkIdProvider: () -> String? = { null },
    private val remoteMcpEnabledProvider: () -> Boolean = { true },
    private val localCapabilityDispatcher: AndroidCapabilityDispatcher,
    private val localActionExecutor: (suspend (action: String, params: Map<String, Any?>?) -> Pair<Map<String, Any?>?, SnowError?>)? = null,
    private val peerDirectoryProvider: () -> List<McpPeerDescriptor> = { emptyList() },
    private val peerActionForwarder: (suspend (targetDeviceId: String, action: String, params: Map<String, Any?>, originClientId: String) -> Pair<Map<String, Any?>?, String?>)? = null,
    private val onPendingToolApprovalsChanged: ((List<PendingToolApprovalSnapshot>) -> Unit)? = null,
    private val onToolApprovalNotification: ((PendingToolApprovalSnapshot) -> Unit)? = null,
    private val onToolApprovalCancelled: ((String) -> Unit)? = null,
    private val clockMs: () -> Long = { System.currentTimeMillis() }
) {
    companion object {
        private const val TAG = "AndroidMcpResponder"
        const val MAX_MCP_REQUEST_BYTES = 128 * 1024
        const val MAX_MCP_RESPONSE_BYTES = 512 * 1024
        const val TOOL_TIMEOUT_MS = 25_000L
        const val SESSION_TTL_MS = 24L * 3600_000L
        const val APPROVAL_TTL_MS = 300_000L
        const val MAX_SESSIONS = 128

        val SUPPORTED_PROTOCOL_VERSIONS = listOf(
            "2026-07-28",
            "2025-11-25",
            "2025-06-18",
            "2025-03-26",
            "2024-11-05"
        )

        const val TOPOLOGY_RESOURCE_URI = "snow://mesh/topology"

        private val BLOCKED_CROSS_NETWORK_FIELDS = setOf(
            "token", "auth_token", "hub_token", "bootstrap_token", "refresh_token", "access_token",
            "seed", "private_key", "recovery_key", "cert_fingerprint", "tls_pin", "secret", "ipc_secret"
        )
    }

    private data class McpSession(
        val sessionId: String,
        val clientId: String,
        val familyId: String,
        val protocolVersion: String,
        val createdAtMs: Long,
        @Volatile var lastSeenMs: Long
    )

    private data class ToolSpec(
        val name: String,
        val wireAction: String,
        val description: String,
        val requiredScope: String,
        val readOnlyHint: Boolean,
        val destructiveHint: Boolean,
        val requiresApproval: Boolean,
        val riskLevel: String,
        val targetKind: String, // "android", "windows", "mesh"
        val schemaJson: JSONObject
    )

    private data class PendingApprovalRecord(
        val requestId: String,
        val clientId: String,
        val clientName: String,
        val toolName: String,
        val action: String,
        val targetDeviceId: String,
        val riskLevel: String,
        val reason: String,
        val paramsHash: String,
        val sanitizedSummary: Map<String, Any?>,
        val createdAtMs: Long,
        val expiresAtMs: Long,
        var approved: Boolean = false,
        var rejected: Boolean = false,
        var consumed: Boolean = false
    ) {
        fun toSnapshot(): PendingToolApprovalSnapshot = PendingToolApprovalSnapshot(
            requestId = requestId,
            clientId = clientId,
            clientName = clientName,
            toolName = toolName,
            action = action,
            targetDeviceId = targetDeviceId,
            riskLevel = riskLevel,
            reason = reason,
            paramsHash = paramsHash,
            sanitizedSummary = sanitizedSummary,
            createdAtMs = createdAtMs,
            expiresAtMs = expiresAtMs
        )
    }

    private val sessions = ConcurrentHashMap<String, McpSession>()
    private val approvals = ConcurrentHashMap<String, PendingApprovalRecord>()
    private val auditLog = ArrayDeque<McpAuditEntry>()

    private val localTools: List<ToolSpec> = buildToolCatalog()

    fun dropSessionsForClient(clientId: String) {
        val clean = clientId.trim()
        if (clean.isEmpty()) return
        val toRemove = sessions.entries.filter { it.value.clientId == clean }.map { it.key }
        toRemove.forEach { sessions.remove(it) }
    }

    fun listPendingToolApprovals(): List<PendingToolApprovalSnapshot> {
        val now = clockMs()
        pruneApprovals(now)
        return approvals.values
            .filter { !it.approved && !it.rejected && !it.consumed && now <= it.expiresAtMs }
            .map { it.toSnapshot() }
    }

    fun approveToolRequest(requestId: String): Boolean {
        val now = clockMs()
        val rec = approvals[requestId] ?: return false
        synchronized(rec) {
            if (rec.rejected || rec.consumed || now > rec.expiresAtMs) return false
            rec.approved = true
        }
        onToolApprovalCancelled?.invoke(requestId)
        onPendingToolApprovalsChanged?.invoke(listPendingToolApprovals())
        return true
    }

    fun rejectToolRequest(requestId: String): Boolean {
        val rec = approvals[requestId] ?: return false
        synchronized(rec) {
            if (rec.consumed) return false
            rec.rejected = true
        }
        onToolApprovalCancelled?.invoke(requestId)
        onPendingToolApprovalsChanged?.invoke(listPendingToolApprovals())
        return true
    }

    fun recentAuditEntries(): List<McpAuditEntry> = synchronized(auditLog) { auditLog.toList() }

    suspend fun handleForwardedHttp(req: McpHttpRequest): McpHttpResponse {
        val path = normalizeSubpath(req.subpath)
        return when {
            path == "/.well-known/oauth-protected-resource" ||
                path == "/.well-known/oauth-protected-resource/mcp" -> {
                if (!req.method.equals("GET", ignoreCase = true)) {
                    methodNotAllowed()
                } else {
                    oauthManager.handleWellKnownProtectedResource(req)
                }
            }
            path == "/.well-known/oauth-authorization-server" -> {
                if (!req.method.equals("GET", ignoreCase = true)) {
                    methodNotAllowed()
                } else {
                    oauthManager.handleWellKnownAuthorizationServer(req)
                }
            }
            path == "/oauth/register" -> {
                if (!req.method.equals("POST", ignoreCase = true)) methodNotAllowed() else oauthManager.handleRegister(req)
            }
            path == "/oauth/authorize" -> {
                if (!req.method.equals("GET", true) && !req.method.equals("POST", true)) {
                    methodNotAllowed()
                } else {
                    oauthManager.handleAuthorize(req)
                }
            }
            path == "/oauth/status" -> {
                if (!req.method.equals("GET", ignoreCase = true)) methodNotAllowed() else oauthManager.handleAuthorizeStatus(req)
            }
            path == "/oauth/token" -> {
                if (!req.method.equals("POST", ignoreCase = true)) methodNotAllowed() else oauthManager.handleToken(req)
            }
            path == "/oauth/revoke" -> {
                if (!req.method.equals("POST", ignoreCase = true)) methodNotAllowed() else oauthManager.handleRevoke(req)
            }
            path == "/mcp" -> handleMcpEndpoint(req)
            else -> McpHttpResponse.json(
                404,
                JSONObject().put("error", "not_found").put("error_description", "Unknown MCP/OAuth path.")
            )
        }
    }

    private suspend fun handleMcpEndpoint(req: McpHttpRequest): McpHttpResponse {
        if (!remoteMcpEnabledProvider()) {
            return McpHttpResponse.json(
                503,
                JSONObject()
                    .put("error", "service_unavailable")
                    .put("error_description", "Android Remote MCP is disabled by owner.")
            )
        }

        val method = req.method.uppercase(Locale.ROOT)
        if (method !in setOf("POST", "GET", "DELETE")) {
            return methodNotAllowed()
        }

        val (issuer, expectedResource, _) = oauthManager.resolveIssuerAndResource(req)
        val authRes = oauthManager.validateBearerHeader(
            authorizationHeader = req.header("authorization"),
            expectedResource = expectedResource,
            requiredScopes = setOf("snow:read")
        )
        if (!authRes.valid || authRes.clientId.isNullOrEmpty() || authRes.familyId.isNullOrEmpty()) {
            val status = authRes.httpStatus
            val wwwAuth = if (status == 403) {
                "Bearer error=\"insufficient_scope\", resource_metadata=\"$issuer/.well-known/oauth-protected-resource\""
            } else {
                "Bearer error=\"invalid_token\", resource_metadata=\"$issuer/.well-known/oauth-protected-resource\""
            }
            return McpHttpResponse.json(
                status,
                JSONObject()
                    .put("error", authRes.errorCode ?: "invalid_token")
                    .put("error_description", authRes.errorDescription ?: "Unauthorized MCP access."),
                mapOf("WWW-Authenticate" to wwwAuth)
            )
        }

        val protoHeader = req.header("mcp-protocol-version")?.trim()
        if (!protoHeader.isNullOrEmpty() && protoHeader !in SUPPORTED_PROTOCOL_VERSIONS) {
            return McpHttpResponse.json(
                400,
                JSONObject()
                    .put("error", "unsupported_protocol_version")
                    .put("error_description", "Unsupported MCP-Protocol-Version header.")
            )
        }

        val incomingSessionId = req.header("mcp-session-id")?.trim()
        if (method == "DELETE") {
            if (incomingSessionId.isNullOrEmpty()) {
                return McpHttpResponse.json(400, JSONObject().put("error", "invalid_request").put("error_description", "Mcp-Session-Id required."))
            }
            val existing = sessions[incomingSessionId]
                ?: return McpHttpResponse.json(404, JSONObject().put("error", "session_not_found"))
            if (existing.clientId != authRes.clientId || existing.familyId != authRes.familyId) {
                return McpHttpResponse.json(403, JSONObject().put("error", "session_forbidden"))
            }
            sessions.remove(incomingSessionId)
            return McpHttpResponse.json(200, JSONObject().put("closed", true))
        }

        if (method == "GET") {
            if (!incomingSessionId.isNullOrEmpty()) {
                val existing = sessions[incomingSessionId]
                if (existing == null || existing.clientId != authRes.clientId || existing.familyId != authRes.familyId) {
                    return McpHttpResponse.json(403, JSONObject().put("error", "invalid_session"))
                }
            }
            return McpHttpResponse.json(
                405,
                JSONObject()
                    .put("error", "sse_not_supported")
                    .put("error_description", "Use POST /mcp Streamable HTTP JSON-RPC requests.")
            )
        }

        // POST /mcp
        val ct = req.header("content-type")?.lowercase(Locale.ROOT).orEmpty()
        if (ct.isNotEmpty() && !ct.contains("application/json")) {
            return McpHttpResponse.json(415, JSONObject().put("error", "unsupported_media_type"))
        }
        if (req.body.size > MAX_MCP_REQUEST_BYTES) {
            return McpHttpResponse.json(413, JSONObject().put("error", "payload_too_large"))
        }

        val rpcReq = try {
            JSONObject(String(req.body, StandardCharsets.UTF_8))
        } catch (_: Exception) {
            return jsonRpcErrorResponse(400, JSONObject.NULL, -32700, "Parse error: invalid JSON.")
        }

        val rpcId = rpcReq.opt("id")
        val rpcMethod = rpcReq.optString("method", "").trim()
        if (rpcReq.optString("jsonrpc") != "2.0" || rpcMethod.isEmpty()) {
            return jsonRpcErrorResponse(400, rpcId ?: JSONObject.NULL, -32600, "Invalid JSON-RPC 2.0 Request.")
        }
        val params = rpcReq.optJSONObject("params") ?: JSONObject()

        if (rpcMethod != "initialize" && !incomingSessionId.isNullOrEmpty()) {
            val existing = sessions[incomingSessionId]
            if (existing == null) {
                return jsonRpcErrorResponse(404, rpcId ?: JSONObject.NULL, -32001, "Unknown or expired Mcp-Session-Id.")
            }
            if (existing.clientId != authRes.clientId || existing.familyId != authRes.familyId) {
                return jsonRpcErrorResponse(403, rpcId ?: JSONObject.NULL, -32003, "Mcp-Session-Id belongs to a different client or token grant.")
            }
            existing.lastSeenMs = clockMs()
        }

        val responsePair: Pair<McpHttpResponse, String?> = when (rpcMethod) {
            "initialize" -> handleInitialize(rpcId, params, authRes)
            "notifications/initialized" -> {
                McpHttpResponse.json(202, JSONObject().put("acknowledged", true)) to incomingSessionId
            }
            "ping" -> {
                jsonRpcResultResponse(rpcId, JSONObject()) to incomingSessionId
            }
            "tools/list" -> {
                val listObj = buildFilteredToolsList(authRes)
                jsonRpcResultResponse(rpcId, listObj) to incomingSessionId
            }
            "resources/list" -> {
                val resList = JSONObject().put(
                    "resources",
                    JSONArray().put(
                        JSONObject()
                            .put("uri", TOPOLOGY_RESOURCE_URI)
                            .put("name", "SNOW Mesh Topology")
                            .put("description", "Live read-only view of this device and reachable same-network SNOW peers (redacted).")
                            .put("mimeType", "application/json")
                    )
                )
                jsonRpcResultResponse(rpcId, resList) to incomingSessionId
            }
            "resources/read" -> handleResourcesRead(rpcId, params) to incomingSessionId
            "tools/call" -> handleToolsCall(rpcId, params, authRes) to incomingSessionId
            else -> jsonRpcErrorResponse(200, rpcId ?: JSONObject.NULL, -32601, "Method not found: $rpcMethod") to incomingSessionId
        }

        val baseResp = responsePair.first
        if (baseResp.body.size > MAX_MCP_RESPONSE_BYTES) {
            return jsonRpcErrorResponse(413, rpcId ?: JSONObject.NULL, -32603, "MCP response exceeded 512 KiB size cap.")
        }
        val sessIdHeader = responsePair.second
        if (sessIdHeader.isNullOrEmpty()) return baseResp
        val mergedHeaders = LinkedHashMap(baseResp.headers).apply {
            put("Mcp-Session-Id", sessIdHeader)
        }
        return McpHttpResponse(status = baseResp.status, headers = mergedHeaders, body = baseResp.body)
    }

    private fun handleInitialize(
        rpcId: Any?,
        params: JSONObject,
        authRes: TokenValidationResult
    ): Pair<McpHttpResponse, String?> {
        val requestedVer = params.optString("protocolVersion", "2025-11-25").trim()
        val negotiated = if (requestedVer in SUPPORTED_PROTOCOL_VERSIONS) requestedVer else "2025-11-25"
        val now = clockMs()
        pruneSessions(now)
        val newSessionId = "mcp_and_" + AndroidOAuthManager.randomToken(24)
        sessions[newSessionId] = McpSession(
            sessionId = newSessionId,
            clientId = authRes.clientId!!,
            familyId = authRes.familyId!!,
            protocolVersion = negotiated,
            createdAtMs = now,
            lastSeenMs = now
        )
        val result = JSONObject()
            .put("protocolVersion", negotiated)
            .put(
                "capabilities",
                JSONObject()
                    .put("tools", JSONObject().put("listChanged", false))
                    .put("resources", JSONObject().put("listChanged", false))
            )
            .put(
                "serverInfo",
                JSONObject()
                    .put("name", "SNOW Android Native MCP")
                    .put("version", "7.0.0")
                    .put("device_snow_id", localSnowIdProvider())
            )
        return jsonRpcResultResponse(rpcId, result) to newSessionId
    }

    private fun buildFilteredToolsList(authRes: TokenValidationResult): JSONObject {
        val peers = peerDirectoryProvider()
        val hasOnlineWindows = peers.any { it.isOnline && it.deviceType.equals("windows", ignoreCase = true) }
        val arr = JSONArray()

        for (spec in localTools) {
            if (spec.requiredScope !in authRes.scopes) continue
            if (spec.targetKind == "android" && !localCapabilityDispatcher.isActionAllowedByProfile(spec.wireAction)) {
                continue
            }
            if (spec.targetKind == "windows" && !hasOnlineWindows) {
                continue
            }
            arr.put(
                JSONObject()
                    .put("name", spec.name)
                    .put("description", spec.description)
                    .put("inputSchema", spec.schemaJson)
                    .put(
                        "annotations",
                        JSONObject()
                            .put("readOnlyHint", spec.readOnlyHint)
                            .put("destructiveHint", spec.destructiveHint)
                    )
            )
        }
        return JSONObject().put("tools", arr)
    }

    private fun handleResourcesRead(rpcId: Any?, params: JSONObject): McpHttpResponse {
        val uri = params.optString("uri", "").trim()
        if (uri != TOPOLOGY_RESOURCE_URI) {
            return jsonRpcErrorResponse(200, rpcId ?: JSONObject.NULL, -32602, "Unknown resource URI: $uri")
        }
        val topology = buildRedactedTopologyJson()
        val contentArr = JSONArray().put(
            JSONObject()
                .put("uri", TOPOLOGY_RESOURCE_URI)
                .put("mimeType", "application/json")
                .put("text", topology.toString(2))
        )
        return jsonRpcResultResponse(rpcId, JSONObject().put("contents", contentArr))
    }

    private suspend fun handleToolsCall(
        rpcId: Any?,
        params: JSONObject,
        authRes: TokenValidationResult
    ): McpHttpResponse {
        val toolName = params.optString("name", "").trim()
        val argsObj = params.optJSONObject("arguments") ?: JSONObject()
        val argsMap = jsonObjectToMap(argsObj).toMutableMap()

        // Strip caller authority spoofing attempts
        argsMap.remove("principal")
        argsMap.remove("trust_tier")
        argsMap.remove("execution_principal")
        argsMap.remove("origin_device_id")
        argsMap.remove("origin_snow_id")

        if (toolName == "snow_mesh_peers") {
            val topo = buildRedactedTopologyJson()
            recordAudit(authRes.clientId!!, "snow_mesh_peers", localDeviceIdProvider(), "SUCCESS")
            return toolSuccessResult(rpcId, topo)
        }

        val spec = localTools.firstOrNull { it.name == toolName }
            ?: return jsonRpcErrorResponse(200, rpcId ?: JSONObject.NULL, -32601, "Unknown MCP tool '$toolName'.")

        // Independent re-validation: OAuth scope check
        if (spec.requiredScope !in authRes.scopes) {
            recordAudit(authRes.clientId!!, toolName, localDeviceIdProvider(), "INSUFFICIENT_SCOPE")
            val (issuer, _, _) = oauthManager.resolveIssuerAndResource()
            return McpHttpResponse.json(
                403,
                JSONObject()
                    .put("error", "insufficient_scope")
                    .put("error_description", "Bearer token lacks required scope '${spec.requiredScope}' for '$toolName'."),
                mapOf("WWW-Authenticate" to "Bearer error=\"insufficient_scope\", scope=\"${spec.requiredScope}\", resource_metadata=\"$issuer/.well-known/oauth-protected-resource\"")
            )
        }

        // Resolve target cleanly (never silently fall back to another device)
        val requestedTarget = (argsMap["device_id"] as? String)?.trim()?.takeIf { it.isNotEmpty() }
            ?: (argsMap["target_device_id"] as? String)?.trim()?.takeIf { it.isNotEmpty() }

        val localId = localDeviceIdProvider().trim()
        val localSnow = localSnowIdProvider().trim().uppercase(Locale.ROOT)
        val isTargetingLocal = if (spec.targetKind == "windows") {
            false
        } else {
            requestedTarget == null ||
                requestedTarget.equals(localId, ignoreCase = true) ||
                requestedTarget.equals(localSnow, ignoreCase = true)
        }

        if (isTargetingLocal) {
            return executeLocalAndroidTool(rpcId, spec, argsMap, authRes)
        }

        return executeRemotePeerTool(rpcId, spec, requestedTarget, argsMap, authRes)
    }

    private suspend fun executeLocalAndroidTool(
        rpcId: Any?,
        spec: ToolSpec,
        rawArgs: MutableMap<String, Any?>,
        authRes: TokenValidationResult
    ): McpHttpResponse {
        val targetId = localDeviceIdProvider().trim()
        // Enforce 5-tier AI_MCP permission profile independently
        if (!localCapabilityDispatcher.isActionAllowedByProfile(spec.wireAction)) {
            recordAudit(authRes.clientId!!, spec.name, targetId, "PERMISSION_DENIED")
            return toolErrorResult(
                rpcId = rpcId,
                status = "PERMISSION_DENIED",
                error = "Tool '${spec.name}' is blocked by active Android permission profile '${localCapabilityDispatcher.activePermissionProfile}'."
            )
        }

        // Enforce owner approval gate for sensitive/write tools when caller lacks consumed approval_id
        val sanitizedParams = LinkedHashMap<String, Any?>()
        for ((k, v) in rawArgs) {
            if (k == "approval_id" || k in BLOCKED_CROSS_NETWORK_FIELDS) continue
            if (k == "content" || k == "text") {
                sanitizedParams[k] = "<${v?.toString()?.length ?: 0} chars>"
            } else {
                sanitizedParams[k] = v
            }
        }
        val paramsHash = AndroidOAuthManager.sha256Hex(JSONObject(sanitizedParams).toString())

        if (spec.requiresApproval) {
            val approvalId = (rawArgs["approval_id"] as? String)?.trim().orEmpty()
            if (approvalId.isEmpty()) {
                val now = clockMs()
                val reqId = "mcp_appr_" + AndroidOAuthManager.randomToken(12)
                val rec = PendingApprovalRecord(
                    requestId = reqId,
                    clientId = authRes.clientId!!,
                    clientName = authRes.clientName ?: "AI Client",
                    toolName = spec.name,
                    action = spec.wireAction,
                    targetDeviceId = localSnowIdProvider(),
                    riskLevel = spec.riskLevel,
                    reason = "${authRes.clientName ?: "AI Client"} requested '${spec.name}' on local Android device.",
                    paramsHash = paramsHash,
                    sanitizedSummary = sanitizedParams,
                    createdAtMs = now,
                    expiresAtMs = now + APPROVAL_TTL_MS
                )
                approvals[reqId] = rec
                val snap = rec.toSnapshot()
                onPendingToolApprovalsChanged?.invoke(listPendingToolApprovals())
                onToolApprovalNotification?.invoke(snap)
                recordAudit(authRes.clientId, spec.name, targetId, "APPROVAL_REQUIRED")
                return toolErrorResult(
                    rpcId = rpcId,
                    status = "APPROVAL_REQUIRED",
                    error = "Action '${spec.name}' requires explicit owner approval on Android.",
                    extraData = mapOf("approval_request_id" to reqId)
                )
            } else {
                val rec = approvals[approvalId]
                val now = clockMs()
                val ok = if (rec != null) {
                    synchronized(rec) {
                        val valid = rec.approved &&
                            !rec.rejected &&
                            !rec.consumed &&
                            now <= rec.expiresAtMs &&
                            rec.clientId == authRes.clientId &&
                            rec.action == spec.wireAction &&
                            rec.paramsHash == paramsHash
                        if (valid) rec.consumed = true
                        valid
                    }
                } else false
                if (!ok) {
                    recordAudit(authRes.clientId!!, spec.name, targetId, "APPROVAL_REJECTED")
                    return toolErrorResult(
                        rpcId = rpcId,
                        status = "UNAUTHORIZED",
                        error = "Invalid, expired, unapproved, or mismatched approval_id."
                    )
                }
            }
        }

        // Re-check right before execution that client wasn't revoked and MCP is enabled
        if (!remoteMcpEnabledProvider()) {
            return toolErrorResult(rpcId, "SERVICE_DISABLED", "Android Remote MCP was disabled.")
        }

        val dispatched = withTimeoutOrNull(TOOL_TIMEOUT_MS) {
            if (localActionExecutor != null) {
                localActionExecutor.invoke(spec.wireAction, rawArgs)
            } else {
                localCapabilityDispatcher.dispatch(spec.wireAction, rawArgs)
            }
        }
        if (dispatched == null) {
            recordAudit(authRes.clientId!!, spec.name, targetId, "TIMEOUT")
            return toolErrorResult(rpcId, "TIMEOUT", "Android capability '${spec.name}' timed out after ${TOOL_TIMEOUT_MS}ms.")
        }

        val (resMap, err) = dispatched
        if (err != null) {
            val errStatus = err.message.substringBefore(':').trim().takeIf {
                it.matches(Regex("^[A-Z0-9_]{3,40}$"))
            } ?: err.code
            recordAudit(authRes.clientId!!, spec.name, targetId, errStatus)
            return toolErrorResult(rpcId, errStatus, err.message)
        }
        val outMap = resMap ?: emptyMap()
        val ok = outMap["status"] == "success" || outMap["success"] == true
        recordAudit(authRes.clientId!!, spec.name, targetId, if (ok) "SUCCESS" else (outMap["status"]?.toString() ?: "ERROR"))
        return if (ok) {
            toolSuccessResult(rpcId, mapToJsonObject(outMap))
        } else {
            toolErrorResult(
                rpcId = rpcId,
                status = (outMap["status"] ?: outMap["error"] ?: "ERROR").toString(),
                error = (outMap["error"] ?: outMap["message"] ?: "Capability failed.").toString(),
                extraData = outMap
            )
        }
    }

    private suspend fun executeRemotePeerTool(
        rpcId: Any?,
        spec: ToolSpec,
        requestedTarget: String?,
        rawArgs: MutableMap<String, Any?>,
        authRes: TokenValidationResult
    ): McpHttpResponse {
        val peers = peerDirectoryProvider()
        val resolvedPeer = if (requestedTarget != null) {
            peers.firstOrNull {
                it.deviceId.equals(requestedTarget, ignoreCase = true) ||
                    (it.snowId.isNotBlank() && it.snowId.equals(requestedTarget, ignoreCase = true))
            }
        } else {
            // Explicit Windows tool without device_id: resolve strictly if exactly one Windows PC peer exists in network
            val winPeers = peers.filter { it.deviceType.equals("windows", ignoreCase = true) }
            if (winPeers.size == 1) winPeers.first() else null
        }

        if (resolvedPeer == null) {
            recordAudit(authRes.clientId!!, spec.name, requestedTarget ?: "unknown", "DEVICE_NOT_FOUND")
            return toolErrorResult(
                rpcId = rpcId,
                status = "DEVICE_NOT_FOUND",
                error = "Target device '${requestedTarget ?: "windows"}' is not paired on this network."
            )
        }

        val localNet = localNetworkIdProvider()?.trim()?.uppercase(Locale.ROOT).orEmpty()
        val peerNet = resolvedPeer.networkId.trim().uppercase(Locale.ROOT)
        if (resolvedPeer.isFederated || (localNet.isNotEmpty() && peerNet.isNotEmpty() && localNet != peerNet)) {
            if ("snow:mesh" !in authRes.scopes) {
                recordAudit(authRes.clientId!!, spec.name, resolvedPeer.deviceId, "CROSS_NETWORK_FORBIDDEN")
                return toolErrorResult(
                    rpcId = rpcId,
                    status = "PERMISSION_DENIED",
                    error = "Cross-network routing requires 'snow:mesh' OAuth scope and explicit federation."
                )
            }
        }

        if (!resolvedPeer.isOnline) {
            recordAudit(authRes.clientId!!, spec.name, resolvedPeer.deviceId, "DEVICE_OFFLINE")
            return toolErrorResult(
                rpcId = rpcId,
                status = "DEVICE_OFFLINE",
                error = "Target device '${resolvedPeer.deviceId}' is offline; SNOW will not silently route to another device."
            )
        }

        val forwarder = peerActionForwarder ?: run {
            recordAudit(authRes.clientId!!, spec.name, resolvedPeer.deviceId, "ROUTING_UNAVAILABLE")
            return toolErrorResult(
                rpcId = rpcId,
                status = "ROUTING_UNAVAILABLE",
                error = "Peer transport forwarder is unavailable."
            )
        }

        val forwardParams = LinkedHashMap<String, Any?>()
        for ((k, v) in rawArgs) {
            if (k in BLOCKED_CROSS_NETWORK_FIELDS) continue
            forwardParams[k] = v
        }

        val (peerResp, peerErr) = withTimeoutOrNull(TOOL_TIMEOUT_MS) {
            forwarder.invoke(resolvedPeer.deviceId, spec.wireAction, forwardParams, authRes.clientId!!)
        } ?: (null to "Peer execution timed out.")

        if (peerErr != null || peerResp == null) {
            val status = when {
                peerErr?.contains("PERMISSION_DENIED", ignoreCase = true) == true ||
                    peerErr?.contains("UNAUTHORIZED", ignoreCase = true) == true -> "PERMISSION_DENIED"
                peerErr?.contains("OFFLINE", ignoreCase = true) == true ||
                    peerErr?.contains("UNREACHABLE", ignoreCase = true) == true -> "DEVICE_OFFLINE"
                else -> "PEER_EXECUTION_FAILED"
            }
            recordAudit(authRes.clientId!!, spec.name, resolvedPeer.deviceId, status)
            return toolErrorResult(rpcId, status, peerErr ?: "Peer request failed.")
        }

        val ok = peerResp["success"] == true || peerResp["status"] == "success"
        recordAudit(authRes.clientId!!, spec.name, resolvedPeer.deviceId, if (ok) "SUCCESS" else (peerResp["status"]?.toString() ?: "ERROR"))
        return if (ok) {
            toolSuccessResult(rpcId, mapToJsonObject(peerResp))
        } else {
            toolErrorResult(
                rpcId = rpcId,
                status = (peerResp["status"] ?: "ERROR").toString(),
                error = (peerResp["error"] ?: "Peer capability denied or failed.").toString(),
                extraData = peerResp
            )
        }
    }

    private fun buildRedactedTopologyJson(): JSONObject {
        val localObj = JSONObject()
            .put("device_id", localDeviceIdProvider())
            .put("snow_id", localSnowIdProvider())
            .put("device_name", localDeviceNameProvider())
            .put("device_type", "android")
            .put("network_id", localNetworkIdProvider() ?: JSONObject.NULL)
            .put("permission_profile", localCapabilityDispatcher.activePermissionProfile)
            .put("is_online", true)

        val peersArr = JSONArray()
        for (p in peerDirectoryProvider()) {
            peersArr.put(
                JSONObject()
                    .put("device_id", p.deviceId)
                    .put("snow_id", p.snowId)
                    .put("device_name", p.deviceName)
                    .put("device_type", p.deviceType)
                    .put("network_id", p.networkId)
                    .put("is_online", p.isOnline)
                    .put("transport", p.transport)
                    .put("is_federated", p.isFederated)
            )
        }
        return JSONObject()
            .put("local_device", localObj)
            .put("peers", peersArr)
            .put("peer_count", peersArr.length())
    }

    private fun buildToolCatalog(): List<ToolSpec> {
        fun schema(props: JSONObject, required: List<String> = emptyList()): JSONObject =
            JSONObject()
                .put("type", "object")
                .put("properties", props)
                .put("required", JSONArray(required))

        fun strProp(desc: String) = JSONObject().put("type", "string").put("description", desc)
        fun boolProp(desc: String) = JSONObject().put("type", "boolean").put("description", desc)
        fun intProp(desc: String) = JSONObject().put("type", "integer").put("description", desc)

        val targetProp = strProp("Optional target device_id or SNW-XXXX-XXXX on this SNOW network.")
        val approvalProp = strProp("Single-use approval_id after owner approval.")

        return listOf(
            ToolSpec("snow_android_battery", "battery_status", "Read battery telemetry from Android device or peer.", "snow:read", true, false, false, "LOW", "android",
                schema(JSONObject().put("device_id", targetProp))),
            ToolSpec("snow_android_device_info", "android_device_info", "Read Android device model, OS version, RAM, storage, screen lock, and active M4.3 transport.", "snow:read", true, false, false, "LOW", "android",
                schema(JSONObject().put("device_id", targetProp))),
            ToolSpec("snow_android_audio_status", "android_audio_status", "Read Android volume levels, ringer mode, and Do Not Disturb status without modifying audio settings.", "snow:read", true, false, false, "LOW", "android",
                schema(JSONObject().put("device_id", targetProp))),
            ToolSpec("snow_android_clipboard_get", "clipboard_pull", "Read current Android clipboard text strictly when SNOW is in foreground.", "snow:read", true, false, false, "MEDIUM", "android",
                schema(JSONObject().put("device_id", targetProp))),
            ToolSpec("snow_android_clipboard_push", "clipboard_push", "Push text to Android device clipboard.", "snow:write", false, false, false, "LOW", "android",
                schema(JSONObject().put("text", strProp("UTF-8 clipboard text")).put("device_id", targetProp), listOf("text"))),
            ToolSpec("snow_android_file_list", "file_list", "List files inside Android configured SAF folder.", "snow:read", true, false, false, "LOW", "android",
                schema(JSONObject().put("subpath", strProp("Relative folder path")).put("device_id", targetProp))),
            ToolSpec("snow_android_file_read", "android_file_read", "Read a UTF-8 text file (up to 256 KiB) inside Android SAF folder.", "snow:read", true, false, false, "LOW", "android",
                schema(JSONObject().put("path", strProp("Relative SAF file path")).put("device_id", targetProp), listOf("path"))),
            ToolSpec("snow_android_file_write", "android_file_write", "Write a UTF-8 text file (up to 256 KiB) inside Android SAF folder (requires owner approval).", "snow:write", false, true, true, "HIGH", "android",
                schema(JSONObject().put("path", strProp("Relative SAF file path")).put("content", strProp("UTF-8 content")).put("overwrite", boolProp("Overwrite existing file")).put("approval_id", approvalProp).put("device_id", targetProp), listOf("path", "content"))),
            ToolSpec("snow_android_file_search", "android_file_search", "Search filenames inside Android SAF folder with bounded depth and result count.", "snow:read", true, false, false, "LOW", "android",
                schema(JSONObject().put("query", strProp("Case-insensitive filename query")).put("max_results", intProp("Max results (1..50)")).put("max_depth", intProp("Max recursion depth (1..5)")).put("device_id", targetProp), listOf("query"))),
            ToolSpec("snow_android_list_apps", "list_apps", "List launchable whitelisted apps on Android.", "snow:read", true, false, false, "LOW", "android",
                schema(JSONObject().put("limit", intProp("Maximum apps to return")).put("device_id", targetProp))),
            ToolSpec("snow_android_launch_app", "launch_app", "Launch a whitelisted application on Android.", "snow:execute", false, false, true, "MEDIUM", "android",
                schema(JSONObject().put("package_name", strProp("Android package name")).put("approval_id", approvalProp).put("device_id", targetProp), listOf("package_name"))),
            ToolSpec("snow_android_notifications_list", "notifications_list", "List active notifications on Android if Notification Listener is enabled.", "snow:read", true, false, false, "LOW", "android",
                schema(JSONObject().put("device_id", targetProp))),
            ToolSpec("snow_android_dnd_toggle", "android_dnd_toggle", "Toggle Do Not Disturb on Android.", "snow:write", false, false, true, "MEDIUM", "android",
                schema(JSONObject().put("enabled", boolProp("Enable or disable DND")).put("approval_id", approvalProp).put("device_id", targetProp), listOf("enabled"))),
            ToolSpec("snow_android_media_control", "media_control", "Control media playback or volume on Android.", "snow:write", false, false, false, "LOW", "android",
                schema(JSONObject().put("action", strProp("play_pause|next|previous|volume_up|volume_down|mute|volume_set")).put("value", intProp("Optional volume 0..100")).put("device_id", targetProp), listOf("action"))),
            ToolSpec("snow_android_share_link", "share_link", "Share a URL or text note on Android.", "snow:write", false, false, false, "LOW", "android",
                schema(JSONObject().put("url", strProp("HTTP/HTTPS URL")).put("text", strProp("Text note")).put("device_id", targetProp))),
            ToolSpec("snow_android_ring", "ring_phone", "Ring Android device at loud volume to help locate it.", "snow:execute", false, false, false, "LOW", "android",
                schema(JSONObject().put("duration_seconds", intProp("Duration in seconds")).put("device_id", targetProp))),
            ToolSpec("snow_android_notification_dismiss", "notification_dismiss", "Dismiss an Android notification (requires approval).", "snow:write", false, true, true, "MEDIUM", "android",
                schema(JSONObject().put("key", strProp("Notification key")).put("approval_id", approvalProp).put("device_id", targetProp), listOf("key"))),
            ToolSpec("snow_android_notification_reply", "notification_reply", "Reply to an Android notification (requires approval).", "snow:write", false, false, true, "HIGH", "android",
                schema(JSONObject().put("key", strProp("Notification key")).put("text", strProp("Reply message")).put("approval_id", approvalProp).put("device_id", targetProp), listOf("key", "text"))),
            ToolSpec("snow_android_send_message", "send_message", "Compose/send a message on Android (requires approval).", "snow:write", false, false, true, "HIGH", "android",
                schema(JSONObject().put("recipient", strProp("Phone or contact")).put("message", strProp("Message text")).put("approval_id", approvalProp).put("device_id", targetProp), listOf("recipient", "message"))),
            ToolSpec("snow_android_whatsapp_send", "whatsapp_send", "Compose WhatsApp message on Android (requires approval).", "snow:write", false, false, true, "HIGH", "android",
                schema(JSONObject().put("recipient", strProp("Phone/contact")).put("message", strProp("Message text")).put("approval_id", approvalProp).put("device_id", targetProp), listOf("recipient", "message"))),
            ToolSpec("snow_android_screenshot", "android_screenshot", "Capture Android screen with on-device MediaProjection consent.", "snow:read", true, false, false, "MEDIUM", "android",
                schema(JSONObject().put("device_id", targetProp))),
            ToolSpec("snow_android_camera_capture", "android_camera_capture", "Request foreground Android camera photo capture.", "snow:execute", false, false, true, "MEDIUM", "android",
                schema(JSONObject().put("approval_id", approvalProp).put("device_id", targetProp))),
            ToolSpec("snow_mesh_peers", "mesh_list_peers", "List authenticated peers on this SNOW network (credentials redacted).", "snow:read", true, false, false, "LOW", "mesh",
                schema(JSONObject())),
            ToolSpec("snow_windows_system_info", "windows_system_info", "Read Windows PC CPU/RAM/OS telemetry when paired PC is online.", "snow:read", true, false, false, "LOW", "windows",
                schema(JSONObject().put("device_id", targetProp))),
            ToolSpec("snow_windows_battery", "windows_battery", "Read Windows PC battery status when paired PC is online.", "snow:read", true, false, false, "LOW", "windows",
                schema(JSONObject().put("device_id", targetProp))),
            ToolSpec("snow_windows_clipboard_get", "windows_clipboard_get", "Read clipboard text from paired Windows PC when online.", "snow:read", true, false, false, "MEDIUM", "windows",
                schema(JSONObject().put("device_id", targetProp))),
            ToolSpec("snow_windows_clipboard_set", "windows_clipboard_set", "Write clipboard text on paired Windows PC (requires owner approval).", "snow:write", false, false, true, "MEDIUM", "windows",
                schema(JSONObject().put("text", strProp("UTF-8 text")).put("approval_id", approvalProp).put("device_id", targetProp), listOf("text"))),
            ToolSpec("snow_windows_file_list", "windows_file_list", "List allowed workspace directory files on paired Windows PC when online.", "snow:read", true, false, false, "LOW", "windows",
                schema(JSONObject().put("path", strProp("Directory path")).put("device_id", targetProp))),
            ToolSpec("snow_windows_file_read", "windows_file_read", "Read a file inside allowed Windows workspace directory.", "snow:read", true, false, false, "LOW", "windows",
                schema(JSONObject().put("path", strProp("File path")).put("device_id", targetProp), listOf("path"))),
            ToolSpec("snow_windows_file_write", "windows_file_write", "Write a file inside allowed Windows workspace directory (requires approval).", "snow:write", false, true, true, "HIGH", "windows",
                schema(JSONObject().put("path", strProp("File path")).put("content", strProp("File content")).put("approval_id", approvalProp).put("device_id", targetProp), listOf("path", "content")))
        )
    }

    private fun pruneSessions(now: Long) {
        val expired = sessions.entries.filter { (now - it.value.lastSeenMs) > SESSION_TTL_MS }.map { it.key }
        expired.forEach { sessions.remove(it) }
        while (sessions.size > MAX_SESSIONS) {
            val oldest = sessions.entries.minByOrNull { it.value.lastSeenMs }?.key ?: break
            sessions.remove(oldest)
        }
    }

    private fun pruneApprovals(now: Long) {
        val expired = approvals.entries.filter { now > it.value.expiresAtMs }.map { it.key }
        expired.forEach { approvals.remove(it) }
    }

    private fun recordAudit(clientId: String, action: String, targetDeviceId: String, outcome: String) {
        val entry = McpAuditEntry(
            timestampMs = clockMs(),
            clientId = clientId,
            action = action,
            targetDeviceId = targetDeviceId,
            outcome = outcome
        )
        synchronized(auditLog) {
            while (auditLog.size >= 200) {
                auditLog.removeFirst()
            }
            auditLog.addLast(entry)
        }
        SafeLog.i(TAG, "MCP audit client=$clientId action=$action target=$targetDeviceId outcome=$outcome")
    }

    private fun normalizeSubpath(raw: String): String {
        val clean = raw.trim()
        if (clean.isEmpty()) return "/mcp"
        val stripped = clean.substringBefore('?')
        return if (stripped.length > 1) stripped.trimEnd('/') else stripped
    }

    private fun methodNotAllowed(): McpHttpResponse =
        McpHttpResponse.json(405, JSONObject().put("error", "method_not_allowed"))

    private fun jsonRpcResultResponse(rpcId: Any?, result: JSONObject): McpHttpResponse =
        McpHttpResponse.json(
            200,
            JSONObject()
                .put("jsonrpc", "2.0")
                .put("id", rpcId ?: JSONObject.NULL)
                .put("result", result)
        )

    private fun jsonRpcErrorResponse(httpStatus: Int, rpcId: Any?, code: Int, message: String): McpHttpResponse =
        McpHttpResponse.json(
            httpStatus,
            JSONObject()
                .put("jsonrpc", "2.0")
                .put("id", rpcId ?: JSONObject.NULL)
                .put("error", JSONObject().put("code", code).put("message", message))
        )

    private fun toolSuccessResult(rpcId: Any?, obj: JSONObject): McpHttpResponse {
        val res = JSONObject()
            .put("isError", false)
            .put("content", JSONArray().put(JSONObject().put("type", "text").put("text", obj.toString(2))))
        return jsonRpcResultResponse(rpcId, res)
    }

    private fun toolErrorResult(
        rpcId: Any?,
        status: String,
        error: String,
        extraData: Map<String, Any?> = emptyMap()
    ): McpHttpResponse {
        val bodyObj = JSONObject()
            .put("success", false)
            .put("status", status)
            .put("error", error)
        for ((k, v) in extraData) {
            if (k !in BLOCKED_CROSS_NETWORK_FIELDS && !bodyObj.has(k)) {
                bodyObj.put(k, wrapJsonValue(v))
            }
        }
        val res = JSONObject()
            .put("isError", true)
            .put("content", JSONArray().put(JSONObject().put("type", "text").put("text", bodyObj.toString(2))))
        return jsonRpcResultResponse(rpcId, res)
    }

    private fun jsonObjectToMap(obj: JSONObject): Map<String, Any?> {
        val out = linkedMapOf<String, Any?>()
        val keys = obj.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            out[k] = unwrapJsonValue(obj.opt(k))
        }
        return out
    }

    private fun unwrapJsonValue(v: Any?): Any? = when (v) {
        null, JSONObject.NULL -> null
        is JSONObject -> jsonObjectToMap(v)
        is JSONArray -> (0 until v.length()).map { unwrapJsonValue(v.opt(it)) }
        else -> v
    }

    private fun mapToJsonObject(map: Map<String, Any?>): JSONObject {
        val obj = JSONObject()
        for ((k, v) in map) {
            obj.put(k, wrapJsonValue(v))
        }
        return obj
    }

    private fun wrapJsonValue(v: Any?): Any = when (v) {
        null -> JSONObject.NULL
        is JSONObject, is JSONArray, is Boolean, is Number, is String -> v
        is Map<*, *> -> {
            val o = JSONObject()
            for ((mk, mv) in v) {
                if (mk != null) o.put(mk.toString(), wrapJsonValue(mv))
            }
            o
        }
        is Iterable<*> -> JSONArray().apply { v.forEach { put(wrapJsonValue(it)) } }
        is Array<*> -> JSONArray().apply { v.forEach { put(wrapJsonValue(it)) } }
        else -> v.toString()
    }
}
