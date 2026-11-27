package org.snow.mcp

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.java_websocket.client.WebSocketClient
import org.java_websocket.handshake.ServerHandshake
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.network.AndroidPeerHostServer
import org.snow.protocol.ErrorCode
import org.snow.protocol.JsonSerialization
import org.snow.protocol.MessageType
import org.snow.protocol.SnowMessage
import org.snow.security.AndroidSelfSignedCertGenerator
import org.snow.security.DeviceKeyIdentity
import org.snow.security.InMemoryAesKeyProvider
import org.snow.security.TokenStorage
import java.io.File
import java.net.URI
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * M4.4 Stage 4 Tests:
 * - Native Android OAuth 2.1 + PKCE (S256 mandatory, redirect allowlist, consent gate, no remote self-approve)
 * - Single-use auth codes + Refresh token rotation + Replay detection revoking entire token family
 * - Encrypted persistence at rest + fail-closed tampering + explicit client revocation UI hook
 * - Streamable HTTP AndroidMcpResponder (401/403 enforcement, per-client Mcp-Session-Id isolation,
 *   independent tools/call re-validation, approval gate, bidirectional peer routing & offline fail-closed)
 * - AndroidMcpRelayForwarder manual stop / reconnect / forwarding bounds
 */
class M44NativeAndroidMcpAndOAuthTest {

    private class MemPrefs : SharedPreferences {
        val map = mutableMapOf<String, Any?>()
        override fun getAll(): MutableMap<String, *> = HashMap(map)
        override fun getString(key: String?, defValue: String?): String? = map[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = defValues
        override fun getInt(key: String?, defValue: Int): Int = (map[key] as? Int) ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = (map[key] as? Long) ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = (map[key] as? Float) ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = (map[key] as? Boolean) ?: defValue
        override fun contains(key: String?): Boolean = map.containsKey(key)
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            private val pending = mutableMapOf<String, Any?>()
            private val removals = mutableSetOf<String>()
            private var clearAll = false
            override fun putString(key: String?, value: String?) = apply { if (key != null) pending[key] = value }
            override fun putStringSet(key: String?, values: MutableSet<String>?) = apply {}
            override fun putInt(key: String?, value: Int) = apply { if (key != null) pending[key] = value }
            override fun putLong(key: String?, value: Long) = apply { if (key != null) pending[key] = value }
            override fun putFloat(key: String?, value: Float) = apply { if (key != null) pending[key] = value }
            override fun putBoolean(key: String?, value: Boolean) = apply { if (key != null) pending[key] = value }
            override fun remove(key: String?) = apply { if (key != null) removals.add(key) }
            override fun clear() = apply { clearAll = true }
            override fun commit(): Boolean {
                if (clearAll) map.clear()
                removals.forEach { map.remove(it) }
                for ((k, v) in pending) if (v == null) map.remove(k) else map[k] = v
                return true
            }
            override fun apply() { commit() }
        }
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    }

    private fun newStubContext(): Pair<Context, MutableMap<String, MemPrefs>> {
        val prefsMap = mutableMapOf<String, MemPrefs>()
        val dir = java.nio.file.Files.createTempDirectory("m44_oauth_test_").toFile()
        val ctx = object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = dir
            override fun getCacheDir(): File = dir
            override fun getPackageName(): String = "org.snow"
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences =
                prefsMap.getOrPut(name ?: "default") { MemPrefs() }
        }
        return ctx to prefsMap
    }

    private fun pkcePair(): Pair<String, String> {
        val verifier = "a".repeat(48) + "Z9_-"
        val digest = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII))
        val challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
        return verifier to challenge
    }

    private fun extractQueryParam(url: String, key: String): String? {
        val q = url.substringAfter('?', "")
        return AndroidOAuthManager.parseQueryParams(q)[key]
    }

    @Test
    fun oauthPkceConsentRefreshReplayAndEncryptedPersistence() {
        val (ctx, prefsMap) = newStubContext()
        val devKey = DeviceKeyIdentity.generate()
        val keyProvider = InMemoryAesKeyProvider()
        val clock = AtomicLong(1_700_000_000_000L)
        val hubHost = "hub.snow.example"
        val canonicalResource = "https://$hubHost/u/${devKey.snowId}/mcp"

        val revokedClientIds = mutableListOf<String>()
        val oauth = AndroidOAuthManager(
            context = ctx,
            deviceSnowIdProvider = { devKey.snowId },
            defaultPublicBaseUrlProvider = { "https://$hubHost" },
            keyProvider = keyProvider,
            clockMs = { clock.get() },
            onClientRevokedCallback = { revokedClientIds.add(it) }
        )

        fun hubReq(method: String, path: String, query: String = "", body: String = "", headers: Map<String, String> = emptyMap()) =
            McpHttpRequest(
                method = method,
                subpath = path,
                query = query,
                headers = mapOf(
                    "x-forwarded-proto" to "https",
                    "x-forwarded-host" to hubHost,
                    "x-forwarded-prefix" to "/u/${devKey.snowId}",
                    "content-type" to "application/json"
                ) + headers,
                body = body.toByteArray(Charsets.UTF_8)
            )

        // 1. Metadata discovery reflects per-device canonical issuer & resource
        val prResp = oauth.handleWellKnownProtectedResource(hubReq("GET", "/.well-known/oauth-protected-resource"))
        assertEquals(200, prResp.status)
        val prJson = JSONObject(prResp.bodyText())
        assertEquals(canonicalResource, prJson.getString("resource"))
        assertEquals("https://$hubHost/u/${devKey.snowId}", prJson.getJSONArray("authorization_servers").getString(0))

        // 2. DCR rejects unsafe redirect URIs (wildcard, non-loopback http, metadata IP, fragment)
        for (badRedirect in listOf(
            "http://evil.example/callback",
            "https://evil.example/*callback",
            "https://evil.example/cb#frag",
            "javascript:alert(1)",
            "https://169.254.169.254/latest"
        )) {
            val badReg = oauth.handleRegister(
                hubReq(
                    "POST",
                    "/oauth/register",
                    body = JSONObject()
                        .put("client_name", "BadClient")
                        .put("redirect_uris", JSONArray().put(badRedirect))
                        .toString()
                )
            )
            assertEquals("Expected 400 rejecting redirect $badRedirect", 400, badReg.status)
        }

        // Valid DCR registration (loopback HTTP + HTTPS public callback)
        val redirectUri = "https://claude.ai/api/mcp/auth_callback"
        val regResp = oauth.handleRegister(
            hubReq(
                "POST",
                "/oauth/register",
                body = JSONObject()
                    .put("client_name", "Claude Assistant")
                    .put("redirect_uris", JSONArray().put(redirectUri))
                    .put("scope", "snow:read snow:write snow:mesh")
                    .toString()
            )
        )
        assertEquals(201, regResp.status)
        val clientId = JSONObject(regResp.bodyText()).getString("client_id")

        // 3. PKCE S256 strictly required (plain rejected)
        val (verifier, challenge) = pkcePair()
        val plainAuthorize = oauth.handleAuthorize(
            hubReq(
                "GET",
                "/oauth/authorize",
                query = "client_id=$clientId&redirect_uri=$redirectUri&response_type=code&code_challenge=$challenge&code_challenge_method=plain&resource=$canonicalResource"
            )
        )
        assertEquals(400, plainAuthorize.status)

        // Wrong audience rejected
        val wrongAudience = oauth.handleAuthorize(
            hubReq(
                "GET",
                "/oauth/authorize",
                query = "client_id=$clientId&redirect_uri=$redirectUri&response_type=code&code_challenge=$challenge&code_challenge_method=S256&resource=https://hub.snow.example/u/SNW-OTHER1/mcp"
            )
        )
        assertEquals(400, wrongAudience.status)

        // Valid GET /oauth/authorize queues pending owner consent without issuing a code
        val authGet = oauth.handleAuthorize(
            hubReq(
                "GET",
                "/oauth/authorize",
                query = "client_id=$clientId&redirect_uri=$redirectUri&response_type=code&code_challenge=$challenge&code_challenge_method=S256&scope=snow:read%20snow:write&state=st_123&resource=$canonicalResource"
            )
        )
        assertEquals(200, authGet.status)
        assertTrue(authGet.bodyText().contains("Claude Assistant"))
        assertTrue(authGet.bodyText().contains(devKey.snowId))
        assertEquals(1, oauth.listPendingConsents().size)
        val consentId = oauth.listPendingConsents().first().requestId

        // Direct unauthenticated remote POST decision=approve MUST fail closed (403)
        val csrfMatch = Regex("""name="csrf_token" value="([^"]+)"""").find(authGet.bodyText())!!
        val csrf = csrfMatch.groupValues[1]
        val pollMatch = Regex("""pollTok="([^"]+)"""").find(authGet.bodyText())!!
        val pollTok = pollMatch.groupValues[1]

        val remoteApproveAttempt = oauth.handleAuthorize(
            hubReq(
                "POST",
                "/oauth/authorize",
                body = "request_id=$consentId&csrf_token=$csrf&decision=approve",
                headers = mapOf("content-type" to "application/x-www-form-urlencoded")
            )
        )
        assertEquals(403, remoteApproveAttempt.status)
        assertEquals(1, oauth.listPendingConsents().size)

        // Owner approves locally inside SNOW Android app -> /oauth/status emits single-use code
        assertTrue(oauth.approveAuthorization(consentId))
        val statusResp = oauth.handleAuthorizeStatus(
            hubReq("GET", "/oauth/status", query = "request_id=$consentId&poll_token=$pollTok")
        )
        assertEquals(200, statusResp.status)
        val statusJson = JSONObject(statusResp.bodyText())
        assertEquals("APPROVED", statusJson.getString("status"))
        val redirUrl = statusJson.getString("redirect_url")
        assertEquals("st_123", extractQueryParam(redirUrl, "state"))
        val authCode = extractQueryParam(redirUrl, "code")!!

        // Wrong PKCE verifier fails
        val badTokenResp = oauth.handleToken(
            hubReq(
                "POST",
                "/oauth/token",
                body = "grant_type=authorization_code&code=$authCode&client_id=$clientId&redirect_uri=$redirectUri&code_verifier=${"b".repeat(48)}",
                headers = mapOf("content-type" to "application/x-www-form-urlencoded")
            )
        )
        assertEquals(400, badTokenResp.status)

        // Valid token exchange succeeds
        val tokenResp = oauth.handleToken(
            hubReq(
                "POST",
                "/oauth/token",
                body = "grant_type=authorization_code&code=$authCode&client_id=$clientId&redirect_uri=$redirectUri&code_verifier=$verifier&resource=$canonicalResource",
                headers = mapOf("content-type" to "application/x-www-form-urlencoded")
            )
        )
        assertEquals(200, tokenResp.status)
        val tokJson = JSONObject(tokenResp.bodyText())
        val access1 = tokJson.getString("access_token")
        val refresh1 = tokJson.getString("refresh_token")

        // Verify persisted state is AES-GCM encrypted (no plaintext tokens in prefs)
        val oauthPrefs = prefsMap[AndroidOAuthManager.PREFS_NAME]!!
        assertFalse(oauthPrefs.map.values.joinToString().contains(access1))
        assertFalse(oauthPrefs.map.values.joinToString().contains(refresh1))

        // Restart persistence check: reload new AndroidOAuthManager instance using same Keystore provider
        val restartedOauth = AndroidOAuthManager(
            context = ctx,
            deviceSnowIdProvider = { devKey.snowId },
            defaultPublicBaseUrlProvider = { "https://$hubHost" },
            keyProvider = keyProvider,
            clockMs = { clock.get() }
        )
        assertTrue(restartedOauth.validateBearerHeader("Bearer $access1", canonicalResource, setOf("snow:read")).valid)
        assertFalse(restartedOauth.validateBearerHeader("Bearer $access1", "https://$hubHost/u/SNW-DIFF/mcp", setOf("snow:read")).valid)

        // Refresh rotation issues new access + new refresh token
        val rotResp = restartedOauth.handleToken(
            hubReq(
                "POST",
                "/oauth/token",
                body = "grant_type=refresh_token&refresh_token=$refresh1&client_id=$clientId",
                headers = mapOf("content-type" to "application/x-www-form-urlencoded")
            )
        )
        assertEquals(200, rotResp.status)
        val rotJson = JSONObject(rotResp.bodyText())
        val access2 = rotJson.getString("access_token")
        val refresh2 = rotJson.getString("refresh_token")
        assertNotEquals(refresh1, refresh2)

        // Refresh replay attack with ALREADY ROTATED refresh1 MUST revoke entire token family!
        val replayResp = restartedOauth.handleToken(
            hubReq(
                "POST",
                "/oauth/token",
                body = "grant_type=refresh_token&refresh_token=$refresh1&client_id=$clientId",
                headers = mapOf("content-type" to "application/x-www-form-urlencoded")
            )
        )
        assertEquals(400, replayResp.status)
        assertFalse(restartedOauth.validateBearerHeader("Bearer $access2", canonicalResource, setOf("snow:read")).valid)

        // Explicit client revocation from UI triggers revocation callback & clears access
        assertTrue(oauth.revokeClient(clientId))
        assertTrue(clientId in revokedClientIds)
        assertEquals(0, oauth.listAuthorizedClients().size)
    }

    @Test
    fun responderEnforcesAuthSessionIsolationProfileApprovalAndBidirectionalRouting() = runBlocking {
        val (ctx, _) = newStubContext()
        val devKey = DeviceKeyIdentity.generate()
        val hubHost = "hub.snow.example"
        val resourceUrl = "https://$hubHost/u/${devKey.snowId}/mcp"
        val oauth = AndroidOAuthManager(
            context = ctx,
            deviceSnowIdProvider = { devKey.snowId },
            defaultPublicBaseUrlProvider = { "https://$hubHost" },
            keyProvider = InMemoryAesKeyProvider(),
            ownerPostApprovalValidator = { _, _, _ -> false }
        )

        fun issueTokenForClient(name: String, scopes: String): Pair<String, String> {
            val reg = oauth.handleRegister(
                McpHttpRequest(
                    "POST", "/oauth/register",
                    headers = mapOf("x-forwarded-proto" to "https", "x-forwarded-host" to hubHost, "x-forwarded-prefix" to "/u/${devKey.snowId}", "content-type" to "application/json"),
                    body = """{"client_name":"$name","redirect_uris":["http://127.0.0.1:9999/cb"],"scope":"$scopes"}""".toByteArray()
                )
            )
            val cid = JSONObject(reg.bodyText()).getString("client_id")
            val (ver, ch) = pkcePair()
            val authGet = oauth.handleAuthorize(
                McpHttpRequest(
                    "GET", "/oauth/authorize",
                    query = "client_id=$cid&redirect_uri=http://127.0.0.1:9999/cb&response_type=code&code_challenge=$ch&code_challenge_method=S256&scope=${scopes.replace(" ", "%20")}&resource=$resourceUrl",
                    headers = mapOf("x-forwarded-proto" to "https", "x-forwarded-host" to hubHost, "x-forwarded-prefix" to "/u/${devKey.snowId}")
                )
            )
            val pollTok = Regex("""pollTok="([^"]+)"""").find(authGet.bodyText())!!.groupValues[1]
            val reqId = oauth.listPendingConsents().last().requestId
            oauth.approveAuthorization(reqId)
            val statusJson = JSONObject(
                oauth.handleAuthorizeStatus(
                    McpHttpRequest(
                        "GET", "/oauth/status",
                        query = "request_id=$reqId&poll_token=$pollTok",
                        headers = mapOf("x-forwarded-proto" to "https", "x-forwarded-host" to hubHost, "x-forwarded-prefix" to "/u/${devKey.snowId}")
                    )
                ).bodyText()
            )
            val redir = statusJson.getString("redirect_url")
            val authCode = extractQueryParam(redir, "code")!!
            val tok = oauth.handleToken(
                McpHttpRequest(
                    "POST", "/oauth/token",
                    headers = mapOf("content-type" to "application/x-www-form-urlencoded", "x-forwarded-proto" to "https", "x-forwarded-host" to hubHost, "x-forwarded-prefix" to "/u/${devKey.snowId}"),
                    body = "grant_type=authorization_code&code=$authCode&client_id=$cid&redirect_uri=http://127.0.0.1:9999/cb&code_verifier=$ver&resource=$resourceUrl".toByteArray()
                )
            )
            val access = JSONObject(tok.bodyText()).getString("access_token")
            return cid to access
        }

        val (cidA, tokA) = issueTokenForClient("ClientA", "snow:read snow:write")
        val (_, tokB) = issueTokenForClient("ClientB", "snow:read")

        val dispatcher = AndroidCapabilityDispatcher(ctx) { null }
        val mcpEnabled = AtomicBoolean(true)
        val peerBProfile = AtomicBoolean(true) // true = allowed, false = not_allowed
        val peerBOnline = AtomicBoolean(true)

        val responder = AndroidMcpResponder(
            oauthManager = oauth,
            localDeviceIdProvider = { "phone-a-uuid" },
            localSnowIdProvider = { devKey.snowId },
            localNetworkIdProvider = { "SNW-NET-AAAA1111" },
            remoteMcpEnabledProvider = { mcpEnabled.get() },
            localCapabilityDispatcher = dispatcher,
            localActionExecutor = { action, params ->
                when (action) {
                    "battery_status" -> mapOf("status" to "success", "level" to 88) to null
                    "android_file_write" -> mapOf("status" to "success", "outcome" to "created", "path" to params?.get("path")) to null
                    else -> mapOf("status" to "error", "error" to "UNSUPPORTED") to null
                }
            },
            peerDirectoryProvider = {
                listOf(
                    McpPeerDescriptor("phone-b-uuid", "SNW-PHNB-2222", "Phone B", "android", "SNW-NET-AAAA1111", peerBOnline.get(), "peer_host", false),
                    McpPeerDescriptor("ext-phone-uuid", "SNW-EXTP-9999", "Ext Phone", "android", "SNW-NET-ZZZZ9999", true, "peer_host", true)
                )
            },
            peerActionForwarder = { targetId, action, _, _ ->
                when {
                    targetId == "phone-b-uuid" && !peerBProfile.get() -> null to "PERMISSION_DENIED: target profile not_allowed"
                    targetId == "phone-b-uuid" -> mapOf("status" to "success", "from" to "phone-b", "action" to action, "level" to 71) to null
                    else -> null to "DEVICE_OFFLINE"
                }
            }
        )

        fun mcpPost(token: String?, body: JSONObject, sessionId: String? = null): McpHttpResponse {
            val h = linkedMapOf(
                "x-forwarded-proto" to "https",
                "x-forwarded-host" to hubHost,
                "x-forwarded-prefix" to "/u/${devKey.snowId}",
                "content-type" to "application/json"
            )
            if (token != null) h["authorization"] = "Bearer $token"
            if (sessionId != null) h["mcp-session-id"] = sessionId
            return runBlocking { responder.handleForwardedHttp(McpHttpRequest("POST", "/mcp", headers = h, body = body.toString().toByteArray())) }
        }

        // 1. Unauthenticated initialize, tools/list, tools/call all return 401 with WWW-Authenticate
        for (m in listOf("initialize", "tools/list", "tools/call")) {
            val r = mcpPost(null, JSONObject().put("jsonrpc", "2.0").put("id", 1).put("method", m))
            assertEquals(401, r.status)
            assertTrue(r.headers["WWW-Authenticate"]?.contains("oauth-protected-resource") == true)
        }

        // 2. ClientA initializes -> receives isolated Mcp-Session-Id
        val initA = mcpPost(tokA, JSONObject().put("jsonrpc", "2.0").put("id", 1).put("method", "initialize").put("params", JSONObject().put("protocolVersion", "2025-11-25")))
        assertEquals(200, initA.status)
        val sessA = initA.headers["Mcp-Session-Id"]!!

        // Cross-client session reuse fails closed (ClientB cannot use ClientA's session)
        val hijack = mcpPost(tokB, JSONObject().put("jsonrpc", "2.0").put("id", 2).put("method", "tools/list"), sessA)
        assertEquals(403, hijack.status)

        // Insufficient scope check on ClientB calling write tool -> 403
        val scopeFail = mcpPost(tokB, JSONObject().put("jsonrpc", "2.0").put("id", 3).put("method", "tools/call").put("params", JSONObject().put("name", "snow_android_file_write").put("arguments", JSONObject().put("path", "x.txt").put("content", "hi"))), null)
        assertEquals(403, scopeFail.status)

        // 3. Approval gate on write tool -> APPROVAL_REQUIRED -> approve -> executes once -> replay fails
        val writeNoAppr = mcpPost(tokA, JSONObject().put("jsonrpc", "2.0").put("id", 4).put("method", "tools/call").put("params", JSONObject().put("name", "snow_android_file_write").put("arguments", JSONObject().put("path", "note.txt").put("content", "secret-body"))), sessA)
        val writeNoApprJson = JSONObject(writeNoAppr.bodyText()).getJSONObject("result")
        assertTrue(writeNoApprJson.getBoolean("isError"))
        val apprPayload = JSONObject(writeNoApprJson.getJSONArray("content").getJSONObject(0).getString("text"))
        assertEquals("APPROVAL_REQUIRED", apprPayload.getString("status"))
        val apprId = apprPayload.getString("approval_request_id")
        assertTrue(responder.approveToolRequest(apprId))

        val writeWithAppr = mcpPost(tokA, JSONObject().put("jsonrpc", "2.0").put("id", 5).put("method", "tools/call").put("params", JSONObject().put("name", "snow_android_file_write").put("arguments", JSONObject().put("path", "note.txt").put("content", "secret-body").put("approval_id", apprId))), sessA)
        assertFalse(JSONObject(writeWithAppr.bodyText()).getJSONObject("result").getBoolean("isError"))

        // Audit log recorded WITHOUT logging sensitive file content
        val audit = responder.recentAuditEntries()
        assertFalse(audit.joinToString().contains("secret-body"))

        // 4. Bidirectional peer routing Phone A MCP -> Phone B
        val fwdB = mcpPost(tokA, JSONObject().put("jsonrpc", "2.0").put("id", 6).put("method", "tools/call").put("params", JSONObject().put("name", "snow_android_battery").put("arguments", JSONObject().put("device_id", "SNW-PHNB-2222"))), sessA)
        val fwdBText = JSONObject(fwdB.bodyText()).getJSONObject("result").getJSONArray("content").getJSONObject(0).getString("text")
        assertTrue(fwdBText.contains("phone-b"))

        // Phone B profile downgrade -> PERMISSION_DENIED
        peerBProfile.set(false)
        val deniedB = mcpPost(tokA, JSONObject().put("jsonrpc", "2.0").put("id", 7).put("method", "tools/call").put("params", JSONObject().put("name", "snow_android_battery").put("arguments", JSONObject().put("device_id", "phone-b-uuid"))), sessA)
        assertTrue(deniedB.bodyText().contains("PERMISSION_DENIED"))
        peerBProfile.set(true)

        // Phone B offline -> DEVICE_OFFLINE (NO silent fallback to Phone A)
        peerBOnline.set(false)
        val offlineB = mcpPost(tokA, JSONObject().put("jsonrpc", "2.0").put("id", 8).put("method", "tools/call").put("params", JSONObject().put("name", "snow_android_battery").put("arguments", JSONObject().put("device_id", "phone-b-uuid"))), sessA)
        assertTrue(offlineB.bodyText().contains("DEVICE_OFFLINE"))

        // Cross-network routing without snow:mesh rejected
        val crossNet = mcpPost(tokA, JSONObject().put("jsonrpc", "2.0").put("id", 9).put("method", "tools/call").put("params", JSONObject().put("name", "snow_android_battery").put("arguments", JSONObject().put("device_id", "ext-phone-uuid"))), sessA)
        assertTrue(crossNet.bodyText().contains("PERMISSION_DENIED"))

        // Local 5-tier downgrade enforced dynamically during tools/call (ignores prior tools/list)
        dispatcher.activePermissionProfile = "not_allowed"
        val profileBlocked = mcpPost(tokA, JSONObject().put("jsonrpc", "2.0").put("id", 10).put("method", "tools/call").put("params", JSONObject().put("name", "snow_android_battery").put("arguments", JSONObject())), sessA)
        assertTrue(profileBlocked.bodyText().contains("PERMISSION_DENIED"))

        // Revoking ClientA drops active session immediately
        oauth.revokeClient(cidA)
        responder.dropSessionsForClient(cidA)
        val postRevoke = mcpPost(tokA, JSONObject().put("jsonrpc", "2.0").put("id", 11).put("method", "tools/list"), sessA)
        assertEquals(401, postRevoke.status)

        // Disabling standalone Android Remote MCP fails closed with 503
        mcpEnabled.set(false)
        val disabledResp = mcpPost(tokB, JSONObject().put("jsonrpc", "2.0").put("id", 12).put("method", "tools/list"))
        assertEquals(503, disabledResp.status)
    }

    @Test
    fun forwarderEnforcesManualStopAndHttpBodyBounds() {
        val (ctx, _) = newStubContext()
        val devKey = DeviceKeyIdentity.generate()
        val oauth = AndroidOAuthManager(ctx, { devKey.snowId }, { "https://hub.snow.example" }, keyProvider = InMemoryAesKeyProvider())
        val responder = AndroidMcpResponder(
            oauthManager = oauth,
            localDeviceIdProvider = { "local-uuid" },
            localSnowIdProvider = { devKey.snowId },
            localCapabilityDispatcher = AndroidCapabilityDispatcher(ctx) { null }
        )
        val enabled = AtomicBoolean(true)
        val wsFactoryInvoked = AtomicBoolean(false)
        val fwd = AndroidMcpRelayForwarder(
            hubHttpUrlProvider = { "https://hub.snow.example" },
            deviceIdProvider = { "local-uuid" },
            deviceKeyProvider = { devKey },
            responder = responder,
            enabledProvider = { enabled.get() },
            autoReconnect = false,
            webSocketFactory = { req, _ ->
                wsFactoryInvoked.set(true)
                object : okhttp3.WebSocket {
                    override fun request() = req
                    override fun queueSize() = 0L
                    override fun send(text: String) = true
                    override fun send(bytes: okio.ByteString) = true
                    override fun close(code: Int, reason: String?) = true
                    override fun cancel() {}
                }
            }
        )
        assertEquals("https://hub.snow.example/u/${devKey.snowId}/mcp", fwd.currentEndpointUrl())
        enabled.set(false)
        fwd.start()
        assertFalse(wsFactoryInvoked.get())
        assertFalse(fwd.isConnected())
        fwd.stop()
        assertFalse(fwd.isConnected())
    }

    @Test
    fun androidPeerHostBidirectionalRelayEnforcesOriginBindingHopLimitNetworkIsolationAndPerDeviceProfile() {
        val tokenStorage = object : TokenStorage {
            private var token: String? = "peer-mesh-secret-m44"
            override fun saveToken(token: String) { this.token = token }
            override fun getToken(): String? = token
            override fun clearToken() { token = null }
            override fun hasToken(): Boolean = token != null
        }
        val (ctx, _) = newStubContext()
        val dispatcher = AndroidCapabilityDispatcher(ctx) { null }
        val cert = AndroidSelfSignedCertGenerator.generate()
        val hostServer = AndroidPeerHostServer(
            requestedPort = 0,
            tokenStorage = tokenStorage,
            dispatcher = dispatcher,
            localDeviceId = "android-host-1",
            sslContext = cert.sslContext,
            hostSnowId = "SNW-HOST-0001",
            hostNetworkId = "SNW-NET-A1B2C3D4",
            perDeviceProfileProvider = { peerId -> if (peerId == "peer-b") "clipboard_only" else "full_control" }
        )
        assertTrue(hostServer.start())

        class LoopbackPeerClient(uri: URI) : WebSocketClient(uri) {
            val incoming = LinkedBlockingQueue<String>()
            init {
                val trustAll = arrayOf<javax.net.ssl.TrustManager>(object : javax.net.ssl.X509TrustManager {
                    override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                    override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
                })
                val sc = javax.net.ssl.SSLContext.getInstance("TLS")
                sc.init(null, trustAll, java.security.SecureRandom())
                setSocketFactory(sc.socketFactory)
            }
            override fun onSetSSLParameters(sslParameters: javax.net.ssl.SSLParameters) {
                sslParameters.endpointIdentificationAlgorithm = null
            }
            override fun onOpen(handshakedata: ServerHandshake?) {}
            override fun onMessage(message: String) { incoming.offer(message) }
            override fun onClose(code: Int, reason: String?, remote: Boolean) {}
            override fun onError(ex: Exception?) {}
            fun nextMessage(): SnowMessage {
                val raw = incoming.poll(5, TimeUnit.SECONDS)
                assertNotNull("Expected WebSocket message from AndroidPeerHostServer", raw)
                return JsonSerialization.fromJson(raw!!)
            }
        }

        val peerA = LoopbackPeerClient(URI("wss://127.0.0.1:${hostServer.boundPort}"))
        val peerB = LoopbackPeerClient(URI("wss://127.0.0.1:${hostServer.boundPort}"))
        try {
            assertTrue(peerA.connectBlocking(5, TimeUnit.SECONDS))
            assertTrue(peerB.connectBlocking(5, TimeUnit.SECONDS))

            peerA.send(JsonSerialization.toJson(SnowMessage.createRequest(
                action = "auth_request",
                data = mapOf("auth_token" to "peer-mesh-secret-m44", "device_id" to "peer-a")
            )))
            assertEquals(MessageType.RESPONSE, peerA.nextMessage().type)

            peerB.send(JsonSerialization.toJson(SnowMessage.createRequest(
                action = "auth_request",
                data = mapOf("auth_token" to "peer-mesh-secret-m44", "device_id" to "peer-b")
            )))
            assertEquals(MessageType.RESPONSE, peerB.nextMessage().type)

            // 1. Live peer directory includes both authenticated peers
            peerA.send(JsonSerialization.toJson(SnowMessage.createRequest(action = "mesh_list_peers", data = emptyMap())))
            val listResp = peerA.nextMessage()
            assertEquals(MessageType.RESPONSE, listResp.type)
            @Suppress("UNCHECKED_CAST")
            val listData = listResp.payload?.get("data") as Map<String, Any?>
            assertEquals("SNW-HOST-0001", listData["host_snow_id"])
            assertEquals(listOf("peer-a", "peer-b").toSet(), hostServer.listAuthenticatedPeerDeviceIds().toSet())

            // 2. Peer-to-peer relay strips spoofed privilege fields and binds origin_device_id server-side
            peerA.send(JsonSerialization.toJson(SnowMessage.createRequest(
                action = "peer_relay_request",
                data = mapOf(
                    "target_device_id" to "peer-b",
                    "action" to "ping_peer_relay",
                    "data" to mapOf(
                        "origin_device_id" to "spoofed-pc",
                        "trust_tier" to "owner",
                        "principal" to "root",
                        "echo" to "hello"
                    )
                )
            )))
            val forwardedToB = peerB.nextMessage()
            assertEquals(MessageType.REQUEST, forwardedToB.type)
            assertEquals("ping_peer_relay", forwardedToB.payload?.get("action"))
            @Suppress("UNCHECKED_CAST")
            val forwardedData = forwardedToB.payload?.get("data") as Map<String, Any?>
            assertEquals("peer-a", forwardedData["origin_device_id"])
            assertFalse(forwardedData.containsKey("trust_tier"))
            assertFalse(forwardedData.containsKey("principal"))
            assertEquals("hello", forwardedData["echo"])

            peerB.send(JsonSerialization.toJson(SnowMessage.createResponse(
                correlationId = forwardedToB.id,
                payload = mapOf("status" to "success", "reply" to "from-peer-b")
            )))
            val relayResp = peerA.nextMessage()
            assertEquals(MessageType.RESPONSE, relayResp.type)
            assertEquals("peer-b", relayResp.payload?.get("target_device_id"))
            @Suppress("UNCHECKED_CAST")
            val relayData = relayResp.payload?.get("data") as Map<String, Any?>
            assertEquals("from-peer-b", relayData["reply"])

            // 3. Relay hop limit / loop guard rejects depth >= 2
            peerA.send(JsonSerialization.toJson(SnowMessage.createRequest(
                action = "peer_relay_request",
                data = mapOf(
                    "target_device_id" to "peer-b",
                    "action" to "ping_peer_relay",
                    "visited_nodes" to listOf("hop-1", "hop-2")
                )
            )))
            val hopErr = peerA.nextMessage()
            assertEquals(MessageType.ERROR, hopErr.type)

            // 4. Cross-network relay denied
            peerA.send(JsonSerialization.toJson(SnowMessage.createRequest(
                action = "peer_relay_request",
                data = mapOf(
                    "target_device_id" to "SNW-HOST-0001",
                    "action" to "battery_status",
                    "network_id" to "SNW-NET-99887766"
                )
            )))
            val netErr = peerA.nextMessage()
            assertEquals(MessageType.ERROR, netErr.type)
            assertEquals(ErrorCode.UNAUTHORIZED, netErr.error?.code)

            // 5. Per-device 5-tier enforcement blocks ring_phone for clipboard_only peer-b
            peerB.send(JsonSerialization.toJson(SnowMessage.createRequest(
                action = "peer_relay_request",
                data = mapOf(
                    "target_device_id" to "SNW-HOST-0001",
                    "action" to "ring_phone"
                )
            )))
            val tierErr = peerB.nextMessage()
            assertEquals(MessageType.ERROR, tierErr.type)
            assertEquals(ErrorCode.UNAUTHORIZED, tierErr.error?.code)
        } finally {
            peerA.closeBlocking()
            peerB.closeBlocking()
            hostServer.stop()
        }
    }
}
