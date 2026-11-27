package org.snow.mcp

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import org.snow.security.AndroidKeyStoreKeyProvider
import org.snow.security.EncryptedPayload
import org.snow.security.KeyStoreManager
import org.snow.security.SafeLog
import org.snow.security.SecretKeyProvider
import java.net.InetAddress
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.ArrayDeque
import java.util.Base64
import java.util.Locale
import java.util.UUID

/**
 * Normalized HTTP request envelope delivered by Render Hub WebSocket tunnel
 * or direct test harnesses into SNOW's native Android MCP responder.
 */
data class McpHttpRequest(
    val method: String,
    val subpath: String,
    val query: String = "",
    val headers: Map<String, String> = emptyMap(),
    val body: ByteArray = ByteArray(0),
    val remoteIp: String = "127.0.0.1"
) {
    fun header(name: String): String? {
        val target = name.lowercase(Locale.ROOT)
        return headers.entries.firstOrNull { it.key.lowercase(Locale.ROOT) == target }?.value
    }
}

/**
 * Normalized HTTP response envelope returned back through Render Hub WebSocket tunnel.
 */
data class McpHttpResponse(
    val status: Int,
    val headers: Map<String, String> = mapOf("Content-Type" to "application/json; charset=utf-8"),
    val body: ByteArray = ByteArray(0)
) {
    fun bodyText(): String = String(body, StandardCharsets.UTF_8)

    companion object {
        fun json(
            status: Int,
            payload: JSONObject,
            extraHeaders: Map<String, String> = emptyMap()
        ): McpHttpResponse {
            val merged = linkedMapOf(
                "Content-Type" to "application/json; charset=utf-8",
                "Cache-Control" to "no-store"
            )
            merged.putAll(extraHeaders)
            return McpHttpResponse(
                status = status,
                headers = merged,
                body = payload.toString().toByteArray(StandardCharsets.UTF_8)
            )
        }

        fun html(
            status: Int,
            htmlBody: String,
            extraHeaders: Map<String, String> = emptyMap()
        ): McpHttpResponse {
            val merged = linkedMapOf("Content-Type" to "text/html; charset=utf-8")
            merged.putAll(extraHeaders)
            return McpHttpResponse(
                status = status,
                headers = merged,
                body = htmlBody.toByteArray(StandardCharsets.UTF_8)
            )
        }
    }
}

data class PendingConsentSnapshot(
    val requestId: String,
    val clientId: String,
    val clientName: String,
    val redirectUri: String,
    val scope: String,
    val resource: String,
    val targetSnowId: String,
    val networkRoutingAllowed: Boolean,
    val status: String,
    val createdAtMs: Long,
    val expiresAtMs: Long
)

data class AuthorizedOAuthClientSummary(
    val clientId: String,
    val clientName: String,
    val redirectUris: List<String>,
    val scopes: List<String>,
    val createdAtMs: Long,
    val authorizedAtMs: Long,
    val activeTokenCount: Int
)

data class TokenValidationResult(
    val valid: Boolean,
    val clientId: String? = null,
    val clientName: String? = null,
    val familyId: String? = null,
    val scopes: Set<String> = emptySet(),
    val resource: String? = null,
    val errorCode: String? = null,
    val errorDescription: String? = null,
    val httpStatus: Int = 401
)

class BoundedWindowRateLimiter(
    private val limit: Int,
    private val windowMs: Long = 60_000L,
    private val maxKeys: Int = 1_000,
    private val clockMs: () -> Long = { System.currentTimeMillis() }
) {
    private val buckets = LinkedHashMap<String, ArrayDeque<Long>>(64, 0.75f, true)

    @Synchronized
    fun checkAndRecord(rawKey: String): Pair<Boolean, Int> {
        val now = clockMs()
        val key = rawKey.trim().ifBlank { "unknown" }
        val q = buckets[key]
        if (q == null) {
            while (buckets.size >= maxKeys) {
                val eldest = buckets.keys.firstOrNull() ?: break
                buckets.remove(eldest)
            }
            buckets[key] = ArrayDeque<Long>().apply { addLast(now) }
            return true to 0
        }
        val cutoff = now - windowMs
        while (q.isNotEmpty() && q.first() < cutoff) {
            q.removeFirst()
        }
        if (q.size >= limit) {
            val waitMs = ((q.first() + windowMs) - now).coerceAtLeast(1_000L)
            return false to ((waitMs + 999L) / 1000L).toInt()
        }
        q.addLast(now)
        return true to 0
    }
}

/**
 * Self-contained OAuth 2.1 + PKCE (S256 only) Authorization Server for SNOW's standalone
 * Android MCP endpoint (`/u/<android_snow_id>/mcp`).
 *
 * Security invariants:
 * - PKCE S256 strictly mandatory (`plain` and unauthenticated PKCE bypasses rejected).
 * - Strict redirect URI allowlist (HTTPS public host or loopback http://127.0.0.1|localhost|[::1] only;
 *   wildcards, fragments, credentials, open redirects, and cleartext remote http:// rejected).
 * - Dynamic Client Registration and PKCE never bypass explicit on-device owner consent.
 * - Single-use authorization codes (reuse revokes the entire token family).
 * - Refresh token rotation with replay detection revoking the entire family immediately.
 * - Strict resource/audience binding (`https://<host>/u/<android_snow_id>/mcp`) and scope verification.
 * - AES-256-GCM encryption at rest via AndroidKeyStore KeyStoreManager; fails closed on tampering.
 */
class AndroidOAuthManager(
    private val context: Context,
    private val deviceSnowIdProvider: () -> String,
    private val defaultPublicBaseUrlProvider: () -> String = { "https://snow-hub.invalid" },
    keyProvider: SecretKeyProvider = AndroidKeyStoreKeyProvider(OAUTH_KEYSTORE_ALIAS),
    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE),
    private val clockMs: () -> Long = { System.currentTimeMillis() },
    private val onPendingConsentChanged: ((List<PendingConsentSnapshot>) -> Unit)? = null,
    private val onNotificationRequested: ((PendingConsentSnapshot) -> Unit)? = null,
    private val onNotificationCancelled: ((String) -> Unit)? = null,
    private val onClientRevokedCallback: ((String) -> Unit)? = null,
    private val ownerPostApprovalValidator: ((McpHttpRequest, PendingConsentSnapshot, String?) -> Boolean)? = null
) {
    companion object {
        private const val TAG = "AndroidOAuthManager"
        const val PREFS_NAME = "snow_android_oauth_prefs"
        const val OAUTH_KEYSTORE_ALIAS = "snow_android_oauth_key"

        private const val KEY_STATE_IV_B64 = "oauth_state_iv_b64"
        private const val KEY_STATE_CT_B64 = "oauth_state_ct_b64"
        private const val KEY_SCHEMA_VERSION = "oauth_schema_version"
        private const val SCHEMA_VERSION = 1

        const val MAX_BODY_BYTES = 16 * 1024
        const val MAX_REGISTERED_CLIENTS = 64
        const val MAX_PENDING_CONSENTS = 32
        const val AUTH_CODE_TTL_MS = 120_000L
        const val CONSENT_TTL_MS = 300_000L
        const val ACCESS_TOKEN_TTL_MS = 3_600_000L
        const val REFRESH_TOKEN_TTL_MS = 30L * 24L * 3600_000L

        val SUPPORTED_SCOPES = linkedSetOf("snow:read", "snow:write", "snow:execute", "snow:mesh")
        private val CODE_CHALLENGE_REGEX = Regex("^[A-Za-z0-9_-]{43,128}$")
        private val CODE_VERIFIER_REGEX = Regex("^[A-Za-z0-9._~-]{43,128}$")
        private val SNOW_ID_REGEX = Regex("^SNW-[A-Z0-9]{4}-[A-Z0-9]{4}$")
        private val FORWARDED_HOST_REGEX = Regex("^[A-Za-z0-9._:\\[\\]-]{1,253}$")
        private val FORWARDED_PREFIX_REGEX = Regex("^/u/SNW-[A-Z0-9]{4}-[A-Z0-9]{4}$")

        private val secureRandom = SecureRandom()

        fun randomToken(numBytes: Int = 24): String {
            val buf = ByteArray(numBytes)
            secureRandom.nextBytes(buf)
            return Base64.getUrlEncoder().withoutPadding().encodeToString(buf)
        }

        fun sha256Hex(raw: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(raw.toByteArray(StandardCharsets.UTF_8))
            return digest.joinToString("") { "%02x".format(it) }
        }

        fun sha256Base64Url(rawAscii: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(rawAscii.toByteArray(StandardCharsets.US_ASCII))
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
        }

        fun constantTimeEquals(a: String?, b: String?): Boolean {
            if (a == null || b == null) return false
            return MessageDigest.isEqual(
                a.toByteArray(StandardCharsets.UTF_8),
                b.toByteArray(StandardCharsets.UTF_8)
            )
        }

        fun htmlEscape(raw: String): String {
            val sb = StringBuilder(raw.length + 16)
            for (ch in raw) {
                when (ch) {
                    '&' -> sb.append("&amp;")
                    '<' -> sb.append("&lt;")
                    '>' -> sb.append("&gt;")
                    '"' -> sb.append("&quot;")
                    '\'' -> sb.append("&#x27;")
                    else -> sb.append(ch)
                }
            }
            return sb.toString()
        }

        fun parseQueryParams(rawQuery: String): Map<String, String> {
            if (rawQuery.isBlank()) return emptyMap()
            val out = linkedMapOf<String, String>()
            for (pair in rawQuery.split('&')) {
                if (pair.isEmpty()) continue
                val eq = pair.indexOf('=')
                val rawKey = if (eq >= 0) pair.substring(0, eq) else pair
                val rawVal = if (eq >= 0) pair.substring(eq + 1) else ""
                val key = try {
                    URLDecoder.decode(rawKey, StandardCharsets.UTF_8.name())
                } catch (_: Exception) {
                    continue
                }
                val value = try {
                    URLDecoder.decode(rawVal, StandardCharsets.UTF_8.name())
                } catch (_: Exception) {
                    continue
                }
                if (key.isNotEmpty() && !out.containsKey(key)) {
                    out[key] = value
                }
            }
            return out
        }

        fun buildRedirectUrl(baseRedirectUri: String, params: Map<String, String>): String {
            val sep = if ('?' in baseRedirectUri) '&' else '?'
            val encoded = params.entries.joinToString("&") { (k, v) ->
                val ek = URLEncoder.encode(k, StandardCharsets.UTF_8.name())
                val ev = URLEncoder.encode(v, StandardCharsets.UTF_8.name())
                "$ek=$ev"
            }
            return if (encoded.isEmpty()) baseRedirectUri else "$baseRedirectUri$sep$encoded"
        }

        fun isRestrictedHostOrIp(rawHost: String): Boolean {
            val clean = rawHost.trim().trimStart('[').trimEnd(']').lowercase(Locale.ROOT)
            if (clean.isEmpty()) return true
            if (clean == "localhost" || clean.endsWith(".localhost") || clean.endsWith(".local")) {
                return true
            }
            val looksIp = clean.all { it.isDigit() || it == '.' } || ':' in clean
            if (!looksIp) return false
            return try {
                val addr = InetAddress.getByName(clean)
                addr.isAnyLocalAddress ||
                    addr.isLoopbackAddress ||
                    addr.isLinkLocalAddress ||
                    addr.isSiteLocalAddress ||
                    addr.isMulticastAddress
            } catch (_: Exception) {
                true
            }
        }

        fun validateRedirectUri(rawUri: String?): Boolean {
            val clean = rawUri?.trim().orEmpty()
            if (clean.isEmpty() || clean.length > 512) return false
            if (clean.any { it.code < 32 || it.code == 127 || it.isWhitespace() }) return false
            if ('*' in clean || '#' in clean) return false
            val parsed = try {
                URI(clean)
            } catch (_: Exception) {
                return false
            }
            if (!parsed.isAbsolute || !parsed.rawUserInfo.isNullOrEmpty() || !parsed.fragment.isNullOrEmpty()) {
                return false
            }
            val scheme = parsed.scheme?.lowercase(Locale.ROOT) ?: return false
            val host = parsed.host?.lowercase(Locale.ROOT)?.trimStart('[')?.trimEnd(']') ?: return false
            if (host.isEmpty()) return false
            return when (scheme) {
                "http" -> host == "127.0.0.1" || host == "localhost" || host == "::1"
                "https" -> !isRestrictedHostOrIp(host)
                else -> false
            }
        }
    }

    private data class RegisteredClient(
        val clientId: String,
        val clientName: String,
        val redirectUris: List<String>,
        val scopes: List<String>,
        val createdAtMs: Long,
        var authorizedAtMs: Long = 0L,
        var revoked: Boolean = false
    )

    private data class PendingConsentRequest(
        val requestId: String,
        val clientId: String,
        val clientName: String,
        val redirectUri: String,
        val scope: String,
        val codeChallenge: String,
        val codeChallengeMethod: String,
        val resource: String,
        val state: String?,
        val targetSnowId: String,
        val csrfToken: String,
        val pollToken: String,
        val createdAtMs: Long,
        val expiresAtMs: Long,
        var status: String = "PENDING",
        var redirectUrl: String? = null
    ) {
        fun toSnapshot(): PendingConsentSnapshot {
            val parts = scope.split(' ').filter { it.isNotBlank() }.toSet()
            val routingFlag = "snow:mesh" in parts || "snow:execute" in parts || "snow:write" in parts
            return PendingConsentSnapshot(
                requestId = requestId,
                clientId = clientId,
                clientName = clientName,
                redirectUri = redirectUri,
                scope = scope,
                resource = resource,
                targetSnowId = targetSnowId,
                networkRoutingAllowed = routingFlag,
                status = status,
                createdAtMs = createdAtMs,
                expiresAtMs = expiresAtMs
            )
        }
    }

    private data class AuthCodeRecord(
        val codeHash: String,
        val clientId: String,
        val redirectUri: String,
        val codeChallenge: String,
        val scope: String,
        val resource: String,
        val familyId: String,
        val createdAtMs: Long,
        val expiresAtMs: Long,
        var used: Boolean = false
    )

    private data class AccessTokenRecord(
        val tokenHash: String,
        val clientId: String,
        val familyId: String,
        val scopes: Set<String>,
        val resource: String,
        val createdAtMs: Long,
        val expiresAtMs: Long,
        var revoked: Boolean = false
    )

    private data class RefreshTokenRecord(
        val tokenHash: String,
        val clientId: String,
        val familyId: String,
        val scopes: Set<String>,
        val resource: String,
        val createdAtMs: Long,
        val expiresAtMs: Long,
        var used: Boolean = false,
        var revoked: Boolean = false
    )

    private val lock = Any()
    private val keyStoreManager = KeyStoreManager(keyProvider)

    private val clients = linkedMapOf<String, RegisteredClient>()
    private val pendingConsents = linkedMapOf<String, PendingConsentRequest>()
    private val authCodes = linkedMapOf<String, AuthCodeRecord>()
    private val accessTokens = linkedMapOf<String, AccessTokenRecord>()
    private val refreshTokens = linkedMapOf<String, RefreshTokenRecord>()
    private val revokedFamilies = hashSetOf<String>()

    private val registerLimiter = BoundedWindowRateLimiter(limit = 30, windowMs = 60_000L, clockMs = clockMs)
    private val authorizeLimiter = BoundedWindowRateLimiter(limit = 40, windowMs = 60_000L, clockMs = clockMs)
    private val tokenLimiter = BoundedWindowRateLimiter(limit = 60, windowMs = 60_000L, clockMs = clockMs)

    @Volatile
    var corruptStateError: String? = null
        private set

    init {
        loadStateLockedOrFailClosed()
    }

    private fun loadStateLockedOrFailClosed() = synchronized(lock) {
        val ivB64 = prefs.getString(KEY_STATE_IV_B64, null)?.trim()
        val ctB64 = prefs.getString(KEY_STATE_CT_B64, null)?.trim()
        if (ivB64.isNullOrEmpty() && ctB64.isNullOrEmpty()) {
            corruptStateError = null
            return@synchronized
        }
        if (ivB64.isNullOrEmpty() || ctB64.isNullOrEmpty()) {
            clearMemoryLocked()
            corruptStateError = "OAuth encrypted state is incomplete; failing closed."
            SafeLog.e(TAG, corruptStateError!!)
            return@synchronized
        }
        try {
            val schema = prefs.getInt(KEY_SCHEMA_VERSION, -1)
            if (schema != SCHEMA_VERSION) {
                throw IllegalStateException("Unsupported OAuth storage schema version: $schema")
            }
            val iv = Base64.getDecoder().decode(ivB64)
            val ct = Base64.getDecoder().decode(ctB64)
            val plainBytes = keyStoreManager.decrypt(EncryptedPayload(iv = iv, ciphertext = ct))
            val root = JSONObject(String(plainBytes, StandardCharsets.UTF_8))
            restoreFromJsonLocked(root)
            corruptStateError = null
        } catch (e: Exception) {
            clearMemoryLocked()
            corruptStateError = "Failed decrypting Android OAuth store: ${e.javaClass.simpleName}"
            SafeLog.e(TAG, "Refusing to trust corrupted OAuth state: ${e.message}")
        }
    }

    private fun clearMemoryLocked() {
        clients.clear()
        pendingConsents.clear()
        authCodes.clear()
        accessTokens.clear()
        refreshTokens.clear()
        revokedFamilies.clear()
    }

    private fun restoreFromJsonLocked(root: JSONObject) {
        clearMemoryLocked()
        val now = clockMs()
        root.optJSONArray("revoked_families")?.let { arr ->
            for (i in 0 until arr.length()) {
                val fid = arr.optString(i).trim()
                if (fid.isNotEmpty()) revokedFamilies.add(fid)
            }
        }
        root.optJSONArray("clients")?.let { arr ->
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                val cid = o.optString("client_id").trim()
                if (cid.isEmpty()) continue
                val uris = mutableListOf<String>()
                o.optJSONArray("redirect_uris")?.let { ua ->
                    for (j in 0 until ua.length()) {
                        val u = ua.optString(j).trim()
                        if (u.isNotEmpty()) uris.add(u)
                    }
                }
                val scopes = mutableListOf<String>()
                o.optJSONArray("scopes")?.let { sa ->
                    for (j in 0 until sa.length()) {
                        val s = sa.optString(j).trim()
                        if (s.isNotEmpty()) scopes.add(s)
                    }
                }
                clients[cid] = RegisteredClient(
                    clientId = cid,
                    clientName = o.optString("client_name", "AI Client"),
                    redirectUris = uris,
                    scopes = scopes,
                    createdAtMs = o.optLong("created_at_ms", now),
                    authorizedAtMs = o.optLong("authorized_at_ms", 0L),
                    revoked = o.optBoolean("revoked", false)
                )
            }
        }
        root.optJSONArray("access_tokens")?.let { arr ->
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                val th = o.optString("token_hash").trim()
                val exp = o.optLong("expires_at_ms", 0L)
                val rev = o.optBoolean("revoked", false)
                if (th.isEmpty() || rev || exp < now) continue
                accessTokens[th] = AccessTokenRecord(
                    tokenHash = th,
                    clientId = o.optString("client_id"),
                    familyId = o.optString("family_id"),
                    scopes = o.optString("scope").split(' ').filter { it.isNotBlank() }.toSet(),
                    resource = o.optString("resource"),
                    createdAtMs = o.optLong("created_at_ms", now),
                    expiresAtMs = exp,
                    revoked = false
                )
            }
        }
        root.optJSONArray("refresh_tokens")?.let { arr ->
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                val th = o.optString("token_hash").trim()
                val exp = o.optLong("expires_at_ms", 0L)
                val rev = o.optBoolean("revoked", false)
                if (th.isEmpty() || rev || exp < now) continue
                refreshTokens[th] = RefreshTokenRecord(
                    tokenHash = th,
                    clientId = o.optString("client_id"),
                    familyId = o.optString("family_id"),
                    scopes = o.optString("scope").split(' ').filter { it.isNotBlank() }.toSet(),
                    resource = o.optString("resource"),
                    createdAtMs = o.optLong("created_at_ms", now),
                    expiresAtMs = exp,
                    used = o.optBoolean("used", false),
                    revoked = false
                )
            }
        }
    }

    private fun persistStateLocked() {
        val now = clockMs()
        val root = JSONObject()
        val clientArr = JSONArray()
        for (c in clients.values) {
            clientArr.put(
                JSONObject().apply {
                    put("client_id", c.clientId)
                    put("client_name", c.clientName)
                    put("redirect_uris", JSONArray(c.redirectUris))
                    put("scopes", JSONArray(c.scopes))
                    put("created_at_ms", c.createdAtMs)
                    put("authorized_at_ms", c.authorizedAtMs)
                    put("revoked", c.revoked)
                }
            )
        }
        root.put("clients", clientArr)

        val accessArr = JSONArray()
        for (t in accessTokens.values) {
            if (t.revoked || t.expiresAtMs < now || t.familyId in revokedFamilies) continue
            accessArr.put(
                JSONObject().apply {
                    put("token_hash", t.tokenHash)
                    put("client_id", t.clientId)
                    put("family_id", t.familyId)
                    put("scope", t.scopes.joinToString(" "))
                    put("resource", t.resource)
                    put("created_at_ms", t.createdAtMs)
                    put("expires_at_ms", t.expiresAtMs)
                    put("revoked", false)
                }
            )
        }
        root.put("access_tokens", accessArr)

        val refreshArr = JSONArray()
        for (r in refreshTokens.values) {
            if (r.revoked || r.expiresAtMs < now || r.familyId in revokedFamilies) continue
            refreshArr.put(
                JSONObject().apply {
                    put("token_hash", r.tokenHash)
                    put("client_id", r.clientId)
                    put("family_id", r.familyId)
                    put("scope", r.scopes.joinToString(" "))
                    put("resource", r.resource)
                    put("created_at_ms", r.createdAtMs)
                    put("expires_at_ms", r.expiresAtMs)
                    put("used", r.used)
                    put("revoked", false)
                }
            )
        }
        root.put("refresh_tokens", refreshArr)

        val revokedList = revokedFamilies.toList().takeLast(256)
        root.put("revoked_families", JSONArray(revokedList))

        val payload = keyStoreManager.encrypt(root.toString().toByteArray(StandardCharsets.UTF_8))
        val committed = prefs.edit()
            .putInt(KEY_SCHEMA_VERSION, SCHEMA_VERSION)
            .putString(KEY_STATE_IV_B64, Base64.getEncoder().encodeToString(payload.iv))
            .putString(KEY_STATE_CT_B64, Base64.getEncoder().encodeToString(payload.ciphertext))
            .commit()
        if (!committed) {
            throw IllegalStateException("Failed committing encrypted Android OAuth state.")
        }
    }

    fun clearAllOnRecovery() {
        val pendingIds: List<String>
        synchronized(lock) {
            pendingIds = pendingConsents.keys.toList()
            clearMemoryLocked()
            corruptStateError = null
            prefs.edit().clear().commit()
        }
        pendingIds.forEach { onNotificationCancelled?.invoke(it) }
        notifyPendingChanged()
    }

    fun resolveIssuerAndResource(req: McpHttpRequest? = null): Triple<String, String, String> {
        val snowId = deviceSnowIdProvider().trim().uppercase(Locale.ROOT)
        val fallbackBase = defaultPublicBaseUrlProvider().trim().trimEnd('/')
        val fallbackUri = try {
            URI(fallbackBase)
        } catch (_: Exception) {
            null
        }
        val rawProto = req?.header("x-forwarded-proto")?.trim()?.lowercase(Locale.ROOT)
        val scheme = when {
            rawProto == "https" -> "https"
            rawProto == "http" && (req?.header("x-forwarded-host")?.startsWith("127.0.0.1") == true ||
                req?.header("x-forwarded-host")?.startsWith("localhost") == true) -> "http"
            else -> fallbackUri?.scheme?.takeIf { it == "https" || it == "http" } ?: "https"
        }
        val rawHost = req?.header("x-forwarded-host")?.trim()
            ?.takeIf { FORWARDED_HOST_REGEX.matches(it) && !it.contains("..") && !it.contains("@") }
            ?: req?.header("host")?.trim()
                ?.takeIf { FORWARDED_HOST_REGEX.matches(it) && !it.contains("..") && !it.contains("@") }
            ?: fallbackUri?.let {
                if (it.port > 0) "${it.host}:${it.port}" else it.host
            }
            ?: "snow-hub.invalid"

        val defaultPrefix = if (SNOW_ID_REGEX.matches(snowId)) "/u/$snowId" else ""
        val rawPrefix = req?.header("x-forwarded-prefix")?.trim()?.trimEnd('/')
        val prefix = when {
            rawPrefix != null && FORWARDED_PREFIX_REGEX.matches(rawPrefix) -> rawPrefix
            else -> defaultPrefix
        }
        val issuer = "$scheme://$rawHost$prefix"
        val resource = "$issuer/mcp"
        return Triple(issuer, resource, prefix)
    }

    fun handleWellKnownProtectedResource(req: McpHttpRequest): McpHttpResponse {
        val (issuer, resource, _) = resolveIssuerAndResource(req)
        val snowId = deviceSnowIdProvider().trim().uppercase(Locale.ROOT)
        val payload = JSONObject().apply {
            put("resource", resource)
            put("authorization_servers", JSONArray(listOf(issuer)))
            put("scopes_supported", JSONArray(SUPPORTED_SCOPES.toList()))
            put("bearer_methods_supported", JSONArray(listOf("header")))
            put("resource_name", "SNOW Android MCP Bridge ($snowId)")
        }
        return McpHttpResponse.json(200, payload)
    }

    fun handleWellKnownAuthorizationServer(req: McpHttpRequest): McpHttpResponse {
        val (issuer, _, _) = resolveIssuerAndResource(req)
        val payload = JSONObject().apply {
            put("issuer", issuer)
            put("authorization_endpoint", "$issuer/oauth/authorize")
            put("token_endpoint", "$issuer/oauth/token")
            put("registration_endpoint", "$issuer/oauth/register")
            put("revocation_endpoint", "$issuer/oauth/revoke")
            put("scopes_supported", JSONArray(SUPPORTED_SCOPES.toList()))
            put("response_types_supported", JSONArray(listOf("code")))
            put("grant_types_supported", JSONArray(listOf("authorization_code", "refresh_token")))
            put("code_challenge_methods_supported", JSONArray(listOf("S256")))
            put("token_endpoint_auth_methods_supported", JSONArray(listOf("none")))
            put("client_id_metadata_document_supported", false)
        }
        return McpHttpResponse.json(200, payload)
    }

    fun handleRegister(req: McpHttpRequest): McpHttpResponse {
        if (corruptStateError != null) {
            return errorJson(503, "server_error", "Device OAuth identity store is unavailable.")
        }
        val (allowed, retryAfter) = registerLimiter.checkAndRecord(req.remoteIp)
        if (!allowed) {
            return McpHttpResponse.json(
                429,
                JSONObject().put("error", "slow_down").put("error_description", "Too many client registrations."),
                mapOf("Retry-After" to retryAfter.toString())
            )
        }
        if (req.body.size > MAX_BODY_BYTES) {
            return errorJson(413, "invalid_client_metadata", "Registration payload exceeds 16 KiB limit.")
        }
        val root = try {
            JSONObject(String(req.body, StandardCharsets.UTF_8))
        } catch (_: Exception) {
            return errorJson(400, "invalid_client_metadata", "Malformed JSON registration body.")
        }

        val rawName = root.optString("client_name", "").trim()
        val clientName = rawName.filter { it.code in 32..126 }.take(100).trim()
        if (clientName.isEmpty()) {
            return errorJson(400, "invalid_client_metadata", "'client_name' is required.")
        }

        val authMethod = root.optString("token_endpoint_auth_method", "none").trim()
        if (authMethod != "none") {
            return errorJson(400, "invalid_client_metadata", "Only public PKCE clients ('none') are supported.")
        }

        val urisArr = root.optJSONArray("redirect_uris")
            ?: return errorJson(400, "invalid_redirect_uri", "'redirect_uris' array is required.")
        if (urisArr.length() == 0 || urisArr.length() > 5) {
            return errorJson(400, "invalid_redirect_uri", "'redirect_uris' must contain 1 to 5 entries.")
        }
        val validatedUris = mutableListOf<String>()
        for (i in 0 until urisArr.length()) {
            val u = urisArr.optString(i, "").trim()
            if (!validateRedirectUri(u)) {
                return errorJson(400, "invalid_redirect_uri", "Disallowed or malformed redirect_uri at index $i.")
            }
            if (u !in validatedUris) {
                validatedUris.add(u)
            }
        }

        val requestedScopes = parseRequestedScopes(root.optString("scope", "snow:read"))
            ?: return errorJson(400, "invalid_scope", "Requested scope contains unsupported values.")

        val grantTypesArr = root.optJSONArray("grant_types")
        if (grantTypesArr != null) {
            for (i in 0 until grantTypesArr.length()) {
                val gt = grantTypesArr.optString(i, "")
                if (gt != "authorization_code" && gt != "refresh_token") {
                    return errorJson(400, "invalid_client_metadata", "Unsupported grant_type '$gt'.")
                }
            }
        }
        val respTypesArr = root.optJSONArray("response_types")
        if (respTypesArr != null) {
            for (i in 0 until respTypesArr.length()) {
                if (respTypesArr.optString(i, "") != "code") {
                    return errorJson(400, "invalid_client_metadata", "Only response_type 'code' is supported.")
                }
            }
        }

        val now = clockMs()
        val clientId = "snw_and_" + randomToken(12)
        val record = RegisteredClient(
            clientId = clientId,
            clientName = clientName,
            redirectUris = validatedUris,
            scopes = requestedScopes.toList(),
            createdAtMs = now
        )

        synchronized(lock) {
            if (clients.size >= MAX_REGISTERED_CLIENTS) {
                val evictKey = clients.values
                    .firstOrNull { !it.revoked && it.authorizedAtMs == 0L }?.clientId
                    ?: clients.values.firstOrNull { it.revoked }?.clientId
                if (evictKey != null) {
                    clients.remove(evictKey)
                } else {
                    return errorJson(429, "invalid_client_metadata", "Maximum authorized OAuth client capacity reached.")
                }
            }
            clients[clientId] = record
            persistStateLocked()
        }

        SafeLog.i(TAG, "Registered OAuth public client [$clientId] ('$clientName')")
        return McpHttpResponse.json(
            201,
            JSONObject().apply {
                put("client_id", clientId)
                put("client_name", clientName)
                put("redirect_uris", JSONArray(validatedUris))
                put("grant_types", JSONArray(listOf("authorization_code", "refresh_token")))
                put("response_types", JSONArray(listOf("code")))
                put("token_endpoint_auth_method", "none")
                put("scope", requestedScopes.joinToString(" "))
                put("client_id_issued_at", now / 1000L)
            }
        )
    }

    fun handleAuthorize(req: McpHttpRequest): McpHttpResponse {
        if (corruptStateError != null) {
            return errorJson(503, "server_error", "Device OAuth identity store is unavailable.")
        }
        return if (req.method.equals("POST", ignoreCase = true)) {
            handleAuthorizePost(req)
        } else {
            handleAuthorizeGet(req)
        }
    }

    private fun handleAuthorizeGet(req: McpHttpRequest): McpHttpResponse {
        val params = parseQueryParams(req.query)
        val (_, canonicalResource, prefix) = resolveIssuerAndResource(req)

        val clientId = params["client_id"]?.trim().orEmpty()
        val redirectUri = params["redirect_uri"]?.trim().orEmpty()
        val responseType = params["response_type"]?.trim().orEmpty()
        val codeChallenge = params["code_challenge"]?.trim().orEmpty()
        val codeMethod = params["code_challenge_method"]?.trim().orEmpty()
        val state = params["state"]?.trim()?.takeIf { it.isNotEmpty() && it.length <= 512 }
        val rawScope = params["scope"]?.trim().takeUnless { it.isNullOrEmpty() } ?: "snow:read"
        val rawResource = params["resource"]?.trim().takeUnless { it.isNullOrEmpty() }

        val client = synchronized(lock) {
            clients[clientId]?.takeIf { !it.revoked }
        } ?: return errorJson(400, "invalid_client", "Unknown or revoked client_id.")

        if (redirectUri.isEmpty() || redirectUri !in client.redirectUris) {
            return errorJson(400, "invalid_request", "redirect_uri is missing or not an exact registered URI.")
        }
        if (responseType != "code") {
            return errorJson(400, "unsupported_response_type", "Only response_type=code is supported.")
        }
        if (codeMethod != "S256") {
            return errorJson(400, "invalid_request", "PKCE code_challenge_method MUST be 'S256'.")
        }
        if (!CODE_CHALLENGE_REGEX.matches(codeChallenge)) {
            return errorJson(400, "invalid_request", "Invalid PKCE code_challenge format.")
        }
        val scopes = parseRequestedScopes(rawScope)
            ?: return errorJson(400, "invalid_scope", "Requested scopes are invalid or unsupported.")

        val boundResource = if (rawResource != null) {
            val normalizedReqRes = rawResource.trimEnd('/')
            if (normalizedReqRes != canonicalResource) {
                return errorJson(
                    400,
                    "invalid_target",
                    "Requested resource URI '$normalizedReqRes' does not match '$canonicalResource'."
                )
            }
            canonicalResource
        } else {
            canonicalResource
        }

        val snowId = deviceSnowIdProvider().trim().uppercase(Locale.ROOT)
        val now = clockMs()
        val pending = PendingConsentRequest(
            requestId = "oauth_req_" + UUID.randomUUID().toString().replace("-", "").take(16),
            clientId = client.clientId,
            clientName = client.clientName,
            redirectUri = redirectUri,
            scope = scopes.joinToString(" "),
            codeChallenge = codeChallenge,
            codeChallengeMethod = "S256",
            resource = boundResource,
            state = state,
            targetSnowId = snowId,
            csrfToken = randomToken(24),
            pollToken = randomToken(24),
            createdAtMs = now,
            expiresAtMs = now + CONSENT_TTL_MS
        )

        val snapshot = pending.toSnapshot()
        synchronized(lock) {
            pruneExpiredLocked(now)
            while (pendingConsents.size >= MAX_PENDING_CONSENTS) {
                val eldest = pendingConsents.keys.firstOrNull() ?: break
                pendingConsents.remove(eldest)
            }
            pendingConsents[pending.requestId] = pending
        }

        notifyPendingChanged()
        onNotificationRequested?.invoke(snapshot)

        val nonce = randomToken(12)
        val safePrefix = htmlEscape(prefix)
        val safeName = htmlEscape(client.clientName)
        val safeCid = htmlEscape(client.clientId)
        val safeScope = htmlEscape(pending.scope)
        val safeResource = htmlEscape(boundResource)
        val safeRedirect = htmlEscape(redirectUri)
        val safeSnowId = htmlEscape(snowId)
        val safeReqId = htmlEscape(pending.requestId)
        val safePollTok = htmlEscape(pending.pollToken)
        val safeCsrf = htmlEscape(pending.csrfToken)
        val routingLabel = if (snapshot.networkRoutingAllowed) {
            "Permitted if authorized (same-network peers only, subject to target owner approvals)"
        } else {
            "Local Android read-only telemetry/files scope only"
        }

        val html = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SNOW Android MCP Authorization</title>
  <style nonce="$nonce">
    body{font-family:system-ui,-apple-system,sans-serif;background:#090d16;color:#e2e8f0;margin:0;padding:24px;display:flex;justify-content:center}
    main{max-width:480px;width:100%;background:#111827;border:1px solid #1f2937;border-radius:16px;padding:24px}
    h1{font-size:1.15rem;margin:0 0 6px}
    .sub{color:#94a3b8;font-size:.88rem;margin:0 0 16px}
    .box{background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:14px;margin-bottom:16px;font-size:.86rem}
    .row{margin-bottom:8px;word-break:break-all}.lbl{color:#94a3b8;display:block;font-size:.75rem}
    .banner{background:rgba(14,165,233,.12);border:1px solid rgba(14,165,233,.35);border-radius:10px;padding:12px;margin-bottom:16px;font-size:.85rem}
    .actions{display:flex;gap:10px}.btn{flex:1;padding:11px;border-radius:10px;font-weight:600;cursor:pointer;border:none}
    .deny{background:#1e293b;color:#cbd5e1}.approve{background:#0ea5e9;color:#03111c}
    #oauth-status{font-size:.86rem;margin-bottom:12px;color:#38bdf8}
  </style>
</head>
<body>
  <main>
    <h1>Approve on SNOW Android App</h1>
    <p class="sub">OAuth 2.1 + PKCE Authorization Request for <strong>$safeSnowId</strong></p>
    <div class="banner">Open the <strong>SNOW</strong> app on your Android phone (Pending Approvals) to review and confirm this connection.</div>
    <div class="box">
      <div class="row"><span class="lbl">AI Application</span><strong>$safeName</strong> (<code>$safeCid</code>)</div>
      <div class="row"><span class="lbl">Target Android Endpoint</span><code>$safeResource</code></div>
      <div class="row"><span class="lbl">Requested Scopes</span><code>$safeScope</code></div>
      <div class="row"><span class="lbl">Files / Clipboard / Network Routing</span><span>${htmlEscape(routingLabel)}</span></div>
      <div class="row"><span class="lbl">Redirect URI</span><code>$safeRedirect</code></div>
    </div>
    <div id="oauth-status">Waiting for Android owner confirmation...</div>
    <form method="POST" action="$safePrefix/oauth/authorize">
      <input type="hidden" name="request_id" value="$safeReqId">
      <input type="hidden" name="csrf_token" value="$safeCsrf">
      <div class="actions">
        <button class="btn deny" type="submit" name="decision" value="deny">Deny</button>
      </div>
    </form>
  </main>
  <script nonce="$nonce">
  (function(){
    var reqId="$safeReqId", pollTok="$safePollTok", prefix="$safePrefix";
    var el=document.getElementById("oauth-status");
    var t=setInterval(async function(){
      try{
        var r=await fetch(prefix+"/oauth/status?request_id="+encodeURIComponent(reqId)+"&poll_token="+encodeURIComponent(pollTok));
        if(!r.ok) return;
        var d=await r.json();
        if((d.status==="APPROVED"||d.status==="REJECTED")&&d.redirect_url){clearInterval(t);window.location.href=d.redirect_url;}
        else if(d.status==="EXPIRED"){clearInterval(t);if(el)el.textContent="Authorization request expired.";}
      }catch(e){}
    },1000);
  })();
  </script>
</body>
</html>
""".trimIndent()

        return McpHttpResponse.html(
            200,
            html,
            mapOf(
                "Content-Security-Policy" to "default-src 'self'; script-src 'self' 'nonce-$nonce'; style-src 'self' 'nonce-$nonce'; object-src 'none'; frame-ancestors 'none';",
                "Cache-Control" to "no-store, no-cache, must-revalidate",
                "Pragma" to "no-cache",
                "X-Content-Type-Options" to "nosniff",
                "Referrer-Policy" to "no-referrer",
                "X-Frame-Options" to "DENY"
            )
        )
    }

    private fun handleAuthorizePost(req: McpHttpRequest): McpHttpResponse {
        val (allowed, retryAfter) = authorizeLimiter.checkAndRecord(req.remoteIp)
        if (!allowed) {
            return McpHttpResponse.json(
                429,
                JSONObject().put("error", "slow_down").put("error_description", "Rate limit exceeded."),
                mapOf("Retry-After" to retryAfter.toString())
            )
        }
        if (req.body.size > MAX_BODY_BYTES) {
            return errorJson(413, "invalid_request", "Request body exceeds 16 KiB.")
        }
        val params = parseBodyParams(req)
        val reqId = params["request_id"]?.trim().orEmpty()
        val csrf = params["csrf_token"]?.trim().orEmpty()
        val decision = params["decision"]?.trim()?.lowercase(Locale.ROOT).orEmpty()
        val ownerSecret = params["owner_secret"]?.trim()

        val pending = synchronized(lock) {
            pruneExpiredLocked(clockMs())
            pendingConsents[reqId]
        } ?: return errorJson(400, "invalid_request", "Unknown or expired authorization request.")

        if (!constantTimeEquals(csrf, pending.csrfToken)) {
            return errorJson(403, "invalid_request", "CSRF token mismatch.")
        }

        if (decision == "deny") {
            rejectAuthorization(reqId)
            val targetUrl = pending.redirectUrl ?: buildDenyRedirect(pending)
            return McpHttpResponse(
                status = 302,
                headers = mapOf("Location" to targetUrl, "Cache-Control" to "no-store"),
                body = ByteArray(0)
            )
        }

        if (decision != "approve") {
            return errorJson(400, "invalid_request", "Unsupported consent decision.")
        }

        val snapshot = pending.toSnapshot()
        val isOwnerVerified = ownerPostApprovalValidator?.invoke(req, snapshot, ownerSecret) == true
        if (!isOwnerVerified) {
            return errorJson(
                403,
                "owner_approval_required",
                "Direct remote POST cannot self-approve OAuth consent. Approve inside the SNOW Android app."
            )
        }

        if (!approveAuthorization(reqId)) {
            return errorJson(400, "invalid_request", "Unable to approve authorization request.")
        }
        val targetUrl = pending.redirectUrl ?: buildDenyRedirect(pending)
        return McpHttpResponse(
            status = 302,
            headers = mapOf("Location" to targetUrl, "Cache-Control" to "no-store"),
            body = ByteArray(0)
        )
    }

    fun handleAuthorizeStatus(req: McpHttpRequest): McpHttpResponse {
        val params = parseQueryParams(req.query)
        val reqId = params["request_id"]?.trim().orEmpty()
        val pollTok = params["poll_token"]?.trim().orEmpty()
        val now = clockMs()
        val rec = synchronized(lock) {
            pruneExpiredLocked(now)
            pendingConsents[reqId]
        } ?: return errorJson(404, "not_found", "Authorization request not found or expired.")

        if (!constantTimeEquals(pollTok, rec.pollToken)) {
            return errorJson(403, "access_denied", "Invalid status poll token.")
        }
        val out = JSONObject().put("status", rec.status)
        if ((rec.status == "APPROVED" || rec.status == "REJECTED") && !rec.redirectUrl.isNullOrBlank()) {
            out.put("redirect_url", rec.redirectUrl)
        }
        return McpHttpResponse.json(200, out)
    }

    fun listPendingConsents(): List<PendingConsentSnapshot> {
        val now = clockMs()
        return synchronized(lock) {
            pruneExpiredLocked(now)
            pendingConsents.values
                .filter { it.status == "PENDING" && now <= it.expiresAtMs }
                .map { it.toSnapshot() }
        }
    }

    fun approveAuthorization(requestId: String): Boolean {
        val now = clockMs()
        var approved = false
        synchronized(lock) {
            pruneExpiredLocked(now)
            val rec = pendingConsents[requestId] ?: return false
            if (rec.status != "PENDING" || now > rec.expiresAtMs) {
                return false
            }
            val client = clients[rec.clientId] ?: return false
            if (client.revoked) return false

            val rawCode = randomToken(24)
            val familyId = "fam_" + randomToken(16)
            authCodes[sha256Hex(rawCode)] = AuthCodeRecord(
                codeHash = sha256Hex(rawCode),
                clientId = rec.clientId,
                redirectUri = rec.redirectUri,
                codeChallenge = rec.codeChallenge,
                scope = rec.scope,
                resource = rec.resource,
                familyId = familyId,
                createdAtMs = now,
                expiresAtMs = now + AUTH_CODE_TTL_MS,
                used = false
            )
            val redirParams = linkedMapOf("code" to rawCode)
            if (!rec.state.isNullOrEmpty()) {
                redirParams["state"] = rec.state
            }
            rec.redirectUrl = buildRedirectUrl(rec.redirectUri, redirParams)
            rec.status = "APPROVED"
            approved = true
            SafeLog.i(TAG, "Owner approved Android OAuth consent [$requestId] for client [${rec.clientId}]")
        }
        if (approved) {
            onNotificationCancelled?.invoke(requestId)
            notifyPendingChanged()
        }
        return approved
    }

    fun rejectAuthorization(requestId: String): Boolean {
        val now = clockMs()
        var rejected = false
        synchronized(lock) {
            pruneExpiredLocked(now)
            val rec = pendingConsents[requestId] ?: return false
            if (rec.status != "PENDING") return false
            rec.status = "REJECTED"
            rec.redirectUrl = buildDenyRedirect(rec)
            rejected = true
            SafeLog.i(TAG, "Owner rejected Android OAuth consent [$requestId] for client [${rec.clientId}]")
        }
        if (rejected) {
            onNotificationCancelled?.invoke(requestId)
            notifyPendingChanged()
        }
        return rejected
    }

    fun handleToken(req: McpHttpRequest): McpHttpResponse {
        if (corruptStateError != null) {
            return errorJson(503, "server_error", "Device OAuth identity store is unavailable.")
        }
        val (allowed, retryAfter) = tokenLimiter.checkAndRecord(req.remoteIp)
        if (!allowed) {
            return McpHttpResponse.json(
                429,
                JSONObject().put("error", "slow_down").put("error_description", "Token rate limit exceeded."),
                mapOf("Retry-After" to retryAfter.toString())
            )
        }
        if (req.body.size > MAX_BODY_BYTES) {
            return errorJson(413, "invalid_request", "Token request exceeds 16 KiB limit.")
        }
        val params = parseBodyParams(req)
        val grantType = params["grant_type"]?.trim().orEmpty()
        val clientId = params["client_id"]?.trim().orEmpty()
        val rawResource = params["resource"]?.trim()?.trimEnd('/')

        return when (grantType) {
            "authorization_code" -> exchangeAuthorizationCode(params, clientId, rawResource)
            "refresh_token" -> rotateRefreshToken(params, clientId, rawResource)
            else -> errorJson(400, "unsupported_grant_type", "Grant type must be authorization_code or refresh_token.")
        }
    }

    private fun exchangeAuthorizationCode(
        params: Map<String, String>,
        clientId: String,
        requestedResource: String?
    ): McpHttpResponse {
        val rawCode = params["code"]?.trim().orEmpty()
        val redirectUri = params["redirect_uri"]?.trim().orEmpty()
        val codeVerifier = params["code_verifier"]?.trim().orEmpty()
        if (rawCode.isEmpty() || clientId.isEmpty() || redirectUri.isEmpty() || codeVerifier.isEmpty()) {
            return errorJson(400, "invalid_request", "code, client_id, redirect_uri, and code_verifier are required.")
        }
        if (!CODE_VERIFIER_REGEX.matches(codeVerifier)) {
            return errorJson(400, "invalid_grant", "Malformed PKCE code_verifier.")
        }

        val codeHash = sha256Hex(rawCode)
        val now = clockMs()
        val computedChallenge = sha256Base64Url(codeVerifier)

        synchronized(lock) {
            val rec = authCodes[codeHash]
                ?: return errorJson(400, "invalid_grant", "Authorization code is invalid or unknown.")
            val client = clients[clientId]
            if (client == null || client.revoked) {
                return errorJson(400, "invalid_client", "Client is unknown or revoked.")
            }
            if (rec.used) {
                // OAuth 2.1 replay protection: revoke any tokens issued in this family
                revokeFamilyLocked(rec.familyId)
                persistStateLocked()
                SafeLog.w(TAG, "Authorization code replay detected for client [$clientId]; revoked token family [${rec.familyId}]")
                return errorJson(400, "invalid_grant", "Authorization code already redeemed.")
            }
            if (now > rec.expiresAtMs) {
                authCodes.remove(codeHash)
                return errorJson(400, "invalid_grant", "Authorization code expired.")
            }
            if (rec.clientId != clientId || rec.redirectUri != redirectUri) {
                return errorJson(400, "invalid_grant", "client_id or redirect_uri mismatch.")
            }
            if (requestedResource != null && requestedResource != rec.resource) {
                return errorJson(400, "invalid_target", "resource parameter mismatch.")
            }
            if (!constantTimeEquals(computedChallenge, rec.codeChallenge)) {
                return errorJson(400, "invalid_grant", "PKCE code_verifier verification failed.")
            }

            rec.used = true
            client.authorizedAtMs = if (client.authorizedAtMs > 0L) client.authorizedAtMs else now
            val scopes = rec.scope.split(' ').filter { it.isNotBlank() }.toSet()
            val (rawAccess, rawRefresh) = issueTokenPairLocked(
                clientId = client.clientId,
                familyId = rec.familyId,
                scopes = scopes,
                resource = rec.resource,
                now = now
            )
            persistStateLocked()

            return McpHttpResponse.json(
                200,
                JSONObject().apply {
                    put("access_token", rawAccess)
                    put("token_type", "Bearer")
                    put("expires_in", ACCESS_TOKEN_TTL_MS / 1000L)
                    put("refresh_token", rawRefresh)
                    put("scope", scopes.joinToString(" "))
                }
            )
        }
    }

    private fun rotateRefreshToken(
        params: Map<String, String>,
        clientId: String,
        requestedResource: String?
    ): McpHttpResponse {
        val rawRefresh = params["refresh_token"]?.trim().orEmpty()
        if (rawRefresh.isEmpty() || clientId.isEmpty()) {
            return errorJson(400, "invalid_request", "refresh_token and client_id are required.")
        }

        val tokenHash = sha256Hex(rawRefresh)
        val now = clockMs()
        synchronized(lock) {
            val rec = refreshTokens[tokenHash]
                ?: return errorJson(400, "invalid_grant", "Unknown refresh token.")
            val client = clients[clientId]
            if (client == null || client.revoked) {
                return errorJson(400, "invalid_client", "Client is unknown or revoked.")
            }
            if (rec.revoked || rec.familyId in revokedFamilies) {
                return errorJson(400, "invalid_grant", "Refresh token family has been revoked.")
            }
            if (rec.used) {
                revokeFamilyLocked(rec.familyId)
                persistStateLocked()
                SafeLog.w(TAG, "Refresh token replay detected for client [$clientId]; revoked family [${rec.familyId}]")
                return errorJson(400, "invalid_grant", "Refresh token reuse detected; token family revoked.")
            }
            if (now > rec.expiresAtMs || rec.clientId != clientId) {
                return errorJson(400, "invalid_grant", "Refresh token expired or client mismatch.")
            }
            if (requestedResource != null && requestedResource != rec.resource) {
                return errorJson(400, "invalid_target", "resource parameter mismatch.")
            }

            rec.used = true
            val (newAccess, newRefresh) = issueTokenPairLocked(
                clientId = rec.clientId,
                familyId = rec.familyId,
                scopes = rec.scopes,
                resource = rec.resource,
                now = now
            )
            persistStateLocked()

            return McpHttpResponse.json(
                200,
                JSONObject().apply {
                    put("access_token", newAccess)
                    put("token_type", "Bearer")
                    put("expires_in", ACCESS_TOKEN_TTL_MS / 1000L)
                    put("refresh_token", newRefresh)
                    put("scope", rec.scopes.joinToString(" "))
                }
            )
        }
    }

    fun handleRevoke(req: McpHttpRequest): McpHttpResponse {
        if (req.body.size > MAX_BODY_BYTES) {
            return errorJson(413, "invalid_request", "Payload exceeds 16 KiB limit.")
        }
        val params = parseBodyParams(req)
        val token = params["token"]?.trim().orEmpty()
        val clientId = params["client_id"]?.trim()
        if (token.isNotEmpty()) {
            val h = sha256Hex(token)
            synchronized(lock) {
                val at = accessTokens[h]
                val rt = refreshTokens[h]
                val fam = when {
                    at != null && (clientId.isNullOrEmpty() || at.clientId == clientId) -> at.familyId
                    rt != null && (clientId.isNullOrEmpty() || rt.clientId == clientId) -> rt.familyId
                    else -> null
                }
                if (fam != null) {
                    revokeFamilyLocked(fam)
                    persistStateLocked()
                }
            }
        }
        return McpHttpResponse.json(200, JSONObject())
    }

    fun validateBearerHeader(
        authorizationHeader: String?,
        expectedResource: String,
        requiredScopes: Set<String> = emptySet()
    ): TokenValidationResult {
        if (corruptStateError != null) {
            return TokenValidationResult(
                valid = false,
                errorCode = "server_error",
                errorDescription = "OAuth token store unavailable.",
                httpStatus = 503
            )
        }
        val raw = authorizationHeader?.trim().orEmpty()
        if (!raw.startsWith("Bearer ", ignoreCase = true)) {
            return TokenValidationResult(
                valid = false,
                errorCode = "invalid_token",
                errorDescription = "Missing Bearer authorization header.",
                httpStatus = 401
            )
        }
        val token = raw.substring(7).trim()
        if (token.isEmpty()) {
            return TokenValidationResult(
                valid = false,
                errorCode = "invalid_token",
                errorDescription = "Empty Bearer token.",
                httpStatus = 401
            )
        }

        val h = sha256Hex(token)
        val now = clockMs()
        val normalizedExpected = expectedResource.trimEnd('/')

        synchronized(lock) {
            val rec = accessTokens[h]
                ?: return TokenValidationResult(
                    valid = false,
                    errorCode = "invalid_token",
                    errorDescription = "Unknown access token.",
                    httpStatus = 401
                )
            val client = clients[rec.clientId]
            if (client == null || client.revoked || rec.revoked || rec.familyId in revokedFamilies) {
                return TokenValidationResult(
                    valid = false,
                    errorCode = "invalid_token",
                    errorDescription = "Access token or client has been revoked.",
                    httpStatus = 401
                )
            }
            if (now > rec.expiresAtMs) {
                return TokenValidationResult(
                    valid = false,
                    errorCode = "invalid_token",
                    errorDescription = "Access token expired.",
                    httpStatus = 401
                )
            }
            if (rec.resource.trimEnd('/') != normalizedExpected) {
                return TokenValidationResult(
                    valid = false,
                    errorCode = "invalid_token",
                    errorDescription = "Access token audience mismatch.",
                    httpStatus = 401
                )
            }
            if (!requiredScopes.all { it in rec.scopes }) {
                return TokenValidationResult(
                    valid = false,
                    clientId = rec.clientId,
                    clientName = client.clientName,
                    familyId = rec.familyId,
                    scopes = rec.scopes,
                    resource = rec.resource,
                    errorCode = "insufficient_scope",
                    errorDescription = "Missing required scope(s): ${requiredScopes.minus(rec.scopes).joinToString(",")}",
                    httpStatus = 403
                )
            }
            return TokenValidationResult(
                valid = true,
                clientId = rec.clientId,
                clientName = client.clientName,
                familyId = rec.familyId,
                scopes = rec.scopes,
                resource = rec.resource,
                httpStatus = 200
            )
        }
    }

    fun listAuthorizedClients(): List<AuthorizedOAuthClientSummary> {
        val now = clockMs()
        return synchronized(lock) {
            clients.values
                .filter { !it.revoked && it.authorizedAtMs > 0L }
                .map { c ->
                    val activeCount = accessTokens.values.count {
                        it.clientId == c.clientId && !it.revoked && it.expiresAtMs >= now && it.familyId !in revokedFamilies
                    }
                    AuthorizedOAuthClientSummary(
                        clientId = c.clientId,
                        clientName = c.clientName,
                        redirectUris = c.redirectUris,
                        scopes = c.scopes,
                        createdAtMs = c.createdAtMs,
                        authorizedAtMs = c.authorizedAtMs,
                        activeTokenCount = activeCount
                    )
                }
        }
    }

    fun revokeClient(clientId: String): Boolean {
        val clean = clientId.trim()
        if (clean.isEmpty()) return false
        var changed = false
        synchronized(lock) {
            val client = clients[clean] ?: return false
            client.revoked = true
            accessTokens.values.filter { it.clientId == clean }.forEach {
                it.revoked = true
                revokedFamilies.add(it.familyId)
            }
            refreshTokens.values.filter { it.clientId == clean }.forEach {
                it.revoked = true
                revokedFamilies.add(it.familyId)
            }
            val codeKeys = authCodes.entries.filter { it.value.clientId == clean }.map { it.key }
            codeKeys.forEach { authCodes.remove(it) }
            persistStateLocked()
            changed = true
            SafeLog.i(TAG, "Revoked Android OAuth client [$clean] and all issued tokens")
        }
        if (changed) {
            onClientRevokedCallback?.invoke(clean)
        }
        return changed
    }

    private fun issueTokenPairLocked(
        clientId: String,
        familyId: String,
        scopes: Set<String>,
        resource: String,
        now: Long
    ): Pair<String, String> {
        val rawAccess = "snwat_" + randomToken(32)
        val rawRefresh = "snwrt_" + randomToken(32)
        val accessHash = sha256Hex(rawAccess)
        val refreshHash = sha256Hex(rawRefresh)
        accessTokens[accessHash] = AccessTokenRecord(
            tokenHash = accessHash,
            clientId = clientId,
            familyId = familyId,
            scopes = scopes,
            resource = resource,
            createdAtMs = now,
            expiresAtMs = now + ACCESS_TOKEN_TTL_MS,
            revoked = false
        )
        refreshTokens[refreshHash] = RefreshTokenRecord(
            tokenHash = refreshHash,
            clientId = clientId,
            familyId = familyId,
            scopes = scopes,
            resource = resource,
            createdAtMs = now,
            expiresAtMs = now + REFRESH_TOKEN_TTL_MS,
            used = false,
            revoked = false
        )
        return rawAccess to rawRefresh
    }

    private fun revokeFamilyLocked(familyId: String) {
        revokedFamilies.add(familyId)
        accessTokens.values.filter { it.familyId == familyId }.forEach { it.revoked = true }
        refreshTokens.values.filter { it.familyId == familyId }.forEach { it.revoked = true }
    }

    private fun pruneExpiredLocked(now: Long) {
        val expiredConsentIds = pendingConsents.entries
            .filter { (_, v) -> now > v.expiresAtMs && v.status == "PENDING" }
            .map { it.key }
        for (id in expiredConsentIds) {
            pendingConsents[id]?.status = "EXPIRED"
            pendingConsents.remove(id)
        }
        val expiredCodes = authCodes.entries.filter { now > it.value.expiresAtMs }.map { it.key }
        expiredCodes.forEach { authCodes.remove(it) }
        val expiredAt = accessTokens.entries.filter { now > it.value.expiresAtMs }.map { it.key }
        expiredAt.forEach { accessTokens.remove(it) }
        val expiredRt = refreshTokens.entries.filter { now > it.value.expiresAtMs }.map { it.key }
        expiredRt.forEach { refreshTokens.remove(it) }
    }

    private fun notifyPendingChanged() {
        onPendingConsentChanged?.invoke(listPendingConsents())
    }

    private fun parseRequestedScopes(rawScope: String): Set<String>? {
        val tokens = rawScope.trim().split(Regex("\\s+")).filter { it.isNotBlank() }
        if (tokens.isEmpty()) return setOf("snow:read")
        if (tokens.any { it !in SUPPORTED_SCOPES }) return null
        return tokens.toCollection(linkedSetOf())
    }

    private fun parseBodyParams(req: McpHttpRequest): Map<String, String> {
        val ct = req.header("content-type")?.lowercase(Locale.ROOT).orEmpty()
        val raw = String(req.body, StandardCharsets.UTF_8)
        if ("application/json" in ct || raw.trimStart().startsWith("{")) {
            return try {
                val obj = JSONObject(raw)
                val out = linkedMapOf<String, String>()
                val keys = obj.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    val v = obj.opt(k)
                    if (v != null && v != JSONObject.NULL) {
                        out[k] = v.toString()
                    }
                }
                out
            } catch (_: Exception) {
                emptyMap()
            }
        }
        return parseQueryParams(raw)
    }

    private fun buildDenyRedirect(rec: PendingConsentRequest): String {
        val params = linkedMapOf(
            "error" to "access_denied",
            "error_description" to "Owner denied authorization."
        )
        if (!rec.state.isNullOrEmpty()) {
            params["state"] = rec.state
        }
        return buildRedirectUrl(rec.redirectUri, params)
    }

    private fun errorJson(status: Int, error: String, description: String): McpHttpResponse {
        return McpHttpResponse.json(
            status,
            JSONObject()
                .put("error", error)
                .put("error_description", description)
        )
    }
}
