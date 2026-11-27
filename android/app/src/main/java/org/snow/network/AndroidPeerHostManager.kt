package org.snow.network

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.security.AndroidSelfSignedCertGenerator
import org.snow.security.EncryptedFilePeerHostCertStorage
import org.snow.security.PeerHostCertStorage
import org.snow.security.SafeLog
import org.snow.security.TokenStorage
import java.net.Inet4Address
import java.net.NetworkInterface
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Raw network interface candidate inspected for local IPv4 ranking.
 */
data class NetworkInterfaceCandidate(
    val interfaceName: String,
    val displayName: String? = null,
    val ipv4Address: String,
    val isUp: Boolean = true,
    val isLoopback: Boolean = false,
    val isPointToPoint: Boolean = false,
    val isVirtual: Boolean = false
)

/**
 * Live reactive state of the Android Direct Peer-Host service.
 */
data class PeerHostState(
    val isActive: Boolean = false,
    val ipAddress: String = "--",
    val candidateIps: List<String> = emptyList(),
    val port: Int = AndroidPeerHostManager.DEFAULT_HOST_PORT,
    val mediaPort: Int = AndroidPeerHostManager.DEFAULT_MEDIA_PORT,
    val certFingerprint: String = "--",
    val peerCount: Int = 0,
    val pairingPin: String? = null,
    val pinExpiresInSeconds: Long = 0L,
    val isPairingLocked: Boolean = false,
    val lockoutRemainingSeconds: Long = 0L,
    val errorMessage: String? = null,
    val networkId: String? = null
)

/**
 * Manages the lifecycle, reachability state, and socket bounds for Android Foreground Peer Host Mode.
 *
 * Guarantees:
 * - Thread-safe state transitions.
 * - Persists TLS keypair & X.509 certificate across restarts via [PeerHostCertStorage] (fails closed on corruption).
 * - Supports unified 60s single-use 6-digit pairing PIN (with 3-attempt lockout) and single-use QR `handshake_token` + `network_id`.
 * - Ranks usable hotspot/Wi-Fi local IPv4 addresses while excluding cellular, VPN, loopback, and link-local interfaces.
 * - Shuts down server sockets cleanly upon app/service lifecycle transitions.
 */
class AndroidPeerHostManager(
    private val certStorage: PeerHostCertStorage? = null
) {
    constructor(context: Context) : this(EncryptedFilePeerHostCertStorage(context))

    companion object {
        private const val TAG = "AndroidPeerHostManager"
        const val DEFAULT_HOST_PORT = 8767
        const val DEFAULT_MEDIA_PORT = 8769
        const val PIN_VALIDITY_MS = 60_000L // 60 seconds unified TTL
        const val HANDSHAKE_TOKEN_VALIDITY_MS = 60_000L // 60 seconds unified TTL
        const val MAX_FAILED_PIN_ATTEMPTS = 3
        const val LOCKOUT_COOLDOWN_MS = 60_000L
        const val IS_QUARANTINED = false

        val CANONICAL_NETWORK_ID_REGEX = Regex("^SNW-NET-[A-Z0-9]{8}$")
        private const val CANONICAL_HEX_CHARS = "0123456789ABCDEF"
        private val networkIdRandom = java.security.SecureRandom()

        fun isValidCanonicalNetworkId(networkId: String?): Boolean {
            val clean = networkId?.trim()?.uppercase() ?: return false
            return CANONICAL_NETWORK_ID_REGEX.matches(clean)
        }

        fun generateCanonicalNetworkId(): String {
            val sb = StringBuilder("SNW-NET-")
            repeat(8) {
                sb.append(CANONICAL_HEX_CHARS[networkIdRandom.nextInt(CANONICAL_HEX_CHARS.length)])
            }
            return sb.toString()
        }

        private val CELLULAR_PREFIXES = listOf("rmnet", "ccmni", "pdp", "wwan", "seth_lte", "svnet", "epdg", "clat", "v4-rmnet")
        private val VPN_PREFIXES = listOf("tun", "tap", "ppp", "wg", "ipsec", "vti", "utun", "nordlynx", "tailscale")
        private val VPN_DISPLAY_TOKEN_REGEX = Regex("""\b(tun\d*|tap\d*|ppp\d*|wg\d*|wireguard|openvpn|ipsec|nordlynx|tailscale|vpn)\b""")
        private val HOTSPOT_PREFIXES = listOf("ap", "swlan", "softap", "wifi_ap", "uap", "sap")
        private val WIFI_PREFIXES = listOf("wlan", "wifi", "wlp", "wlx", "ath", "ra")
        private val WIRED_USB_PREFIXES = listOf("eth", "rndis", "usb", "ncm", "en")

        fun isValidRoutableLocalIpv4(ipRaw: String): Boolean {
            val clean = ipRaw.trim()
            val parts = clean.split('.')
            if (parts.size != 4) return false
            val octets = parts.map { it.toIntOrNull() ?: return false }
            if (octets.any { it !in 0..255 }) return false
            val b0 = octets[0]
            val b1 = octets[1]
            if (b0 == 0 || b0 == 127) return false // Unspecified / loopback
            if (b0 == 169 && b1 == 254) return false // Link-local
            if (b0 >= 224) return false // Multicast / reserved
            return true
        }

        private fun isPrivateRfc1918(ip: String): Boolean {
            val parts = ip.split('.').mapNotNull { it.toIntOrNull() }
            if (parts.size != 4) return false
            val (a, b, _, _) = parts
            return a == 10 || (a == 172 && b in 16..31) || (a == 192 && b == 168)
        }

        private fun isLikelyHotspotSubnet(ip: String): Boolean {
            return ip.startsWith("192.168.43.") ||
                ip.startsWith("192.168.49.") ||
                ip.startsWith("192.168.137.") ||
                ip.startsWith("172.20.10.")
        }

        /**
         * Deterministically rank eligible local IPv4 addresses for peer reachability:
         * 1. Hotspot / AP interfaces (ap0, swlan0, softap*, or secondary hotspot subnets)
         * 2. Wi-Fi interfaces (wlan0, wlan*, wifi*)
         * 3. Wired / tethered local interfaces (eth*, rndis*, usb*, ncm*)
         * 4. Other eligible non-excluded UP private interfaces
         * Excludes loopback, link-local, cellular (rmnet*, ccmni*, etc.), VPN/tunnels (tun*, wg*, etc.).
         */
        fun rankLocalIpv4Candidates(candidates: List<NetworkInterfaceCandidate>): List<String> {
            data class Scored(val ip: String, val tier: Int, val privateScore: Int, val ifaceOrder: String)

            val bestByIp = LinkedHashMap<String, Scored>()
            for (cand in candidates) {
                if (!cand.isUp || cand.isLoopback || cand.isVirtual) continue
                val ip = cand.ipv4Address.trim()
                if (!isValidRoutableLocalIpv4(ip)) continue

                val ifName = cand.interfaceName.trim().lowercase()
                val dispName = cand.displayName?.trim()?.lowercase().orEmpty()
                if (ifName == "lo" || ifName.startsWith("lo")) continue
                val isHotspot = HOTSPOT_PREFIXES.any { ifName.startsWith(it) } ||
                    (ifName.startsWith("wlan") && ifName != "wlan0" && isLikelyHotspotSubnet(ip)) ||
                    isLikelyHotspotSubnet(ip)
                if (!isHotspot && CELLULAR_PREFIXES.any { ifName.startsWith(it) || dispName.contains(it) }) continue
                if (!isHotspot && (VPN_PREFIXES.any { ifName.startsWith(it) } || VPN_DISPLAY_TOKEN_REGEX.containsMatchIn(dispName))) continue

                val isWifi = WIFI_PREFIXES.any { ifName.startsWith(it) } || dispName.contains("wi-fi") || dispName.contains("wifi")
                val isWiredUsb = WIRED_USB_PREFIXES.any { ifName.startsWith(it) }

                if (cand.isPointToPoint && !isHotspot && !isWifi && !isWiredUsb) continue

                val tier = when {
                    isHotspot -> 0
                    isWifi -> 1
                    isWiredUsb -> 2
                    else -> 3
                }
                val privateScore = if (isPrivateRfc1918(ip)) 0 else 1
                val ifaceSort = "${if (ifName == "ap0" || ifName == "swlan0" || ifName == "wlan0") "0" else "1"}_$ifName"
                val scored = Scored(ip = ip, tier = tier, privateScore = privateScore, ifaceOrder = ifaceSort)
                val prev = bestByIp[ip]
                if (prev == null ||
                    scored.tier < prev.tier ||
                    (scored.tier == prev.tier && scored.privateScore < prev.privateScore) ||
                    (scored.tier == prev.tier && scored.privateScore == prev.privateScore && scored.ifaceOrder < prev.ifaceOrder)
                ) {
                    bestByIp[ip] = scored
                }
            }

            return bestByIp.values
                .sortedWith(compareBy<Scored>({ it.tier }, { it.privateScore }, { it.ifaceOrder }, { it.ip }))
                .map { it.ip }
        }
    }

    data class EphemeralPin(
        val pin: String,
        val expiresAtMillis: Long,
        var isConsumed: Boolean = false
    )

    data class EphemeralHandshakeToken(
        val token: String,
        val expiresAtMillis: Long,
        val networkId: String? = null,
        var isConsumed: Boolean = false
    )

    data class MergeProposalRecord(
        val txId: String,
        val sourceNetworkId: String,
        val targetNetworkId: String,
        val survivingNetworkId: String,
        val sourceOwnerDeviceId: String,
        val targetOwnerDeviceId: String,
        var sourceOwnerApproved: Boolean = false,
        var targetOwnerApproved: Boolean = false,
        var status: String = "PENDING"
    )

    private val hostModeSettingEnabled = AtomicBoolean(false)
    private val isRunning = AtomicBoolean(false)
    private var server: AndroidPeerHostServer? = null
    private var mediaServer: AndroidPeerMediaServer? = null
    private var currentEphemeralPin: EphemeralPin? = null
    private var currentHandshakeToken: EphemeralHandshakeToken? = null
    private var configuredSnowId: String? = null
    private var configuredNetworkId: String? = null
    private var configuredLocalDeviceId: String = ""
    private var onHostNetworkUpdatedCallback: ((String?) -> Unit)? = null
    private val mergeProposals = java.util.concurrent.ConcurrentHashMap<String, MergeProposalRecord>()
    private var failedPinAttempts: Int = 0
    private var lockoutUntilMillis: Long = 0L
    internal var clockMillis: () -> Long = { System.currentTimeMillis() }
    private val secureRandom = java.security.SecureRandom()

    private val _hostState = MutableStateFlow(PeerHostState())
    val hostState: StateFlow<PeerHostState> = _hostState.asStateFlow()

    var activePort: Int = DEFAULT_HOST_PORT
        private set

    var activeMediaPort: Int = DEFAULT_MEDIA_PORT
        private set

    val activeConnectionCount: Int
        get() = server?.getActiveConnectionCount() ?: 0

    fun getMediaServer(): AndroidPeerMediaServer? = mediaServer

    /**
     * Enumerate all usable local IPv4 addresses ranked deterministically (Hotspot -> Wi-Fi -> Wired/USB -> Other).
     */
    fun enumerateLocalIpv4Candidates(): List<String> {
        return try {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return emptyList()
            val rawCandidates = mutableListOf<NetworkInterfaceCandidate>()
            for (iface in interfaces) {
                for (addr in iface.inetAddresses) {
                    if (addr is Inet4Address) {
                        val host = addr.hostAddress ?: continue
                        rawCandidates.add(
                            NetworkInterfaceCandidate(
                                interfaceName = iface.name ?: "",
                                displayName = iface.displayName,
                                ipv4Address = host,
                                isUp = iface.isUp,
                                isLoopback = iface.isLoopback,
                                isPointToPoint = iface.isPointToPoint,
                                isVirtual = iface.isVirtual
                            )
                        )
                    }
                }
            }
            rankLocalIpv4Candidates(rawCandidates)
        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * Resolve the highest-priority local IPv4 address for Wi-Fi or Hotspot interfaces.
     */
    fun getLocalIpv4Address(): String? = enumerateLocalIpv4Candidates().firstOrNull()

    /**
     * User-controlled setting to opt into Direct Phone-to-Phone Host Mode.
     * Defaults to false (OFF). Must be explicitly enabled by user action.
     */
    fun setHostModeSettingEnabled(enabled: Boolean) {
        hostModeSettingEnabled.set(enabled)
        if (!enabled) {
            disableHostMode()
        }
        SafeLog.i(TAG, "Direct Phone-to-Phone Host Mode setting set to: $enabled")
    }

    fun isHostModeSettingEnabled(): Boolean = hostModeSettingEnabled.get()

    @Synchronized
    fun isPinLockedOut(): Boolean {
        val now = clockMillis()
        if (lockoutUntilMillis > now) return true
        if (lockoutUntilMillis > 0L && now >= lockoutUntilMillis) {
            lockoutUntilMillis = 0L
            failedPinAttempts = 0
        }
        return false
    }

    @Synchronized
    fun getRemainingLockoutSeconds(): Long {
        val rem = lockoutUntilMillis - clockMillis()
        return if (rem > 0L) (rem + 999L) / 1000L else 0L
    }

    /**
     * Generate an ephemeral single-use 6-digit pairing PIN with a 60-second validity window.
     * Enforces lockout cooldown across repeated dialog re-opens.
     */
    @Synchronized
    fun generatePairingPin(): String {
        val now = clockMillis()
        if (isPinLockedOut()) {
            val remSec = getRemainingLockoutSeconds()
            _hostState.value = _hostState.value.copy(
                pairingPin = null,
                pinExpiresInSeconds = 0L,
                isPairingLocked = true,
                lockoutRemainingSeconds = remSec,
                errorMessage = "Pairing temporarily locked for ${remSec}s due to repeated invalid attempts."
            )
            return ""
        }
        val pinVal = String.format("%06d", secureRandom.nextInt(1_000_000))
        currentEphemeralPin = EphemeralPin(
            pin = pinVal,
            expiresAtMillis = now + PIN_VALIDITY_MS,
            isConsumed = false
        )
        _hostState.value = _hostState.value.copy(
            pairingPin = pinVal,
            pinExpiresInSeconds = PIN_VALIDITY_MS / 1000L,
            isPairingLocked = false,
            lockoutRemainingSeconds = 0L,
            errorMessage = null
        )
        SafeLog.i(TAG, "Generated ephemeral 6-digit pairing PIN (valid for ${PIN_VALIDITY_MS / 1000L}s)")
        return pinVal
    }

    @Synchronized
    fun cancelPairingPin() {
        currentEphemeralPin = null
        currentHandshakeToken = null
        _hostState.value = _hostState.value.copy(
            pairingPin = null,
            pinExpiresInSeconds = 0L,
            isPairingLocked = isPinLockedOut(),
            lockoutRemainingSeconds = getRemainingLockoutSeconds()
        )
        SafeLog.i(TAG, "Cancelled active pairing PIN and handshake token.")
    }

    @Synchronized
    internal fun setHostStateForTesting(state: PeerHostState) {
        _hostState.value = state
        activePort = state.port
    }

    /**
     * Generate a cryptographically random, single-use QR handshake token valid for 60 seconds.
     */
    @Synchronized
    fun generateHandshakeToken(networkId: String? = configuredNetworkId): String {
        val now = clockMillis()
        val raw = ByteArray(24)
        secureRandom.nextBytes(raw)
        val tok = Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
        currentHandshakeToken = EphemeralHandshakeToken(
            token = tok,
            expiresAtMillis = now + HANDSHAKE_TOKEN_VALIDITY_MS,
            networkId = networkId?.trim()?.uppercase()?.takeIf { it.isNotBlank() },
            isConsumed = false
        )
        SafeLog.i(TAG, "Generated ephemeral single-use QR handshake token (valid for ${HANDSHAKE_TOKEN_VALIDITY_MS / 1000L}s)")
        return tok
    }

    @Synchronized
    fun getCurrentHandshakeTokenInfo(): Pair<String, Long>? {
        val now = clockMillis()
        val t = currentHandshakeToken ?: return null
        if (t.isConsumed || now > t.expiresAtMillis) {
            return null
        }
        return t.token to (t.expiresAtMillis - now)
    }

    /**
     * Verify and consume a single-use QR handshake token with optional network_id enforcement.
     */
    @Synchronized
    fun verifyAndConsumeHandshakeToken(inputToken: String?, networkId: String? = null): Boolean {
        val now = clockMillis()
        val presented = inputToken?.trim() ?: return false
        if (presented.length < 16) return false
        val tokObj = currentHandshakeToken ?: return false
        if (tokObj.isConsumed) {
            SafeLog.w(TAG, "QR handshake token has already been consumed.")
            return false
        }
        if (now > tokObj.expiresAtMillis) {
            SafeLog.w(TAG, "QR handshake token has expired.")
            currentHandshakeToken = null
            return false
        }
        val expectedNet = tokObj.networkId ?: configuredNetworkId
        val cleanPresentedNet = networkId?.trim()?.uppercase()?.takeIf { it.isNotBlank() }
        if (!expectedNet.isNullOrBlank()) {
            if (cleanPresentedNet != expectedNet) {
                SafeLog.w(TAG, "QR handshake network_id mismatch: expected=$expectedNet presented=$cleanPresentedNet")
                return false
            }
        }
        val matches = MessageDigest.isEqual(
            presented.toByteArray(Charsets.UTF_8),
            tokObj.token.toByteArray(Charsets.UTF_8)
        )
        if (matches) {
            tokObj.isConsumed = true
            SafeLog.i(TAG, "QR handshake token successfully verified and consumed.")
            return true
        }
        SafeLog.w(TAG, "QR handshake token mismatch.")
        return false
    }

    @Synchronized
    fun resetPersistedIdentity() {
        try {
            certStorage?.clear()
        } catch (_: Exception) {}
        failedPinAttempts = 0
        lockoutUntilMillis = 0L
    }

    /**
     * Generate QR pairing payload (v1 or v2) including all ranked local candidate IPs.
     *
     * When [includePin] is false and version == 2, generates a live zero-PIN QR payload
     * backed by a single-use cryptographic handshake token (only including any already-active PIN).
     */
    @Synchronized
    @JvmOverloads
    fun generatePairingQrJson(
        localDeviceId: String,
        snowId: String? = null,
        networkId: String? = null,
        version: Int = 1,
        hubUrl: String? = null,
        rdvId: String? = null,
        includePin: Boolean = true
    ): String? {
        val state = _hostState.value
        val cleanFp = state.certFingerprint.replace(":", "").replace(" ", "").trim().uppercase()
        if (cleanFp.isBlank() || cleanFp == "--") return null

        val rankedCandidates = LinkedHashSet<String>()
        if (state.candidateIps.isNotEmpty()) {
            rankedCandidates.addAll(state.candidateIps.filter { isValidRoutableLocalIpv4(it) })
        }
        if (state.ipAddress != "--" && state.ipAddress.isNotBlank() && isValidRoutableLocalIpv4(state.ipAddress)) {
            rankedCandidates.add(state.ipAddress)
        }
        rankedCandidates.addAll(enumerateLocalIpv4Candidates())
        val ipList = rankedCandidates.toList()
        if (ipList.isEmpty()) return null

        val effectiveNetId = networkId?.trim()?.uppercase()?.takeIf { isValidCanonicalNetworkId(it) }
            ?: configuredNetworkId?.trim()?.uppercase()?.takeIf { isValidCanonicalNetworkId(it) }
            ?: state.networkId?.trim()?.uppercase()?.takeIf { isValidCanonicalNetworkId(it) }
        val activePin = if (includePin || version == 1) {
            getCurrentEphemeralPinInfo()?.first ?: generatePairingPin()
        } else {
            getCurrentEphemeralPinInfo()?.first.orEmpty()
        }
        if (activePin.isBlank() && version == 1) return null
        val activeHandshakeToken = getCurrentHandshakeTokenInfo()?.first ?: generateHandshakeToken(effectiveNetId)
        val effectiveSnowId = snowId?.trim()?.uppercase()?.takeIf { it.isNotBlank() } ?: configuredSnowId
        val expSec = (clockMillis() + HANDSHAKE_TOKEN_VALIDITY_MS) / 1000L

        val json = org.json.JSONObject().apply {
            if (version == 2) {
                put("v", 2)
                put("id", localDeviceId)
                put("device_id", localDeviceId)
                if (!effectiveSnowId.isNullOrBlank()) put("snow_id", effectiveSnowId)
                put("device_type", "android")
                put("network_id", effectiveNetId ?: org.json.JSONObject.NULL)
                put("fp", cleanFp)
                put("port", activePort)
                put("transfer_port", activeMediaPort)
                put("ips", org.json.JSONArray(ipList))
                if (activePin.isNotBlank()) put("pin", activePin)
                put("handshake_token", activeHandshakeToken)
                hubUrl?.trim()?.takeIf { it.isNotBlank() }?.let { put("hub_url", it) }
                rdvId?.trim()?.takeIf { it.isNotBlank() }?.let { put("rdv_id", it) }
                put("exp", expSec)
            } else {
                put("v", 1)
                put("id", localDeviceId)
                if (!effectiveSnowId.isNullOrBlank()) put("snow_id", effectiveSnowId)
                if (!effectiveNetId.isNullOrBlank()) put("network_id", effectiveNetId)
                put("ips", org.json.JSONArray(ipList))
                put("port", activePort)
                put("fp", cleanFp)
                put("pin", activePin)
                put("handshake_token", activeHandshakeToken)
            }
        }
        return json.toString()
    }

    @Synchronized
    fun getCurrentEphemeralPinInfo(): Pair<String, Long>? {
        val now = clockMillis()
        val p = currentEphemeralPin ?: return null
        if (p.isConsumed || now > p.expiresAtMillis) {
            return null
        }
        val remainingMs = p.expiresAtMillis - now
        return Pair(p.pin, remainingMs)
    }

    /**
     * Verify and consume an ephemeral pairing PIN with detailed failure status (expired / locked / remaining attempts).
     */
    @Synchronized
    fun verifyAndConsumePairingPinDetailed(inputPin: String): PinVerificationResult {
        val now = clockMillis()
        if (isPinLockedOut()) {
            val remSec = getRemainingLockoutSeconds()
            SafeLog.w(TAG, "Pairing PIN rejected: pairing is locked out.")
            return PinVerificationResult(
                status = PinVerificationStatus.LOCKED,
                lockoutSeconds = remSec,
                message = "Pairing temporarily locked for ${remSec}s due to repeated invalid PIN attempts."
            )
        }
        val pinObj = currentEphemeralPin ?: return PinVerificationResult(
            status = PinVerificationStatus.EXPIRED,
            message = "No active pairing PIN. Generate a fresh QR code or PIN."
        )
        if (pinObj.isConsumed) {
            SafeLog.w(TAG, "Pairing PIN has already been consumed.")
            return PinVerificationResult(
                status = PinVerificationStatus.EXPIRED,
                message = "Pairing PIN has already been used. Generate a fresh QR code or PIN."
            )
        }
        if (now > pinObj.expiresAtMillis) {
            SafeLog.w(TAG, "Pairing PIN has expired.")
            currentEphemeralPin = null
            _hostState.value = _hostState.value.copy(pairingPin = null, pinExpiresInSeconds = 0L)
            return PinVerificationResult(
                status = PinVerificationStatus.EXPIRED,
                message = "Pairing PIN expired after ${PIN_VALIDITY_MS / 1000L}s. Generate a fresh QR code or PIN."
            )
        }
        val submitted = inputPin.trim()
        val validSyntax = submitted.length == 6 && submitted.all { it.isDigit() }
        val match = validSyntax && MessageDigest.isEqual(
            pinObj.pin.toByteArray(Charsets.UTF_8),
            submitted.toByteArray(Charsets.UTF_8)
        )
        if (match) {
            pinObj.isConsumed = true
            failedPinAttempts = 0
            lockoutUntilMillis = 0L
            _hostState.value = _hostState.value.copy(
                pairingPin = null,
                pinExpiresInSeconds = 0L,
                isPairingLocked = false,
                lockoutRemainingSeconds = 0L
            )
            SafeLog.i(TAG, "Pairing PIN successfully verified and consumed.")
            return PinVerificationResult(
                status = PinVerificationStatus.SUCCESS,
                message = "PIN verified"
            )
        }
        failedPinAttempts++
        return if (failedPinAttempts >= MAX_FAILED_PIN_ATTEMPTS) {
            lockoutUntilMillis = now + LOCKOUT_COOLDOWN_MS
            currentEphemeralPin = null
            currentHandshakeToken = null
            val remSec = LOCKOUT_COOLDOWN_MS / 1000L
            _hostState.value = _hostState.value.copy(
                pairingPin = null,
                pinExpiresInSeconds = 0L,
                isPairingLocked = true,
                lockoutRemainingSeconds = remSec
            )
            SafeLog.w(TAG, "Pairing PIN locked for ${remSec}s after $failedPinAttempts failed attempts.")
            PinVerificationResult(
                status = PinVerificationStatus.LOCKED,
                lockoutSeconds = remSec,
                message = "Pairing locked for ${remSec}s after $MAX_FAILED_PIN_ATTEMPTS failed attempts."
            )
        } else {
            val remaining = (MAX_FAILED_PIN_ATTEMPTS - failedPinAttempts).coerceAtLeast(1)
            SafeLog.w(TAG, "Pairing PIN mismatch (attempt $failedPinAttempts/$MAX_FAILED_PIN_ATTEMPTS).")
            PinVerificationResult(
                status = PinVerificationStatus.INVALID_PIN,
                remainingAttempts = remaining,
                message = "Invalid pairing PIN ($remaining attempts remaining)."
            )
        }
    }

    /**
     * Verify and consume an ephemeral pairing PIN with single-use semantics and 3-attempt lockout.
     */
    @Synchronized
    fun verifyAndConsumePairingPin(inputPin: String): Boolean {
        return verifyAndConsumePairingPinDetailed(inputPin).status == PinVerificationStatus.SUCCESS
    }

    @Synchronized
    fun setConfiguredNetworkId(networkId: String?) {
        val clean = networkId?.trim()?.uppercase()?.takeIf { isValidCanonicalNetworkId(it) }
        configuredNetworkId = clean
        _hostState.value = _hostState.value.copy(networkId = clean)
    }

    @Synchronized
    fun resolveMergeDecision(txId: String, decision: String, actingDeviceId: String): NetworkMergeCommandResult {
        val prop = mergeProposals[txId]
            ?: return NetworkMergeCommandResult(
                success = false,
                errorCode = org.snow.protocol.ErrorCode.INVALID_PAYLOAD,
                errorMessage = "Merge transaction '$txId' not found."
            )
        val cleanDecision = decision.trim().lowercase()
        if (cleanDecision == "keep_separate" || cleanDecision == "reject") {
            prop.status = "REJECTED"
            return NetworkMergeCommandResult(
                success = true,
                committed = false,
                networkAction = "KEEP_SEPARATE",
                networkId = prop.sourceNetworkId,
                relationship = "external_network"
            )
        }
        val cleanActor = actingDeviceId.trim()
        if (cleanActor != prop.sourceOwnerDeviceId && cleanActor != prop.targetOwnerDeviceId) {
            return NetworkMergeCommandResult(
                success = false,
                errorCode = org.snow.protocol.ErrorCode.UNAUTHORIZED,
                errorMessage = "Only network owners can authorize a network merge."
            )
        }
        if (cleanActor == prop.sourceOwnerDeviceId) prop.sourceOwnerApproved = true
        if (cleanActor == prop.targetOwnerDeviceId) prop.targetOwnerApproved = true
        return if (prop.sourceOwnerApproved && prop.targetOwnerApproved) {
            prop.status = "COMMITTED"
            setConfiguredNetworkId(prop.survivingNetworkId)
            onHostNetworkUpdatedCallback?.invoke(prop.survivingNetworkId)
            NetworkMergeCommandResult(
                success = true,
                committed = true,
                networkAction = "MERGED",
                networkId = prop.survivingNetworkId,
                relationship = "member"
            )
        } else {
            NetworkMergeCommandResult(
                success = true,
                committed = false,
                networkAction = "MERGE_APPROVAL_REQUIRED",
                networkId = prop.sourceNetworkId,
                relationship = "external_network"
            )
        }
    }

    /**
     * Enable foreground peer host mode, starting the listening server with mandatory persisted TLS.
     * Fails closed if persisted keystore material is corrupt.
     */
    @Synchronized
    @JvmOverloads
    fun enableHostMode(
        port: Int = DEFAULT_HOST_PORT,
        tokenStorage: TokenStorage,
        dispatcher: AndroidCapabilityDispatcher,
        localDeviceId: String,
        manifestProvider: () -> Map<String, Any?> = { emptyMap() },
        peerTokenValidator: ((String) -> Boolean)? = null,
        parentScope: CoroutineScope? = null,
        mediaPort: Int = 0,
        snowId: String? = null,
        networkId: String? = null,
        transferStorageDir: java.io.File? = null,
        perDeviceProfileProvider: ((String) -> String)? = null,
        freeSpaceProvider: ((java.io.File) -> Long)? = null,
        onHostNetworkUpdated: ((String?) -> Unit)? = null
    ): Boolean {
        if (!hostModeSettingEnabled.get()) {
            SafeLog.w(
                TAG,
                "Direct Phone-to-Phone Host Mode is disabled by user setting. Refusing to start TCP server."
            )
            disableHostMode()
            return false
        }

        if (isRunning.get() && server != null && server!!.isListening()) {
            SafeLog.i(TAG, "Foreground host mode is already active on port $activePort")
            return true
        }

        disableHostMode()
        configuredSnowId = snowId?.trim()?.uppercase()?.takeIf { it.isNotBlank() }
        configuredNetworkId = networkId?.trim()?.uppercase()?.takeIf { isValidCanonicalNetworkId(it) }
        configuredLocalDeviceId = localDeviceId.trim()
        onHostNetworkUpdatedCallback = onHostNetworkUpdated

        val certResult = try {
            AndroidSelfSignedCertGenerator.loadOrCreate(
                storage = certStorage,
                regenerateOnCorruption = false
            )
        } catch (e: Exception) {
            SafeLog.e(TAG, "Peer Host TLS keystore load failed (failing closed): ${e.message}", e)
            _hostState.value = _hostState.value.copy(
                isActive = false,
                certFingerprint = "--",
                errorMessage = "Persisted TLS keystore error: ${e.message}"
            )
            return false
        }

        val newServer = AndroidPeerHostServer(
            requestedPort = port,
            tokenStorage = tokenStorage,
            dispatcher = dispatcher,
            localDeviceId = localDeviceId,
            manifestProvider = manifestProvider,
            peerTokenValidator = peerTokenValidator,
            pinVerifier = { verifyAndConsumePairingPin(it) },
            parentScope = parentScope,
            sslContext = certResult.sslContext,
            handshakeTokenVerifier = { tok, net -> verifyAndConsumeHandshakeToken(tok, net) },
            hostSnowId = configuredSnowId,
            hostNetworkId = configuredNetworkId,
            defaultMediaPort = if (mediaPort > 0) mediaPort else DEFAULT_MEDIA_PORT,
            hostNetworkIdProvider = { configuredNetworkId },
            pinDetailedVerifier = { verifyAndConsumePairingPinDetailed(it) },
            onNetworkNegotiated = { outcome ->
                val effectiveNet = outcome.effectiveHostNetworkId?.trim()?.uppercase()
                if (effectiveNet != null && effectiveNet != configuredNetworkId) {
                    setConfiguredNetworkId(effectiveNet)
                    onHostNetworkUpdatedCallback?.invoke(effectiveNet)
                }
                if (outcome.networkConflict && !outcome.mergeTxId.isNullOrBlank() &&
                    effectiveNet != null && !outcome.peerNetworkId.isNullOrBlank()
                ) {
                    mergeProposals[outcome.mergeTxId] = MergeProposalRecord(
                        txId = outcome.mergeTxId,
                        sourceNetworkId = effectiveNet,
                        targetNetworkId = outcome.peerNetworkId,
                        survivingNetworkId = outcome.survivingNetworkId ?: effectiveNet,
                        sourceOwnerDeviceId = configuredLocalDeviceId,
                        targetOwnerDeviceId = outcome.peerDeviceId,
                        sourceOwnerApproved = false,
                        targetOwnerApproved = outcome.networkAction == "MERGE_APPROVAL_REQUIRED",
                        status = "PENDING"
                    )
                }
            },
            mergeDecisionHandler = { txId, decision, actingDev ->
                resolveMergeDecision(txId, decision, actingDev)
            },
            perDeviceProfileProvider = perDeviceProfileProvider
        )

        val success = newServer.start()
        if (success) {
            server = newServer
            activePort = newServer.boundPort
            isRunning.set(true)
            activeMediaPort = if (mediaPort > 0) mediaPort else 0
            if (mediaPort > 0) {
                val ms = AndroidPeerMediaServer(
                    requestedPort = mediaPort,
                    sslContext = certResult.sslContext,
                    tokenStorage = tokenStorage,
                    peerTokenValidator = peerTokenValidator,
                    activeProfileProvider = { dispatcher.activePermissionProfile },
                    storageRootDir = transferStorageDir,
                    perDeviceProfileProvider = perDeviceProfileProvider,
                    freeSpaceProvider = freeSpaceProvider
                )
                if (ms.start()) {
                    mediaServer = ms
                    activeMediaPort = ms.boundPort
                }
            }
            val rankedIps = enumerateLocalIpv4Candidates()
            val ip = rankedIps.firstOrNull() ?: "127.0.0.1"
            val pinRemainingSec = getCurrentEphemeralPinInfo()?.let { (_, rem) -> (rem + 999L) / 1000L } ?: 0L
            _hostState.value = PeerHostState(
                isActive = true,
                ipAddress = ip,
                candidateIps = rankedIps,
                port = activePort,
                mediaPort = activeMediaPort,
                certFingerprint = certResult.fingerprint,
                peerCount = 0,
                pairingPin = currentEphemeralPin?.pin,
                pinExpiresInSeconds = pinRemainingSec,
                isPairingLocked = isPinLockedOut(),
                lockoutRemainingSeconds = getRemainingLockoutSeconds(),
                errorMessage = null,
                networkId = configuredNetworkId
            )
            SafeLog.i(TAG, "Foreground host mode enabled on $ip:$activePort (media=$activeMediaPort, candidates=${rankedIps.size})")
        } else {
            newServer.stop()
            server = null
            isRunning.set(false)
            _hostState.value = _hostState.value.copy(isActive = false, errorMessage = "Failed to bind port $port")
            SafeLog.e(TAG, "Failed to enable foreground host mode on port $port")
        }
        return success
    }

    /**
     * Disable foreground peer host mode and close listening sockets.
     */
    @Synchronized
    fun disableHostMode() {
        currentEphemeralPin = null
        currentHandshakeToken = null
        if (!isRunning.getAndSet(false) && server == null) {
            _hostState.value = PeerHostState(isActive = false, ipAddress = "--", port = activePort)
            return
        }
        SafeLog.i(TAG, "Disabling foreground peer host mode...")
        try {
            mediaServer?.stop()
        } catch (_: Exception) {}
        mediaServer = null
        try {
            server?.stop()
        } catch (e: Exception) {
            SafeLog.w(TAG, "Error stopping peer host server: ${e.message}")
        }
        server = null
        _hostState.value = PeerHostState(
            isActive = false,
            ipAddress = "--",
            port = activePort,
            certFingerprint = "--",
            peerCount = 0,
            pairingPin = null,
            pinExpiresInSeconds = 0L,
            errorMessage = null,
            networkId = configuredNetworkId
        )
        SafeLog.i(TAG, "Foreground peer host mode disabled.")
    }

    /**
     * Return True if foreground peer host mode is actively listening.
     */
    fun isHostModeActive(): Boolean {
        return isRunning.get() && server != null && server!!.isListening()
    }

    fun listAuthenticatedPeers(): List<String> = server?.listAuthenticatedPeerDeviceIds() ?: emptyList()

    suspend fun sendRequestToPeer(
        targetDeviceId: String,
        action: String,
        data: Map<String, Any?> = emptyMap(),
        timeoutMs: Long = 20_000L
    ): Pair<Map<String, Any?>?, String?> {
        val srv = server ?: return null to "DEVICE_OFFLINE: Android Peer Host is not active."
        return srv.sendRequestToPeer(targetDeviceId, action, data, timeoutMs)
    }

    /**
     * Return the live reachability profile governed by host mode state.
     */
    fun getReachabilityProfile(): ReachabilityProfile {
        return if (isHostModeActive()) {
            ReachabilityProfile.FOREGROUND_HOST
        } else {
            ReachabilityProfile.ACTIVE_SESSION_PEER
        }
    }
}
