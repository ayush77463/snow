package org.snow.network

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import org.snow.protocol.Constants
import org.snow.security.CertPinStorage
import org.snow.security.SafeLog
import org.snow.security.TokenStorage
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.abs

/**
 * Representation of a discovered network peer on the local subnet.
 */
data class DiscoveredPeer(
    val deviceId: String,
    val deviceName: String,
    val deviceType: String,
    val ipAddress: String,
    val port: Int,
    val transferPort: Int,
    val certFingerprint: String,
    val lastSeenTimestamp: Long = System.currentTimeMillis(),
    val isPaired: Boolean = false,
    val snowId: String? = null,
    val wakeTarget: String? = null
) {
    val isStale: Boolean
        get() = (System.currentTimeMillis() - lastSeenTimestamp) > DiscoveryManager.STALE_TIMEOUT_MS
}

/**
 * Zero-touch UDP discovery listener and candidate tracker for SNOW Android.
 *
 * Listens on UDP port 8768 for periodic JSON beacons broadcast by Desktop Core instances,
 * parses and validates beacon payloads, maintains active candidate records, and correlates
 * with pinned certificate fingerprints to enable automatic seamless reconnection.
 */
class DiscoveryManager(
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
    var certPinStorage: CertPinStorage? = null,
    var tokenStorage: TokenStorage? = null,
    private val port: Int = Constants.DEFAULT_DISCOVERY_PORT,
    var localDeviceId: String? = null,
    var onWakeTargetMatched: ((DiscoveredPeer) -> Unit)? = null
) {
    companion object {
        const val TAG = "DiscoveryManager"
        const val MAX_BEACON_SIZE = 2048
        const val STALE_TIMEOUT_MS = 10_000L
        const val MAX_TIMESTAMP_DRIFT_SEC = 30.0

        fun isRelayEndpoint(host: String?): Boolean {
            val h = host?.trim()?.lowercase().orEmpty()
            return h.contains("relay") || h.contains("tunnel") || h.contains("hub") || h.contains("onrender.com")
        }

        fun shouldPauseDiscovery(
            connectionState: ConnectionState,
            authState: AuthState,
            targetHost: String?
        ): Boolean {
            if (connectionState != ConnectionState.CONNECTED) return false
            if (authState !is AuthState.Authenticated) return false
            if (targetHost.isNullOrBlank() || isRelayEndpoint(targetHost)) return false
            return true
        }

        private val secureRandom = SecureRandom()
        const val DEFAULT_BEACON_INTERVAL_MS = 3000L
        const val MIN_BEACON_INTERVAL_MS = 1500L

        /**
         * Serialize an untrusted SNOW UDP discovery beacon (<= 2048 bytes, zero secrets/PINs/tokens).
         */
        @JvmOverloads
        fun createBeaconPayload(
            deviceId: String,
            deviceName: String,
            deviceType: String = "android",
            port: Int,
            transferPort: Int,
            certFingerprint: String,
            snowId: String? = null,
            ips: List<String> = emptyList(),
            wakeTarget: String? = null,
            timestampSec: Double = System.currentTimeMillis() / 1000.0,
            nonce: String? = null
        ): ByteArray {
            require(deviceId.isNotBlank()) { "device_id must not be blank" }
            require(port in 1..65535) { "Invalid discovery port: $port" }
            require(transferPort in 0..65535) { "Invalid transfer port: $transferPort" }
            val cleanNonce = nonce?.takeIf { it.isNotBlank() } ?: ByteArray(16).also {
                secureRandom.nextBytes(it)
            }.joinToString("") { "%02x".format(it) }
            val cleanFp = certFingerprint.replace(":", "").replace(" ", "").trim().uppercase()

            val obj = JSONObject().apply {
                put("proto", "snow-discovery")
                put("v", 1)
                put("device_id", deviceId.trim())
                put("device_name", deviceName.ifBlank { "Android Peer" })
                put("device_type", deviceType.ifBlank { "android" })
                put("port", port)
                put("transfer_port", transferPort)
                put("cert_fingerprint", cleanFp)
                put("timestamp", timestampSec)
                put("nonce", cleanNonce)
                snowId?.trim()?.uppercase()?.takeIf { it.isNotBlank() }?.let { put("snow_id", it) }
                wakeTarget?.trim()?.takeIf { it.isNotBlank() }?.let { put("wake_target", it) }
                val cleanIps = ips.map { it.trim() }.filter { it.isNotEmpty() }.distinct()
                if (cleanIps.isNotEmpty()) {
                    put("ips", org.json.JSONArray(cleanIps))
                }
            }
            var raw = obj.toString().toByteArray(Charsets.UTF_8)
            if (raw.size > MAX_BEACON_SIZE) {
                obj.remove("ips")
                raw = obj.toString().toByteArray(Charsets.UTF_8)
            }
            require(raw.size <= MAX_BEACON_SIZE) { "Discovery beacon exceeds $MAX_BEACON_SIZE bytes" }
            return raw
        }

        fun resolveBroadcastDestinations(candidateIps: List<String>): List<String> {
            val targets = linkedSetOf("255.255.255.255")
            for (raw in candidateIps) {
                val clean = raw.trim()
                val octets = clean.split('.')
                if (octets.size == 4 && octets.all { it.toIntOrNull() in 0..255 }) {
                    val first = octets[0].toInt()
                    val second = octets[1].toInt()
                    if (first != 127 && !(first == 169 && second == 254) && first != 0 && first < 224) {
                        targets.add("${octets[0]}.${octets[1]}.${octets[2]}.255")
                    }
                }
            }
            return targets.toList()
        }

        /**
         * Pure parsing and validation function for an incoming discovery beacon datagram.
         */
        fun parseBeacon(
            data: ByteArray,
            length: Int,
            remoteIp: String,
            currentTimeMs: Long = System.currentTimeMillis()
        ): DiscoveredPeer? {
            if (length <= 0 || length > MAX_BEACON_SIZE) {
                return null
            }

            return try {
                val jsonStr = String(data, 0, length, Charsets.UTF_8)
                val json = JSONObject(jsonStr)

                if (json.optString("proto") != "snow-discovery") return null
                if (json.optInt("v", -1) != 1) return null

                val devId = json.optString("device_id").trim()
                if (devId.isEmpty()) return null

                val devName = json.optString("device_name", "Unknown Desktop")
                val devType = json.optString("device_type", "windows")

                val peerPort = json.optInt("port", -1)
                if (peerPort !in 1..65535) return null

                val xferPort = json.optInt("transfer_port", 0)
                if (xferPort !in 0..65535) return null

                val certFp = json.optString("cert_fingerprint", "").trim()
                val snowId = json.optString("snow_id", "").trim().takeIf { it.isNotBlank() }
                val wakeTarget = json.optString("wake_target", "").trim().takeIf { it.isNotBlank() }

                val ts = json.optDouble("timestamp", Double.NaN)
                if (ts.isNaN() || ts.isInfinite()) return null

                val nowSec = currentTimeMs / 1000.0
                if (abs(nowSec - ts) > MAX_TIMESTAMP_DRIFT_SEC) {
                    SafeLog.w(TAG, "Dropped beacon with excessive timestamp drift: delta=${abs(nowSec - ts)}s")
                    return null
                }

                DiscoveredPeer(
                    deviceId = devId,
                    deviceName = devName,
                    deviceType = devType,
                    ipAddress = remoteIp,
                    port = peerPort,
                    transferPort = xferPort,
                    certFingerprint = certFp,
                    lastSeenTimestamp = currentTimeMs,
                    snowId = snowId,
                    wakeTarget = wakeTarget
                )
            } catch (e: Exception) {
                SafeLog.w(TAG, "Failed parsing discovery beacon: ${e.message}")
                null
            }
        }
    }

    private val _peers = MutableStateFlow<List<DiscoveredPeer>>(emptyList())
    val peers: StateFlow<List<DiscoveredPeer>> = _peers.asStateFlow()

    private val peerMap = ConcurrentHashMap<String, DiscoveredPeer>()
    private val rateLimits = ConcurrentHashMap<String, ArrayDeque<Long>>()
    private var socket: DatagramSocket? = null
    private var beaconSocket: DatagramSocket? = null
    private var listenJob: Job? = null
    private var pruneJob: Job? = null
    private var beaconJob: Job? = null
    private var isListening = false
    @Volatile
    private var isBeaconActive = false

    fun isPeerHostBeaconActive(): Boolean = isBeaconActive && beaconJob?.isActive == true

    /**
     * Broadcast a periodic UDP discovery beacon on port 8768 while Android Peer Host mode is active.
     * Untrusted metadata only; never exposes PINs, tokens, or private keys.
     */
    @Synchronized
    fun startPeerHostBeacon(
        deviceId: String,
        deviceName: String,
        port: Int,
        transferPort: Int,
        certFingerprint: String,
        snowId: String? = null,
        candidateIpsProvider: () -> List<String> = { emptyList() },
        intervalMs: Long = DEFAULT_BEACON_INTERVAL_MS
    ): Boolean {
        if (deviceId.isBlank() || port !in 1..65535) return false
        stopPeerHostBeacon()
        localDeviceId = deviceId.trim()
        val effectiveIntervalMs = intervalMs.coerceAtLeast(MIN_BEACON_INTERVAL_MS)

        return try {
            val sock = DatagramSocket().apply {
                broadcast = true
                reuseAddress = true
            }
            beaconSocket = sock
            isBeaconActive = true

            beaconJob = scope.launch {
                while (isActive && isBeaconActive) {
                    try {
                        val candidateIps = candidateIpsProvider()
                        val payload = createBeaconPayload(
                            deviceId = deviceId,
                            deviceName = deviceName,
                            deviceType = "android",
                            port = port,
                            transferPort = transferPort,
                            certFingerprint = certFingerprint,
                            snowId = snowId,
                            ips = candidateIps
                        )
                        val destinations = resolveBroadcastDestinations(candidateIps)
                        for (destIp in destinations) {
                            try {
                                val targetAddr = InetAddress.getByName(destIp)
                                sock.send(DatagramPacket(payload, payload.size, targetAddr, this@DiscoveryManager.port))
                            } catch (_: Exception) {
                            }
                        }
                    } catch (e: Exception) {
                        if (isActive && isBeaconActive) {
                            SafeLog.w(TAG, "UDP beacon transmit error: ${e.message}")
                        }
                    }
                    delay(effectiveIntervalMs)
                }
            }
            SafeLog.i(TAG, "Started peer host UDP beacon on port $port (target UDP ${this.port}, interval=${effectiveIntervalMs}ms)")
            true
        } catch (e: Exception) {
            SafeLog.w(TAG, "Failed starting peer host UDP beacon: ${e.message}")
            stopPeerHostBeacon()
            false
        }
    }

    @Synchronized
    fun stopPeerHostBeacon() {
        isBeaconActive = false
        beaconJob?.cancel()
        beaconJob = null
        try {
            beaconSocket?.close()
        } catch (_: Exception) {}
        beaconSocket = null
    }

    /**
     * Start background UDP socket listener and peer prune job.
     */
    @Synchronized
    fun startListening() {
        if (isListening && listenJob?.isActive == true) return
        listenJob?.cancel()
        pruneJob?.cancel()
        try {
            socket?.close()
        } catch (_: Exception) {}
        socket = null

        try {
            val sock = DatagramSocket(null).apply {
                reuseAddress = true
                broadcast = true
                bind(InetSocketAddress("0.0.0.0", port))
            }
            socket = sock
            isListening = true
            SafeLog.i(TAG, "DiscoveryManager listening on UDP port $port")

            listenJob = scope.launch {
                val buffer = ByteArray(MAX_BEACON_SIZE)
                val packet = DatagramPacket(buffer, buffer.size)

                while (isActive && isListening) {
                    try {
                        sock.receive(packet)
                        val remoteIp = packet.address?.hostAddress ?: "127.0.0.1"
                        if (!isRateLimited(remoteIp)) {
                            val peer = parseBeacon(packet.data, packet.length, remoteIp)
                            if (peer != null) {
                                handleDiscoveredPeer(peer)
                            }
                        }
                    } catch (e: Exception) {
                        if (isActive && isListening) {
                            SafeLog.w(TAG, "UDP receive error: ${e.message}")
                        }
                    }
                }
            }

            pruneJob = scope.launch {
                while (isActive && isListening) {
                    delay(3000L)
                    pruneStalePeers()
                }
            }
        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed starting DiscoveryManager on port $port: ${e.message}")
            stopListening()
        }
    }

    private fun isRateLimited(remoteIp: String, nowMs: Long = System.currentTimeMillis()): Boolean {
        val queue = rateLimits.computeIfAbsent(remoteIp) { ArrayDeque() }
        synchronized(queue) {
            while (queue.isNotEmpty() && nowMs - queue.first() > 2000L) {
                queue.removeFirst()
            }
            if (queue.size >= 25) return true
            queue.addLast(nowMs)
            return false
        }
    }

    /**
     * Ingest a valid parsed peer record, determine pairing status, and emit updated flow.
     */
    fun handleDiscoveredPeer(peer: DiscoveredPeer) {
        val myId = localDeviceId?.trim()
        if (!myId.isNullOrBlank() && peer.deviceId.equals(myId, ignoreCase = true)) {
            return
        }
        val pinnedFp = certPinStorage?.getPinnedFingerprintForDevice(peer.deviceId)
            ?: if (certPinStorage?.listPinnedDeviceIds().isNullOrEmpty()) certPinStorage?.getPinnedFingerprint() else null
        val tokStorage = tokenStorage
        val hasToken = if (tokStorage == null) {
            true
        } else {
            tokStorage.hasTokenForDevice(peer.deviceId) ||
                (tokStorage.listStoredDeviceIds().isEmpty() && tokStorage.hasToken())
        }

        val isPaired = !pinnedFp.isNullOrBlank() &&
            peer.certFingerprint.isNotBlank() &&
            hasToken &&
            peer.certFingerprint.replace(":", "").equals(pinnedFp.replace(":", ""), ignoreCase = true)

        val enriched = peer.copy(isPaired = isPaired)
        peerMap[peer.deviceId] = enriched
        publishPeers()

        val targetId = peer.wakeTarget?.trim()
        if (isPaired && !targetId.isNullOrBlank() && !myId.isNullOrBlank() && targetId == myId) {
            onWakeTargetMatched?.invoke(enriched)
        }
    }

    private fun pruneStalePeers() {
        val now = System.currentTimeMillis()
        var changed = false
        val iterator = peerMap.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value.lastSeenTimestamp > STALE_TIMEOUT_MS) {
                iterator.remove()
                changed = true
            }
        }
        if (changed) {
            publishPeers()
        }
    }

    private fun publishPeers() {
        _peers.value = peerMap.values.toList()
    }

    /**
     * Check if an active discovered peer matches the saved desktop certificate fingerprint or deviceId.
     */
    fun getCandidateForPairedDesktop(pairedDeviceId: String? = null): DiscoveredPeer? {
        val explicitPin = pairedDeviceId?.let { certPinStorage?.getPinnedFingerprintForDevice(it) }
            ?.replace(":", "")?.lowercase()
        val legacyPin = if (certPinStorage?.listPinnedDeviceIds().isNullOrEmpty()) {
            certPinStorage?.getPinnedFingerprint()?.replace(":", "")?.lowercase()
        } else null
        return peerMap.values.firstOrNull { peer ->
            if (peer.isStale) return@firstOrNull false
            val peerFpClean = peer.certFingerprint.replace(":", "").lowercase()
            val perDevPin = certPinStorage?.getPinnedFingerprintForDevice(peer.deviceId)
                ?.replace(":", "")?.lowercase()
            val expectedPin = explicitPin ?: perDevPin ?: legacyPin
            val fpMatch = !expectedPin.isNullOrBlank() && peerFpClean == expectedPin
            val matchedByFpIndex = peerFpClean.isNotBlank() && certPinStorage?.findDeviceIdByFingerprint(peer.certFingerprint) != null
            val idMatch = !pairedDeviceId.isNullOrBlank() && peer.deviceId == pairedDeviceId
            fpMatch || matchedByFpIndex || idMatch
        }
    }

    /**
     * Stop listener, beacon, and prune jobs cleanly.
     */
    @Synchronized
    fun stopListening() {
        isListening = false
        stopPeerHostBeacon()
        listenJob?.cancel()
        listenJob = null
        pruneJob?.cancel()
        pruneJob = null

        try {
            socket?.close()
        } catch (_: Exception) {}
        socket = null

        peerMap.clear()
        rateLimits.clear()
        _peers.value = emptyList()
        SafeLog.i(TAG, "DiscoveryManager stopped cleanly.")
    }
}
