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
import java.net.InetSocketAddress
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

                val devId = json.optString("device_id")
                if (devId.isNullOrBlank()) return null

                val devName = json.optString("device_name", "Unknown Desktop")
                val devType = json.optString("device_type", "windows")

                val peerPort = json.optInt("port", -1)
                if (peerPort !in 1..65535) return null

                val xferPort = json.optInt("transfer_port", 0)
                val certFp = json.optString("cert_fingerprint", "")
                val snowId = json.optString("snow_id", "").takeIf { it.isNotBlank() }
                val wakeTarget = json.optString("wake_target", "").takeIf { it.isNotBlank() }

                val ts = json.optDouble("timestamp", Double.NaN)
                if (ts.isNaN()) return null

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
    private var socket: DatagramSocket? = null
    private var listenJob: Job? = null
    private var pruneJob: Job? = null
    private var isListening = false

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
                        val peer = parseBeacon(packet.data, packet.length, remoteIp)

                        if (peer != null) {
                            handleDiscoveredPeer(peer)
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

    /**
     * Ingest a valid parsed peer record, determine pairing status, and emit updated flow.
     */
    fun handleDiscoveredPeer(peer: DiscoveredPeer) {
        val pinnedFp = certPinStorage?.getPinnedFingerprintForDevice(peer.deviceId)
            ?: if (certPinStorage?.listPinnedDeviceIds().isNullOrEmpty()) certPinStorage?.getPinnedFingerprint() else null
        val hasToken = (tokenStorage?.hasTokenForDevice(peer.deviceId) == true) ||
            (tokenStorage?.listStoredDeviceIds().isNullOrEmpty() && tokenStorage?.hasToken() == true)

        val isPaired = if (!pinnedFp.isNullOrBlank() && peer.certFingerprint.isNotBlank()) {
            peer.certFingerprint.replace(":", "").equals(pinnedFp.replace(":", ""), ignoreCase = true)
        } else if (!pinnedFp.isNullOrBlank()) {
            hasToken
        } else {
            hasToken && certPinStorage?.listPinnedDeviceIds().isNullOrEmpty()
        }

        val enriched = peer.copy(isPaired = isPaired)
        peerMap[peer.deviceId] = enriched
        publishPeers()

        val targetId = peer.wakeTarget?.trim()
        val myId = localDeviceId?.trim()
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
     * Stop listener and prune jobs cleanly.
     */
    @Synchronized
    fun stopListening() {
        isListening = false
        listenJob?.cancel()
        listenJob = null
        pruneJob?.cancel()
        pruneJob = null

        try {
            socket?.close()
        } catch (_: Exception) {}
        socket = null

        peerMap.clear()
        _peers.value = emptyList()
        SafeLog.i(TAG, "DiscoveryManager stopped cleanly.")
    }
}
