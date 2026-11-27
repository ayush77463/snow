package org.snow.network

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.SharedPreferences
import android.provider.Settings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.security.InMemoryCertPinStorage
import org.snow.security.InMemoryPeerHostCertStorage
import org.snow.security.InMemoryTokenStorage
import org.snow.security.PairingFlow
import org.snow.security.PairingState
import org.snow.ui.SnowUiRepository
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.ServerSocket
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * M4.2 Unit 1 (RC-1, RC-2, and Carry-Forward 2.3):
 * - Real SnowWebSocketClient <-> real TLS AndroidPeerHostServer Android-to-Android pairing
 * - EXPLICIT_PAIRING_INITIATOR mode eliminating empty pair_request race collision
 * - Ranked candidate IPv4 prioritization & exclusion + multi-IP sequential QR fallback
 * - UDP port 8768 peer-host beacon lifecycle & strict pairing status gating
 * - Battery Optimization settings fallback contract
 */
@OptIn(ExperimentalCoroutinesApi::class)
class M42Unit1DirectPairingAndDiscoveryTest {

    private class MemPrefs : SharedPreferences {
        private val map = mutableMapOf<String, Any?>()
        override fun getAll(): MutableMap<String, *> = HashMap(map)
        override fun getString(key: String?, defValue: String?): String? = map[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? {
            @Suppress("UNCHECKED_CAST")
            return (map[key] as? Set<String>)?.toMutableSet() ?: defValues
        }
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
            override fun putStringSet(key: String?, values: MutableSet<String>?) = apply {
                if (key != null) pending[key] = values?.toSet()
            }
            override fun putInt(key: String?, value: Int) = apply { if (key != null) pending[key] = value }
            override fun putLong(key: String?, value: Long) = apply { if (key != null) pending[key] = value }
            override fun putFloat(key: String?, value: Float) = apply { if (key != null) pending[key] = value }
            override fun putBoolean(key: String?, value: Boolean) = apply { if (key != null) pending[key] = value }
            override fun remove(key: String?) = apply { if (key != null) removals.add(key) }
            override fun clear() = apply { clearAll = true }
            override fun commit(): Boolean {
                if (clearAll) map.clear()
                for (r in removals) map.remove(r)
                for ((k, v) in pending) {
                    if (v == null) map.remove(k) else map[k] = v
                }
                return true
            }
            override fun apply() { commit() }
        }
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    }

    private lateinit var mainExecutor: java.util.concurrent.ExecutorService
    private lateinit var testDispatcher: kotlinx.coroutines.CoroutineDispatcher
    private val prefsByName = mutableMapOf<String, MemPrefs>()
    private lateinit var tempDir: File
    private lateinit var context: Context
    private lateinit var hostScope: CoroutineScope
    private lateinit var clientScope: CoroutineScope
    private lateinit var hostManager: AndroidPeerHostManager
    private lateinit var hostTokens: InMemoryTokenStorage
    private lateinit var dispatcher: AndroidCapabilityDispatcher
    private var hostPort: Int = 0
    private var mediaPort: Int = 0

    private fun freeTcpPort(): Int {
        ServerSocket(0).use { return it.localPort }
    }

    private fun resetRepoSingleton() {
        val f = SnowUiRepository::class.java.getDeclaredField("instance")
        f.isAccessible = true
        f.set(null, null)
    }

    @Before
    fun setUp() {
        mainExecutor = java.util.concurrent.Executors.newSingleThreadExecutor()
        testDispatcher = mainExecutor.asCoroutineDispatcher()
        Dispatchers.setMain(testDispatcher)
        resetRepoSingleton()
        prefsByName.clear()
        tempDir = File(System.getProperty("java.io.tmpdir"), "snow_m42_u1_${UUID.randomUUID()}").apply { mkdirs() }
        context = object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = tempDir
            override fun getCacheDir(): File = tempDir
            override fun getPackageName(): String = "org.snow"
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences {
                return prefsByName.getOrPut(name ?: "default") { MemPrefs() }
            }
            override fun startForegroundService(service: Intent?): ComponentName? = null
            override fun startService(service: Intent?): ComponentName? = null
        }

        hostScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        clientScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        hostManager = AndroidPeerHostManager(InMemoryPeerHostCertStorage())
        hostTokens = InMemoryTokenStorage()
        dispatcher = AndroidCapabilityDispatcher(context, transferClientProvider = { null })
        hostPort = freeTcpPort()
        mediaPort = freeTcpPort()
    }

    @After
    fun tearDown() {
        SnowUiRepository.batteryIntentLauncherForTest = null
        hostManager.disableHostMode()
        resetRepoSingleton()
        hostScope.cancel()
        clientScope.cancel()
        tempDir.deleteRecursively()
        Dispatchers.resetMain()
        mainExecutor.shutdownNow()
    }

    @Test
    fun testRc1_ExplicitPairingModeEliminatesPinRaceAndCompletesRealTlsPeerPairing() {
        val hostId = "android-host-${UUID.randomUUID().toString().take(8)}"
        hostManager.setHostModeSettingEnabled(true)
        assertTrue(
            hostManager.enableHostMode(
                port = hostPort,
                tokenStorage = hostTokens,
                dispatcher = dispatcher,
                localDeviceId = hostId,
                parentScope = hostScope,
                mediaPort = mediaPort,
                snowId = "SNW-HOST-PEER",
                networkId = "SNW-NET-AAAA1111"
            )
        )
        val hostFp = hostManager.hostState.value.certFingerprint
        assertNotEquals("--", hostFp)

        val clientPins = InMemoryCertPinStorage().apply {
            pinFingerprintForDevice(hostId, hostFp)
        }
        val clientTokens = InMemoryTokenStorage()
        val clientIdentity = org.snow.security.DeviceIdentity(
            deviceId = UUID.randomUUID().toString(),
            deviceName = "Phone B Client",
            createdAt = "2026-11-27T00:00:00Z"
        )
        val wsClient = SnowWebSocketClient(
            scope = clientScope,
            certPinStorage = clientPins,
            tokenStorage = clientTokens,
            useTls = true
        ).apply { autoReconnectEnabled = false }

        val connectLatch = CountDownLatch(1)
        val unauthSeen = AtomicBoolean(false)
        wsClient.authState.let { flow ->
            // Observe via polling below alongside listener wait
            unauthSeen.set(flow.value is AuthState.ConnectedUnauthenticated)
        }
        val pin = hostManager.generatePairingPin()
        val hsToken = hostManager.generateHandshakeToken("SNW-NET-AAAA1111")

        // EXPLICIT_PAIRING_INITIATOR connects WITHOUT auto-emitting empty pair_request
        wsClient.connect(
            host = "127.0.0.1",
            port = hostPort,
            targetDeviceId = hostId,
            mode = ConnectionHandshakeMode.EXPLICIT_PAIRING_INITIATOR
        )
        val deadline = System.currentTimeMillis() + 5000L
        while (System.currentTimeMillis() < deadline) {
            if (wsClient.connectionState.value == ConnectionState.CONNECTED &&
                wsClient.authState.value is AuthState.ConnectedUnauthenticated
            ) {
                connectLatch.countDown()
                break
            }
            Thread.sleep(25)
        }
        assertTrue("Expected ConnectedUnauthenticated over TLS without auth error", connectLatch.await(1, TimeUnit.SECONDS))
        // Crucially, the single-use PIN on Phone A MUST NOT have been consumed or failed by an empty auto pair_request!
        assertNotNull("Host PIN must remain unconsumed while awaiting explicit pairing payload", hostManager.getCurrentEphemeralPinInfo())

        // Complete real handshake_token pairing via PairingFlow over TLS WebSocket
        val pairingFlow = PairingFlow(clientIdentity, clientTokens)
        val pairLatch = CountDownLatch(1)
        val pairResult = AtomicReference<PairingState>()
        assertTrue(
            pairingFlow.submitHandshakeToken(
                handshakeToken = hsToken,
                networkId = "SNW-NET-AAAA1111",
                client = wsClient,
                targetDeviceId = hostId
            ) { state ->
                if (state !is PairingState.InProgress) {
                    pairResult.set(state)
                    pairLatch.countDown()
                }
            }
        )
        assertTrue("Pairing completion callback timed out", pairLatch.await(5, TimeUnit.SECONDS))
        val paired = pairResult.get() as? PairingState.Paired
        assertNotNull("Expected Paired state, got ${pairResult.get()}", paired)
        assertEquals(hostId, paired!!.desktopId)
        assertFalse(paired.authToken.isNullOrBlank())
        assertEquals(paired.authToken, clientTokens.getTokenForDevice(hostId))

        // Replay of the same single-use handshake_token MUST fail!
        val replayClient = SnowWebSocketClient(
            scope = clientScope,
            certPinStorage = clientPins,
            tokenStorage = InMemoryTokenStorage(),
            useTls = true
        ).apply { autoReconnectEnabled = false }
        replayClient.connect("127.0.0.1", hostPort, hostId, ConnectionHandshakeMode.EXPLICIT_PAIRING_INITIATOR)
        val replayConnDeadline = System.currentTimeMillis() + 5000L
        while (System.currentTimeMillis() < replayConnDeadline) {
            if (replayClient.connectionState.value == ConnectionState.CONNECTED) break
            Thread.sleep(25)
        }
        assertEquals(ConnectionState.CONNECTED, replayClient.connectionState.value)
        val replayLatch = CountDownLatch(1)
        val replayState = AtomicReference<PairingState>()
        PairingFlow(clientIdentity, null).submitHandshakeToken(
            handshakeToken = hsToken,
            networkId = "SNW-NET-AAAA1111",
            client = replayClient,
            targetDeviceId = hostId
        ) { state ->
            if (state !is PairingState.InProgress) {
                replayState.set(state)
                replayLatch.countDown()
            }
        }
        assertTrue(replayLatch.await(5, TimeUnit.SECONDS))
        assertTrue(
            "Replayed token must be rejected, got ${replayState.get()}",
            replayState.get() is PairingState.Error ||
                replayState.get() is PairingState.WrongPin ||
                replayState.get() is PairingState.Expired
        )

        // Complete a 6-digit PIN pairing flow too and verify PIN was intact until used here
        val pinClient = SnowWebSocketClient(
            scope = clientScope,
            certPinStorage = clientPins,
            tokenStorage = InMemoryTokenStorage(),
            useTls = true
        ).apply { autoReconnectEnabled = false }
        pinClient.connect("127.0.0.1", hostPort, hostId, ConnectionHandshakeMode.EXPLICIT_PAIRING_INITIATOR)
        val pinConnDeadline = System.currentTimeMillis() + 5000L
        while (System.currentTimeMillis() < pinConnDeadline) {
            if (pinClient.connectionState.value == ConnectionState.CONNECTED) break
            Thread.sleep(25)
        }
        val pinLatch = CountDownLatch(1)
        val pinRes = AtomicReference<PairingState>()
        PairingFlow(clientIdentity, InMemoryTokenStorage()).submitPin(pin, pinClient, hostId) { state ->
            if (state !is PairingState.InProgress) {
                pinRes.set(state)
                pinLatch.countDown()
            }
        }
        assertTrue(pinLatch.await(5, TimeUnit.SECONDS))
        assertTrue("6-digit PIN pairing after handshake token must still succeed, got ${pinRes.get()}", pinRes.get() is PairingState.Paired)

        wsClient.disconnect()
        replayClient.disconnect()
        pinClient.disconnect()
    }

    @Test
    fun testRc2_LocalIpv4CandidateRankingExcludesCellularVpnAndFallbackPairsViaSecondIp() {
        // 1. Verify strict interface ranking & cellular/VPN/loopback/link-local exclusion
        val candidates = listOf(
            NetworkInterfaceCandidate("lo", "Loopback", "127.0.0.1", isUp = true, isLoopback = true),
            NetworkInterfaceCandidate("rmnet_data0", "Cellular LTE", "10.120.45.2", isUp = true),
            NetworkInterfaceCandidate("ccmni0", "5G Modem", "100.64.10.9", isUp = true),
            NetworkInterfaceCandidate("tun0", "WireGuard VPN", "10.8.0.2", isUp = true, isPointToPoint = true),
            NetworkInterfaceCandidate("wg0", "WG Tunnel", "10.9.0.2", isUp = true),
            NetworkInterfaceCandidate("wlan0", "LinkLocal", "169.254.12.34", isUp = true),
            NetworkInterfaceCandidate("eth0", "Ethernet", "192.168.50.10", isUp = true),
            NetworkInterfaceCandidate("wlan0", "Wi-Fi", "192.168.1.44", isUp = true),
            NetworkInterfaceCandidate("ap0", "SoftAP Hotspot", "192.168.43.1", isUp = true),
            NetworkInterfaceCandidate("br0", "Other Private", "172.16.10.5", isUp = true)
        )
        val ranked = AndroidPeerHostManager.rankLocalIpv4Candidates(candidates)
        assertEquals(
            listOf("192.168.43.1", "192.168.1.44", "192.168.50.10", "172.16.10.5"),
            ranked
        )

        // 2. Verify SnowUiRepository.handleQrScanPayload tries IP[0] (unreachable) then succeeds on IP[1] (real host)
        val hostId = "android-host-fb-${UUID.randomUUID().toString().take(8)}"
        hostManager.setHostModeSettingEnabled(true)
        assertTrue(
            hostManager.enableHostMode(
                port = hostPort,
                tokenStorage = hostTokens,
                dispatcher = dispatcher,
                localDeviceId = hostId,
                parentScope = hostScope,
                mediaPort = mediaPort,
                snowId = "SNW-FALL-BACK",
                networkId = "SNW-NET-BBBB2222"
            )
        )
        val hostFp = hostManager.hostState.value.certFingerprint.replace(":", "").uppercase()
        val hsToken = hostManager.generateHandshakeToken("SNW-NET-BBBB2222")

        val repo = SnowUiRepository.getInstance(context)
        val repoPins = InMemoryCertPinStorage()
        val repoTokens = InMemoryTokenStorage()
        repo.certPinStorageOverrideForTest = repoPins
        repo.tokenStorageOverrideForTest = repoTokens
        repo.allowLoopbackCandidateIpsForTest = true
        repo.qrCandidateTimeoutMs = 900L

        val wsClient = SnowWebSocketClient(
            scope = clientScope,
            certPinStorage = repoPins,
            tokenStorage = repoTokens,
            useTls = true
        ).apply { autoReconnectEnabled = false }
        repo.attachClientForTest(wsClient)
        val attemptedHosts = CopyOnWriteArrayList<Pair<String, ConnectionHandshakeMode>>()
        val closedRefusePort = freeTcpPort() // Guaranteed unreachable immediate connection refusal on loopback
        repo.connectLauncherForTest = { h, p, devId, mode ->
            attemptedHosts.add(h to mode)
            // First host is unreachable closed loopback port; wait for real connection on second candidate
            val targetPort = if (h == "127.0.0.2") closedRefusePort else p
            wsClient.connect(h, targetPort, devId, mode)
        }

        val qrPayload = JSONObject().apply {
            put("v", 2)
            put("device_id", hostId)
            put("snow_id", "SNW-FALL-BACK")
            put("device_type", "android")
            put("network_id", "SNW-NET-BBBB2222")
            put("fp", hostFp)
            put("port", hostPort)
            put("transfer_port", mediaPort)
            put("ips", JSONArray(listOf("127.0.0.2", "127.0.0.1")))
            put("handshake_token", hsToken)
            put("exp", (System.currentTimeMillis() / 1000L) + 60L)
        }.toString()

        val qrLatch = CountDownLatch(1)
        val qrResult = AtomicReference<Pair<Boolean, String?>>()
        repo.handleQrScanPayload(qrPayload) { ok, err ->
            qrResult.set(ok to err)
            qrLatch.countDown()
        }
        assertTrue("Multi-IP fallback QR onboarding timed out", qrLatch.await(10, TimeUnit.SECONDS))
        assertEquals(true to null, qrResult.get())
        assertEquals(
            listOf(
                "127.0.0.2" to ConnectionHandshakeMode.EXPLICIT_PAIRING_INITIATOR,
                "127.0.0.1" to ConnectionHandshakeMode.EXPLICIT_PAIRING_INITIATOR
            ),
            attemptedHosts.toList()
        )
        // Verify active transfer port resolved for connected Android peer is mediaPort (not hardcoded PC 8766)
        assertEquals(mediaPort, repo.resolveActiveTransferPort())
        wsClient.disconnect()
    }

    @Test
    fun testRc2_UdpBeaconStartsBroadcastsIgnoresSelfAndRequiresTokenForPairedStatus() {
        val udpPort = freeTcpPort()
        val pins = InMemoryCertPinStorage()
        val tokens = InMemoryTokenStorage()
        val dm = DiscoveryManager(
            port = udpPort,
            scope = hostScope,
            certPinStorage = pins,
            tokenStorage = tokens,
            localDeviceId = "phone-self-id"
        )

        // Bind a UDP receiver on same ephemeral port? Instead validate payload creation + broadcast destinations + self-ignore & token gate
        val fp = "AB".repeat(32)
        val beaconBytes = DiscoveryManager.createBeaconPayload(
            deviceId = "phone-peer-id",
            deviceName = "Realme P4",
            deviceType = "android",
            port = 8767,
            transferPort = 8769,
            certFingerprint = fp,
            snowId = "SNW-REAL-MEP4",
            ips = listOf("192.168.43.1", "192.168.1.25")
        )
        val parsed = DiscoveryManager.parseBeacon(beaconBytes, beaconBytes.size, "192.168.43.1")
        assertNotNull(parsed)
        assertEquals("android", parsed!!.deviceType)
        assertEquals(8767, parsed.port)
        assertEquals(8769, parsed.transferPort)

        // Pin cert WITHOUT token -> NOT marked paired when TokenStorage is present!
        pins.pinFingerprintForDevice("phone-peer-id", fp)
        dm.handleDiscoveredPeer(parsed)
        val beforeToken = dm.peers.value.firstOrNull { it.deviceId == "phone-peer-id" }
        assertNotNull(beforeToken)
        assertFalse("Pinned cert alone without per-device token must NOT be marked isPaired", beforeToken!!.isPaired)

        // Provision per-device token -> marked paired cleanly
        tokens.saveTokenForDevice("phone-peer-id", "peer-auth-tok-123")
        dm.handleDiscoveredPeer(parsed)
        val afterToken = dm.peers.value.firstOrNull { it.deviceId == "phone-peer-id" }
        assertTrue("Pinned cert + valid per-device token must be marked isPaired", afterToken!!.isPaired)

        // Self-beacon must be suppressed
        val selfRaw = DiscoveryManager.createBeaconPayload(
            deviceId = "phone-self-id",
            deviceName = "Self Phone",
            port = 8767,
            transferPort = 8769,
            certFingerprint = fp
        )
        val selfParsed = DiscoveryManager.parseBeacon(selfRaw, selfRaw.size, "127.0.0.1")!!
        dm.handleDiscoveredPeer(selfParsed)
        assertFalse(dm.peers.value.any { it.deviceId == "phone-self-id" })

        val dests = DiscoveryManager.resolveBroadcastDestinations(listOf("192.168.43.1", "192.168.1.40", "127.0.0.1", "169.254.1.2"))
        assertEquals(listOf("255.255.255.255", "192.168.43.255", "192.168.1.255"), dests)

        // Start & stop beacon socket cleanly
        val recvSock = DatagramSocket(0)
        try {
            val dm2 = DiscoveryManager(port = recvSock.localPort, scope = hostScope)
            assertTrue(
                dm2.startPeerHostBeacon(
                    deviceId = "phone-host-udp",
                    deviceName = "Host UDP",
                    port = 8767,
                    transferPort = 8769,
                    certFingerprint = fp,
                    candidateIpsProvider = { listOf("127.0.0.1") },
                    intervalMs = 1500L
                )
            )
            dm2.stopPeerHostBeacon()
            dm2.stopListening()
        } finally {
            recvSock.close()
        }
        dm.stopListening()
    }

    @Test
    fun testCarryForward23_BatteryOptimizationSettingsFallbackAndWiring() {
        val launchedActions = mutableListOf<Pair<String, String?>>()
        var failFirst = true
        SnowUiRepository.batteryIntentLauncherForTest = { _, spec, _ ->
            launchedActions.add(spec.action to spec.dataUri)
            if (failFirst) {
                failFirst = false
                throw android.content.ActivityNotFoundException("Primary battery optimization intent unavailable")
            }
        }

        val ok = SnowUiRepository.openBatteryOptimizationSettings(context)
        assertTrue("Primary battery intent failure must cleanly fall back to App Info", ok)
        assertEquals(2, launchedActions.size)
        assertEquals(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS, launchedActions[0].first)
        assertEquals(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, launchedActions[1].first)
        assertEquals("package:org.snow", launchedActions[1].second)

        // If all intents throw, openBatteryOptimizationSettings fails closed with false instead of crashing
        SnowUiRepository.batteryIntentLauncherForTest = { _, _, _ -> throw RuntimeException("No settings app") }
        assertFalse(SnowUiRepository.openBatteryOptimizationSettings(context))

        val settingsSrc = listOf(
            File("src/main/java/org/snow/ui/settings/SettingsScreen.kt"),
            File("app/src/main/java/org/snow/ui/settings/SettingsScreen.kt"),
            File("android/app/src/main/java/org/snow/ui/settings/SettingsScreen.kt")
        ).first { it.exists() }.readText()
        assertTrue(settingsSrc.contains("openBatteryOptimizationSettings(context)"))
        assertFalse(settingsSrc.contains("REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"))
    }
}
