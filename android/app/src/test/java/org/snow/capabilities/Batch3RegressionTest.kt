package org.snow.capabilities

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.network.AndroidPeerHostManager
import org.snow.network.AndroidPeerHostServer
import org.snow.network.SnowWebSocketClient
import org.snow.protocol.ErrorCode
import org.snow.protocol.SnowMessage
import org.snow.security.AndroidSelfSignedCertGenerator
import org.snow.security.MockSharedPreferences
import org.snow.security.TokenStorage
import org.snow.ui.SnowUiRepository
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicBoolean

class Batch3RegressionTest {

    private lateinit var testScope: CoroutineScope
    private lateinit var mockPrefs: MockSharedPreferences
    private lateinit var context: Context
    private lateinit var dispatcher: AndroidCapabilityDispatcher

    class TestTokenStorage : TokenStorage {
        private var storedToken: String? = "test-token"
        override fun saveToken(token: String) { this.storedToken = token }
        override fun getToken(): String? = storedToken
        override fun clearToken() { storedToken = null }
        override fun hasToken(): Boolean = storedToken != null
    }

    @Before
    fun setUp() {
        testScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val prefsMap = mutableMapOf<String, MockSharedPreferences>()
        mockPrefs = prefsMap.getOrPut(SnowUiRepository.PREFS_SETTINGS) { MockSharedPreferences() }
        context = object : ContextWrapper(null) {
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences {
                return prefsMap.getOrPut(name ?: "default") { MockSharedPreferences() }
            }
        }
        dispatcher = AndroidCapabilityDispatcher(context, transferClientProvider = { null })
        ClipboardHandler.isAppInForeground = false
        ClipboardHandler.isUserIntentGranted = false
    }

    @After
    fun tearDown() {
        testScope.cancel()
        ClipboardHandler.isAppInForeground = false
        ClipboardHandler.isUserIntentGranted = false
    }

    @Test
    fun testWP2_InstantSyncPermissionContract() {
        // 1. Background -> FOREGROUND_REQUIRED
        ClipboardHandler.isAppInForeground = false
        ClipboardHandler.isUserIntentGranted = false
        mockPrefs.edit().putBoolean(SnowUiRepository.PREF_KEY_INSTANT_SYNC, false).commit()

        val violationBg = dispatcher.validateExecutionContract("clipboard_pull", null)
        assertNotNull(violationBg)
        assertEquals(false, violationBg?.get("success"))
        assertEquals("FOREGROUND_REQUIRED", violationBg?.get("status"))

        // 2. Foreground, but intent not granted and instant sync disabled -> USER_CONFIRMATION_REQUIRED
        ClipboardHandler.isAppInForeground = true
        ClipboardHandler.isUserIntentGranted = false
        mockPrefs.edit().putBoolean(SnowUiRepository.PREF_KEY_INSTANT_SYNC, false).commit()

        val violationNoConfirm = dispatcher.validateExecutionContract("clipboard_pull", null)
        assertNotNull(violationNoConfirm)
        assertEquals(false, violationNoConfirm?.get("success"))
        assertEquals("USER_CONFIRMATION_REQUIRED", violationNoConfirm?.get("status"))

        // 3. Foreground with user intent granted -> Allowed (null violation)
        ClipboardHandler.isUserIntentGranted = true
        val violationIntentGranted = dispatcher.validateExecutionContract("clipboard_pull", null)
        assertNull(violationIntentGranted)

        // 4. Foreground with instant sync preference enabled -> Allowed (null violation)
        ClipboardHandler.isUserIntentGranted = false
        mockPrefs.edit().putBoolean(SnowUiRepository.PREF_KEY_INSTANT_SYNC, true).commit()

        val violationInstantSync = dispatcher.validateExecutionContract("clipboard_pull", null)
        assertNull(violationInstantSync)
    }

    @Test
    fun testWP6_ActivityCountedForegroundLifecycle() {
        // Clean initial state
        ClipboardHandler.isAppInForeground = false

        // Resume Activity A (e.g. MainActivity)
        ClipboardHandler.onActivityResumed("MainActivity")
        assertTrue("Foreground should be true after MainActivity resumed", ClipboardHandler.isAppInForeground)

        // Resume Activity B (e.g. ClipSyncActivity opens while MainActivity is finishing/pausing)
        ClipboardHandler.onActivityResumed("ClipSyncActivity")
        assertTrue("Foreground should be true when both are active", ClipboardHandler.isAppInForeground)

        // Pause Activity A
        ClipboardHandler.onActivityPaused("MainActivity")
        assertTrue("Foreground must remain true while ClipSyncActivity is still active", ClipboardHandler.isAppInForeground)

        // Pause Activity B -> all paused
        ClipboardHandler.onActivityPaused("ClipSyncActivity")
        assertFalse("Foreground must be false when all activities are paused", ClipboardHandler.isAppInForeground)
    }

    @Test
    fun testWP3_AndroidSelfSignedCertGeneratorProducesValidRSAKeyAndFingerprint() {
        val certResult = AndroidSelfSignedCertGenerator.generate()

        assertNotNull(certResult.keyPair)
        assertEquals("RSA", certResult.keyPair.public.algorithm)
        assertEquals(2048, (certResult.keyPair.public as java.security.interfaces.RSAPublicKey).modulus.bitLength())

        assertNotNull(certResult.certificate)
        assertNotNull(certResult.sslContext)

        val fp = certResult.fingerprint
        assertNotNull(fp)
        assertTrue(
            "Fingerprint must match 32 hex pairs separated by colons: $fp",
            fp.matches(Regex("^([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$"))
        )
    }

    @Test
    fun testWP3_AndroidPeerHostServerRefusesWithoutTLS() {
        val storage = TestTokenStorage()

        // Missing SSLContext must fail closed
        var caughtException = false
        try {
            val server = AndroidPeerHostServer(
                requestedPort = 8769,
                tokenStorage = storage,
                dispatcher = dispatcher,
                localDeviceId = "test-node",
                parentScope = testScope,
                sslContext = null
            )
            val started = server.start()
            if (!started) caughtException = true
        } catch (_: IllegalArgumentException) {
            caughtException = true
        }
        assertTrue("AndroidPeerHostServer must fail closed without TLS SSLContext", caughtException)
    }

    @Test
    fun testWP3_PeerHostManagerPinAndStateFlowLifecycle() = runBlocking {
        val manager = AndroidPeerHostManager()
        val storage = TestTokenStorage()

        val initialState = manager.hostState.first()
        assertFalse(initialState.isActive)
        assertEquals(8767, initialState.port)

        // Generate pairing pin
        val pin = manager.generatePairingPin()
        assertEquals(6, pin.length)
        assertTrue(pin.matches(Regex("^\\d{6}$")))

        // Test single-use consumption
        assertTrue("First PIN verification should succeed", manager.verifyAndConsumePairingPin(pin))
        assertFalse("Second PIN verification (replay) must fail", manager.verifyAndConsumePairingPin(pin))

        // Ephemeral port for host enable
        val ss = ServerSocket(0)
        val port = ss.localPort
        ss.close()

        manager.setHostModeSettingEnabled(true)
        val enabled = manager.enableHostMode(
            port = port,
            tokenStorage = storage,
            dispatcher = dispatcher,
            localDeviceId = "host-phone-1",
            parentScope = testScope
        )
        assertTrue("Host mode should start when enabled", enabled)

        val activeState = manager.hostState.first()
        assertTrue("hostState.isActive should be true", activeState.isActive)
        assertNotNull(activeState.certFingerprint)

        manager.disableHostMode()
        val stoppedState = manager.hostState.first()
        assertFalse("hostState.isActive should be false after disable", stoppedState.isActive)
    }

    @Test
    fun testWP5_SnowWebSocketClientBoundingAndTeardown() {
        assertEquals(100, SnowWebSocketClient.MAX_PENDING_REQUESTS)
        assertEquals(30L, SnowWebSocketClient.DEFAULT_REQUEST_TIMEOUT_SECONDS)

        val client = SnowWebSocketClient(scope = testScope)

        // When disconnected, sendRequest immediately yields INTERNAL_ERROR
        val receivedError = AtomicBoolean(false)
        client.sendRequest("test_action") { resp ->
            if (resp.type == org.snow.protocol.MessageType.ERROR && resp.error?.code == ErrorCode.INTERNAL_ERROR) {
                receivedError.set(true)
            }
        }
        assertTrue("Disconnected sendRequest must fail with INTERNAL_ERROR", receivedError.get())

        // Teardown should execute cleanly
        client.teardown()
    }

    @Test
    fun testWP3_PeerHostTokenStoragePrefNameIsIsolated() {
        assertEquals("snow_peer_host_security", org.snow.security.SharedPreferencesTokenStorage.PEER_HOST_PREFS_NAME)

        val keyManager = org.snow.security.KeyStoreManager(org.snow.security.InMemoryAesKeyProvider())
        val hostStore = org.snow.security.SharedPreferencesTokenStorage(
            context,
            prefName = org.snow.security.SharedPreferencesTokenStorage.PEER_HOST_PREFS_NAME,
            keyStoreManager = keyManager
        )
        val defaultStore = org.snow.security.SharedPreferencesTokenStorage(
            context,
            keyStoreManager = keyManager
        )

        hostStore.saveToken("peer-host-secret-token")
        defaultStore.saveToken("desktop-client-token")

        assertEquals("peer-host-secret-token", hostStore.getToken())
        assertEquals("desktop-client-token", defaultStore.getToken())
    }

    @Test
    fun testWP3_PeerHostStateReactiveFlow() = runBlocking {
        val manager = AndroidPeerHostManager()
        val flow = manager.hostState
        assertFalse(flow.first().isActive)

        manager.setHostModeSettingEnabled(true)
        val ss = ServerSocket(0)
        val port = ss.localPort
        ss.close()

        val started = manager.enableHostMode(
            port = port,
            tokenStorage = TestTokenStorage(),
            dispatcher = dispatcher,
            localDeviceId = "host-phone-test",
            parentScope = testScope
        )
        assertTrue(started)
        assertTrue(flow.first().isActive)

        manager.disableHostMode()
        assertFalse(flow.first().isActive)
    }
}
