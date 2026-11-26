package org.snow.ui

import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okio.ByteString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.network.AuthState
import org.snow.network.BackoffPolicy
import org.snow.network.ConnectionState
import org.snow.network.SnowWebSocketClient
import org.snow.protocol.JsonSerialization
import org.snow.protocol.SnowMessage
import org.snow.security.InMemoryTokenStorage
import org.snow.transfer.FileTransferClient
import java.io.File

/**
 * Stage 6A Android JVM regression suite covering WS2, WS4, WS5, WS6, WS8 & version invariants.
 */
class Stage6ARegressionTest {

    private class FakeWebSocket : WebSocket {
        val sentMessages = mutableListOf<String>()
        var cancelled = false
        var closedCode: Int? = null
        var closedReason: String? = null

        override fun request(): Request = Request.Builder().url("https://127.0.0.1:8765").build()
        override fun queueSize(): Long = 0L
        override fun send(text: String): Boolean {
            sentMessages.add(text)
            return true
        }
        override fun send(bytes: ByteString): Boolean = true
        override fun close(code: Int, reason: String?): Boolean {
            closedCode = code
            closedReason = reason
            return true
        }
        override fun cancel() {
            cancelled = true
        }
    }

    private fun resolveModuleFile(relPath: String): File {
        val candidates = listOf(File(relPath), File("app", relPath), File("android/app", relPath))
        return candidates.firstOrNull { it.exists() }
            ?: error("Could not locate file: $relPath (cwd=${File(".").absolutePath})")
    }

    @Test
    fun testWs2UiConnectionStateRequiresAuthenticatedHandshake() {
        assertEquals(
            ConnectionState.CONNECTING,
            SnowUiRepository.resolveUiConnectionState(
                ConnectionState.CONNECTED,
                AuthState.ConnectedUnauthenticated
            )
        )
        assertEquals(
            ConnectionState.DISCONNECTED,
            SnowUiRepository.resolveUiConnectionState(
                ConnectionState.CONNECTED,
                AuthState.AuthFailed("INVALID_TOKEN")
            )
        )
        assertEquals(
            ConnectionState.DISCONNECTED,
            SnowUiRepository.resolveUiConnectionState(
                ConnectionState.CONNECTED,
                AuthState.FingerprintMismatch("aa", "bb")
            )
        )
        assertEquals(
            ConnectionState.CONNECTED,
            SnowUiRepository.resolveUiConnectionState(
                ConnectionState.CONNECTED,
                AuthState.Authenticated(sessionId = "sess-1", trustTier = "owner")
            )
        )
        assertFalse(
            SnowUiRepository.isSessionTrulyConnected(
                ConnectionState.CONNECTED,
                AuthState.ConnectedUnauthenticated
            )
        )
        assertTrue(
            SnowUiRepository.isSessionTrulyConnected(
                ConnectionState.CONNECTED,
                AuthState.Authenticated(sessionId = "sess-1", trustTier = "owner")
            )
        )
    }

    @Test
    fun testWs2HeartbeatTimeoutClearsStateAndWs4SessionDisconnectPreservesToken() {
        val tokenStore = InMemoryTokenStorage().apply { saveToken("persisted-owner-token") }
        val client = SnowWebSocketClient(
            backoffPolicy = BackoffPolicy(),
            tokenStorage = tokenStore
        )
        client.autoReconnectEnabled = false

        val fakeWs = FakeWebSocket()
        client.handleHeartbeatFailure("2 consecutive missed ACKs")
        assertEquals(ConnectionState.DISCONNECTED, client.connectionState.value)
        assertTrue(client.authState.value is AuthState.Disconnected)
        assertEquals("persisted-owner-token", tokenStore.getToken())

        // Incoming session_disconnect from host ACKs and preserves token
        val discReq = SnowMessage.createRequest(
            action = "session_disconnect",
            data = mapOf("reason" to "Disconnected by host")
        )
        client.handleIncomingMessage(fakeWs, JsonSerialization.toJson(discReq))
        assertTrue(fakeWs.sentMessages.any { it.contains("session_disconnect") })
        assertEquals(ConnectionState.DISCONNECTED, client.connectionState.value)
        assertTrue(client.authState.value is AuthState.Disconnected)
        assertEquals("persisted-owner-token", tokenStore.getToken())

        // Incoming device_revoked from host ACKs, clears token, and invokes revocation callback
        var revokedReason: String? = null
        client.onDeviceRevoked = { r -> revokedReason = r }
        val revokeReq = SnowMessage.createRequest(
            action = "device_revoked",
            data = mapOf("reason" to "Revoked by owner")
        )
        client.handleIncomingMessage(fakeWs, JsonSerialization.toJson(revokeReq))
        assertTrue(fakeWs.sentMessages.any { it.contains("device_revoked") })
        assertNull(tokenStore.getToken())
        assertEquals("Revoked by owner", revokedReason)
        assertTrue(client.authState.value is AuthState.AuthFailed)
    }

    @Test
    fun testWs5StrictSemverAndVersionCodeOtaComparison() {
        val validSha = "a".repeat(64)
        assertEquals(Triple(5, 10, 0), SnowUiRepository.parseSemverTuple("5.10.0"))
        assertEquals(Triple(5, 2, 0), SnowUiRepository.parseSemverTuple("v5.2.0"))

        val sameVer = FileTransferClient.AppUpdateInfo(
            versionCode = 3,
            versionName = "5.1.0",
            sizeBytes = 1024L,
            sha256 = validSha,
            available = true
        )
        assertFalse(SnowUiRepository.isUpdateStrictlyNewer(sameVer, 3, "5.1.0"))

        val downgradedVerName = FileTransferClient.AppUpdateInfo(
            versionCode = 4,
            versionName = "5.0.9",
            sizeBytes = 1024L,
            sha256 = validSha,
            available = true
        )
        assertFalse(SnowUiRepository.isUpdateStrictlyNewer(downgradedVerName, 3, "5.1.0"))

        val newerSemver = FileTransferClient.AppUpdateInfo(
            versionCode = 4,
            versionName = "5.10.0",
            sizeBytes = 1024L,
            sha256 = validSha,
            available = true
        )
        assertTrue(SnowUiRepository.isUpdateStrictlyNewer(newerSemver, 3, "5.2.0"))
    }

    @Test
    fun testWs4WakeSyncWs6CameraForegroundGuardAndVersionFrozenAt510() {
        val mainSrc = resolveModuleFile("src/main/java/org/snow/ui/MainActivity.kt").readText()
        assertTrue(mainSrc.contains("isCameraCaptureLaunchInFlight"))
        assertTrue(mainSrc.contains("request_camera_capture"))

        val dispSrc = resolveModuleFile("src/main/java/org/snow/capabilities/AndroidCapabilityDispatcher.kt").readText()
        assertTrue(dispSrc.contains("request_camera_capture"))
        assertTrue(dispSrc.contains("ClipboardHandler.isAppInForeground"))
        assertTrue(dispSrc.contains("ActionNotificationHelper.postActionNotification"))

        val discoverySrc = resolveModuleFile("src/main/java/org/snow/network/DiscoveryManager.kt").readText()
        assertTrue(discoverySrc.contains("wake_target"))
        assertTrue(discoverySrc.contains("onWakeTargetMatched"))

        val gradleSrc = resolveModuleFile("build.gradle.kts").readText()
        assertTrue(gradleSrc.contains("versionCode = 4"))
        assertTrue(gradleSrc.contains("versionName = \"5.2.0\""))

        val settingsSrc = resolveModuleFile("src/main/java/org/snow/ui/settings/SettingsScreen.kt").readText()
        assertTrue(settingsSrc.contains("ColorOS") || settingsSrc.contains("Restricted"))
    }
}
