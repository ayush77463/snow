package org.snow.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.capabilities.LiveScreenStreamHandler
import org.snow.network.AndroidPeerMediaServer
import org.snow.security.AndroidSelfSignedCertGenerator
import org.snow.security.InMemoryTokenStorage
import org.snow.ui.tools.ToolSubTab
import java.io.File
import java.net.URL
import javax.net.ssl.HttpsURLConnection

class Stage6CAndroidRegressionTest {

    private fun resolveModuleFile(relativePath: String): File {
        val candidates = listOf(File(relativePath), File("android", relativePath), File("app", relativePath))
        return candidates.firstOrNull { it.exists() } ?: candidates.first()
    }

    @Test
    fun testToolsTabHasFiveSubTabsWithScreenAndMediaSeparated() {
        val tabs = ToolSubTab.values()
        assertEquals(5, tabs.size)
        assertEquals(listOf("Files", "Apps", "Media", "Terminal", "Screen"), tabs.map { it.title })

        val toolsSrc = resolveModuleFile("src/main/java/org/snow/ui/tools/ToolsScreen.kt").readText()
        // MediaToolView no longer owns Android Screen Share; ScreenToolView does cleanly
        val mediaSection = toolsSrc.substringAfter("private fun MediaToolView(").substringBefore("private fun ScreenToolView(")
        val screenSection = toolsSrc.substringAfter("private fun ScreenToolView(")
        assertFalse(mediaSection.contains("Android Screen Share"))
        assertTrue(mediaSection.contains("REMOTE PC MEDIA CONTROLS"))
        assertTrue(mediaSection.contains("Camera Photo Delivery"))

        assertTrue(screenSection.contains("INCOMING LIVE SCREEN"))
        assertTrue(screenSection.contains("SHARE THIS PHONE SCREEN"))
        assertTrue(screenSection.contains("Select devices to share with"))
        assertTrue(screenSection.contains("ONE-TIME SCREEN CAPTURE"))

        val appSrc = resolveModuleFile("src/main/java/org/snow/ui/SnowApp.kt").readText()
        assertTrue(appSrc.contains("Sharing Screen"))
        assertTrue(appSrc.contains("repository.stopScreenShare()"))
    }

    @Test
    fun testScreenCapabilitiesEnforceFullControlTierOnly() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "snow_6c_disp_${System.currentTimeMillis()}").apply { mkdirs() }
        try {
            val prefsMap = mutableMapOf<String, Any?>()
            val fakePrefs = object : android.content.SharedPreferences {
                override fun getAll(): MutableMap<String, *> = prefsMap
                override fun getString(k: String?, d: String?): String? = prefsMap[k] as? String ?: d
                override fun getStringSet(k: String?, d: MutableSet<String>?): MutableSet<String>? = d
                override fun getInt(k: String?, d: Int): Int = (prefsMap[k] as? Int) ?: d
                override fun getLong(k: String?, d: Long): Long = (prefsMap[k] as? Long) ?: d
                override fun getFloat(k: String?, d: Float): Float = (prefsMap[k] as? Float) ?: d
                override fun getBoolean(k: String?, d: Boolean): Boolean = (prefsMap[k] as? Boolean) ?: d
                override fun contains(k: String?): Boolean = prefsMap.containsKey(k)
                override fun edit(): android.content.SharedPreferences.Editor = object : android.content.SharedPreferences.Editor {
                    override fun putString(k: String?, v: String?) = apply { if (k != null) prefsMap[k] = v }
                    override fun putStringSet(k: String?, v: MutableSet<String>?) = apply { if (k != null) prefsMap[k] = v }
                    override fun putInt(k: String?, v: Int) = apply { if (k != null) prefsMap[k] = v }
                    override fun putLong(k: String?, v: Long) = apply { if (k != null) prefsMap[k] = v }
                    override fun putFloat(k: String?, v: Float) = apply { if (k != null) prefsMap[k] = v }
                    override fun putBoolean(k: String?, v: Boolean) = apply { if (k != null) prefsMap[k] = v }
                    override fun remove(k: String?) = apply { prefsMap.remove(k) }
                    override fun clear() = apply { prefsMap.clear() }
                    override fun commit(): Boolean = true
                    override fun apply() {}
                }
                override fun registerOnSharedPreferenceChangeListener(l: android.content.SharedPreferences.OnSharedPreferenceChangeListener?) {}
                override fun unregisterOnSharedPreferenceChangeListener(l: android.content.SharedPreferences.OnSharedPreferenceChangeListener?) {}
            }
            val ctx = object : android.content.ContextWrapper(null) {
                override fun getApplicationContext() = this
                override fun getFilesDir() = tempDir
                override fun getCacheDir() = tempDir
                override fun getSharedPreferences(name: String?, mode: Int): android.content.SharedPreferences = fakePrefs
            }
            val dispatcher = AndroidCapabilityDispatcher(ctx) { null }
            val screenActions = listOf(
                "screen_stream_start",
                "screen_stream_stop",
                "android_screen_stream_stop",
                "screen_stream_subscribe",
                "screen_stream_event",
                "screen_stream_status"
            )
            dispatcher.activePermissionProfile = "full_control"
            screenActions.forEach { act ->
                assertTrue("full_control should allow $act", dispatcher.isActionAllowedByProfile(act))
            }
            for (tier in listOf("files_and_clipboard", "files_only", "clipboard_only", "not_allowed")) {
                dispatcher.activePermissionProfile = tier
                screenActions.forEach { act ->
                    assertFalse("$tier must deny $act", dispatcher.isActionAllowedByProfile(act))
                }
            }
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun testAndroidPeerMediaServerSupportsAuthenticatedPhoneToPhoneFramesAndRejectsUnauthorized() {
        val cert = AndroidSelfSignedCertGenerator.generate()
        val tokenStore = InMemoryTokenStorage().apply { saveToken("peer-token-123") }
        val server = AndroidPeerMediaServer(
            requestedPort = 0,
            sslContext = cert.sslContext,
            tokenStorage = tokenStore
        )
        assertTrue(server.start())
        try {
            val port = server.boundPort
            val trustAllCtx = javax.net.ssl.SSLContext.getInstance("TLS").apply {
                init(null, arrayOf(object : javax.net.ssl.X509TrustManager {
                    override fun checkClientTrusted(c: Array<out java.security.cert.X509Certificate>?, a: String?) {}
                    override fun checkServerTrusted(c: Array<out java.security.cert.X509Certificate>?, a: String?) {}
                    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
                }), java.security.SecureRandom())
            }

            // 1. Unauthorized POST rejected with 401
            val unauthConn = (URL("https://127.0.0.1:$port/api/v1/screen/frame").openConnection() as HttpsURLConnection).apply {
                sslSocketFactory = trustAllCtx.socketFactory
                hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
                requestMethod = "POST"
                doOutput = true
                setRequestProperty("Content-Type", "image/jpeg")
            }
            unauthConn.outputStream.use { it.write(byteArrayOf(1, 2, 3)) }
            assertEquals(401, unauthConn.responseCode)

            // 2. Authorized POST accepted and GET retrieves exact sender bytes without mixing
            val sampleFrame = "P2P_JPEG_FRAME_DATA".toByteArray()
            val postConn = (URL("https://127.0.0.1:$port/api/v1/screen/frame").openConnection() as HttpsURLConnection).apply {
                sslSocketFactory = trustAllCtx.socketFactory
                hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
                requestMethod = "POST"
                doOutput = true
                setRequestProperty("Authorization", "Bearer peer-token-123")
                setRequestProperty("X-Snow-Device-Id", "phone-a")
                setRequestProperty("X-Snow-Sender-Id", "phone-a")
                setRequestProperty("X-Snow-Sender-Name", "Galaxy Phone")
                setRequestProperty("X-Snow-Session-Id", "sess-p2p")
                setRequestProperty("X-Snow-Frame-Seq", "1")
                setRequestProperty("Content-Type", "image/jpeg")
            }
            postConn.outputStream.use { it.write(sampleFrame) }
            assertEquals(200, postConn.responseCode)

            val getConn = (URL("https://127.0.0.1:$port/api/v1/screen/frame?sender_id=phone-a").openConnection() as HttpsURLConnection).apply {
                sslSocketFactory = trustAllCtx.socketFactory
                hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
                requestMethod = "GET"
                setRequestProperty("Authorization", "Bearer peer-token-123")
                setRequestProperty("X-Snow-Device-Id", "phone-b")
            }
            assertEquals(200, getConn.responseCode)
            val got = getConn.inputStream.readBytes()
            assertEquals("P2P_JPEG_FRAME_DATA", String(got))

            // 3. Querying non-existent sender-other never mixes phone-a's frame
            val getOther = (URL("https://127.0.0.1:$port/api/v1/screen/frame?sender_id=phone-other").openConnection() as HttpsURLConnection).apply {
                sslSocketFactory = trustAllCtx.socketFactory
                hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
                requestMethod = "GET"
                setRequestProperty("Authorization", "Bearer peer-token-123")
                setRequestProperty("X-Snow-Device-Id", "phone-b")
            }
            assertEquals(204, getOther.responseCode)
            assertNotNull(server.getActiveSenders().firstOrNull())
        } finally {
            server.stop()
        }
    }

    @Test
    fun testLiveScreenStreamHandlerMaxConstantsZeroDegradationPreserved() {
        assertEquals(524288L, LiveScreenStreamHandler.MAX_FRAME_BYTES)
        assertEquals(70, LiveScreenStreamHandler.JPEG_QUALITY)
        assertEquals(720, LiveScreenStreamHandler.MAX_LONG_EDGE)
    }
}
