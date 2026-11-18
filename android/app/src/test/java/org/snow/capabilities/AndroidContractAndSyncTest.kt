package org.snow.capabilities

import android.content.ContextWrapper
import android.content.pm.PackageManager
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.protocol.ErrorCode

class AndroidContractAndSyncTest {

    @Before
    fun setUp() {
        ClipboardHandler.isAppInForeground = false
        ClipboardHandler.isUserIntentGranted = false
    }

    @Test
    fun testValidateExecutionContractClipboardForegroundRequired() {
        val dummyContext = object : ContextWrapper(null) {}
        val dispatcher = AndroidCapabilityDispatcher(dummyContext, transferClientProvider = { null })

        ClipboardHandler.isAppInForeground = false
        ClipboardHandler.isUserIntentGranted = true

        val violation = dispatcher.validateExecutionContract("clipboard_pull", null)
        assertNotNull(violation)
        assertEquals(false, violation?.get("success"))
        assertEquals("FOREGROUND_REQUIRED", violation?.get("status"))
        assertTrue((violation?.get("error") as String).contains("foreground"))
        assertTrue((violation?.get("remediation_hint") as String).contains("foreground"))
    }

    @Test
    fun testValidateExecutionContractClipboardUserConfirmationRequired() {
        val dummyContext = object : ContextWrapper(null) {}
        val dispatcher = AndroidCapabilityDispatcher(dummyContext, transferClientProvider = { null })

        ClipboardHandler.isAppInForeground = true
        ClipboardHandler.isUserIntentGranted = false

        val violation = dispatcher.validateExecutionContract("clipboard_pull", null)
        assertNotNull(violation)
        assertEquals(false, violation?.get("success"))
        assertEquals("USER_CONFIRMATION_REQUIRED", violation?.get("status"))
        assertTrue((violation?.get("remediation_hint") as String).contains("Confirm"))
    }

    @Test
    fun testValidateExecutionContractBackgroundAppLaunchNotificationsDenied() {
        val dummyContext = object : ContextWrapper(null) {
            override fun checkPermission(permission: String, pid: Int, uid: Int): Int {
                return PackageManager.PERMISSION_DENIED
            }
        }
        val dispatcher = AndroidCapabilityDispatcher(dummyContext, transferClientProvider = { null })

        ClipboardHandler.isAppInForeground = false

        val violation = dispatcher.validateExecutionContract("launch_app", mapOf("package_name" to "com.example.app"))
        assertNotNull(violation)
        assertEquals(false, violation?.get("success"))
        assertEquals("FOREGROUND_REQUIRED", violation?.get("status"))
        assertTrue((violation?.get("remediation_hint") as String).contains("Notification"))
    }

    @Test
    fun testValidateExecutionContractBackgroundMessagingNotificationsDenied() {
        val dummyContext = object : ContextWrapper(null) {
            override fun checkPermission(permission: String, pid: Int, uid: Int): Int {
                return PackageManager.PERMISSION_DENIED
            }
        }
        val dispatcher = AndroidCapabilityDispatcher(dummyContext, transferClientProvider = { null })

        ClipboardHandler.isAppInForeground = false

        val violation = dispatcher.validateExecutionContract(
            "send_message",
            mapOf("recipient" to "+1234567890", "message" to "Hello", "mode" to "intent")
        )
        assertNotNull(violation)
        assertEquals(false, violation?.get("success"))
        assertEquals("FOREGROUND_REQUIRED", violation?.get("status"))
    }

    @Test
    fun testValidateExecutionContractSmsModeUnconfirmed() {
        val dummyContext = object : ContextWrapper(null) {}
        val dispatcher = AndroidCapabilityDispatcher(dummyContext, transferClientProvider = { null })

        val violation = dispatcher.validateExecutionContract(
            "send_message",
            mapOf("recipient" to "+1234567890", "message" to "Hello", "mode" to "sms", "user_confirmed" to false)
        )
        assertNotNull(violation)
        assertEquals(false, violation?.get("success"))
        assertEquals("USER_CONFIRMATION_REQUIRED", violation?.get("status"))
    }

    @Test
    fun testDispatchCentralizedContractRejectionReturnsSnowError() = runBlocking {
        val dummyContext = object : ContextWrapper(null) {}
        val dispatcher = AndroidCapabilityDispatcher(dummyContext, transferClientProvider = { null })

        ClipboardHandler.isAppInForeground = false

        val (res, err) = dispatcher.dispatch(
            action = "clipboard_pull",
            data = null,
            serverHost = "127.0.0.1",
            defaultTransferPort = 8766
        )

        assertNull(res)
        assertNotNull(err)
        assertEquals(ErrorCode.UNAUTHORIZED, err?.code)
        assertTrue(err?.message?.contains("FOREGROUND_REQUIRED") == true)
    }
}
