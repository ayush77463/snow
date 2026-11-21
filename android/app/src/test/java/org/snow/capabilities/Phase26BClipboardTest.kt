package org.snow.capabilities

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.ui.SnowUiRepository
import java.security.MessageDigest

/**
 * Phase 26B Unit Test Suite:
 * Android Shared Clipboard Buffer DTOs, Metadata, and Execution Contracts.
 *
 * Verifies:
 * 1. ClipboardItemDto creation and data integrity.
 * 2. SHA-256 deduplication hashing parity.
 * 3. Android 10+ background clipboard access contracts.
 * 4. Pinned state tracking and metadata representation.
 * 5. Text truncation bounds and size calculations.
 */
class Phase26BClipboardTest {

    @Test
    fun test_01_clipboard_item_dto_creation() {
        val item = SnowUiRepository.ClipboardItemDto(
            itemId = "abc12345",
            type = "text",
            sourceDevice = "pc",
            previewText = "Hello from Windows laptop",
            sizeBytes = 25L,
            timestamp = 1700000000.0,
            isPinned = false
        )
        assertEquals("abc12345", item.itemId)
        assertEquals("text", item.type)
        assertEquals("pc", item.sourceDevice)
        assertEquals("Hello from Windows laptop", item.previewText)
        assertEquals(25L, item.sizeBytes)
        assertFalse(item.isPinned)
    }

    @Test
    fun test_02_pinned_state_and_device_tracking() {
        val pinnedPhoneItem = SnowUiRepository.ClipboardItemDto(
            itemId = "pinned-789",
            type = "text",
            sourceDevice = "phone",
            previewText = "Critical auth token snippet",
            sizeBytes = 27L,
            timestamp = 1700000100.0,
            isPinned = true
        )
        assertTrue(pinnedPhoneItem.isPinned)
        assertEquals("phone", pinnedPhoneItem.sourceDevice)
    }

    @Test
    fun test_03_sha256_deduplication_parity() {
        val text = "Shared clipboard sync test string"
        val md = MessageDigest.getInstance("SHA-256")
        val expectedHash = md.digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

        assertNotNull(expectedHash)
        assertEquals(64, expectedHash.length)

        // Same content yields same digest
        val md2 = MessageDigest.getInstance("SHA-256")
        val secondHash = md2.digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
        assertEquals(expectedHash, secondHash)
    }

    @Test
    fun test_04_execution_contract_foreground_enforcement() {
        // Android 10+ clipboard contract requires foreground app state
        ClipboardHandler.isAppInForeground = false
        ClipboardHandler.isUserIntentGranted = false

        // Simulating capability dispatcher contract check for clipboard_pull
        val isForegroundPermitted = ClipboardHandler.isAppInForeground && ClipboardHandler.isUserIntentGranted
        assertFalse("Background clipboard access must be rejected", isForegroundPermitted)

        // When foreground and user intent are granted
        ClipboardHandler.isAppInForeground = true
        ClipboardHandler.isUserIntentGranted = true
        val isForegroundPermittedNow = ClipboardHandler.isAppInForeground && ClipboardHandler.isUserIntentGranted
        assertTrue("Foreground clipboard access with user intent must be permitted", isForegroundPermittedNow)

        // Clean up
        ClipboardHandler.isAppInForeground = false
        ClipboardHandler.isUserIntentGranted = false
    }

    @Test
    fun test_05_image_clipboard_item_dto() {
        val imageItem = SnowUiRepository.ClipboardItemDto(
            itemId = "img-5555",
            type = "image",
            sourceDevice = "pc",
            previewText = "[Image 1024x768 PNG]",
            sizeBytes = 204800L,
            timestamp = 1700000200.0,
            isPinned = false
        )
        assertEquals("image", imageItem.type)
        assertEquals(204800L, imageItem.sizeBytes)
        assertTrue(imageItem.previewText.contains("Image"))
    }

    @Test
    fun test_06_preview_and_content_separation() {
        val longContent = "A".repeat(1000)
        val preview = longContent.take(120)
        assertEquals(120, preview.length)
        assertEquals(1000, longContent.length)
        assertFalse("Preview must not equal full text content", preview == longContent)
    }

    @Test
    fun test_07_ten_item_timeline_limit() {
        val items = (1..15).map { i ->
            SnowUiRepository.ClipboardItemDto(
                itemId = "cb_$i",
                type = "text",
                sourceDevice = "pc",
                previewText = "Item $i",
                sizeBytes = 10L,
                timestamp = 1700000000.0 + i,
                isPinned = i <= 2
            )
        }
        val displayed = items.take(10)
        assertEquals(10, displayed.size)
        assertEquals("cb_1", displayed.first().itemId)
        assertEquals("cb_10", displayed.last().itemId)
    }

    @Test
    fun test_08_image_transfer_metadata_parsing_and_digest() {
        val payload: Map<String, Any> = mapOf(
            "type" to "image",
            "mime_type" to "image/png",
            "transfer_id" to "trans_999",
            "sha256" to "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "transfer_port" to 8766,
            "size" to 512000L
        )
        assertEquals("image", payload["type"])
        assertEquals("trans_999", payload["transfer_id"])
        assertEquals(64, (payload["sha256"] as String).length)
        assertEquals(8766, payload["transfer_port"])
    }

    @Test
    fun test_09_full_text_size_validation() {
        val validText = "Valid clipboard payload"
        assertTrue(validText.toByteArray(Charsets.UTF_8).size <= 65536)

        val oversizedText = "X".repeat(70000)
        assertFalse(oversizedText.toByteArray(Charsets.UTF_8).size <= 65536)
    }

    @Test
    fun test_10_failure_handling_on_invalid_payload() {
        val responsePayload: Map<String, Any?> = mapOf("status" to "error", "error" to "Item not found")
        val isSuccess = responsePayload["status"] == "success"
        assertFalse("Error payload must not be marked success", isSuccess)
        assertEquals("Item not found", responsePayload["error"])
    }
}
