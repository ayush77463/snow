package org.snow.protocol

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.util.UUID

/**
 * Cross-language protocol v1 parity verification tests.
 *
 * Direction A: Generates Kotlin JSON fixtures and exports them to build/cross_language/kotlin_to_python/.
 * Direction B: Reads and strictly validates Python-generated JSON fixtures from build/cross_language/python_to_kotlin/.
 */
class CrossLanguageParityTest {

    companion object {
        private lateinit var repoRoot: File
        private lateinit var pyToKtValid: File
        private lateinit var pyToKtInvalid: File
        private lateinit var ktToPyValid: File
        private lateinit var ktToPyInvalid: File

        @BeforeClass
        @JvmStatic
        fun setupDirectoriesAndExportFixtures() {
            repoRoot = findRepoRoot()
            val crossLangRoot = File(repoRoot, "build/cross_language")
            pyToKtValid = File(crossLangRoot, "python_to_kotlin/valid")
            pyToKtInvalid = File(crossLangRoot, "python_to_kotlin/invalid")
            ktToPyValid = File(crossLangRoot, "kotlin_to_python/valid")
            ktToPyInvalid = File(crossLangRoot, "kotlin_to_python/invalid")

            ktToPyValid.mkdirs()
            ktToPyInvalid.mkdirs()

            exportKotlinFixtures()
        }

        private fun findRepoRoot(): File {
            var current: File? = File(System.getProperty("user.dir") ?: ".")
            while (current != null) {
                if (File(current, "ARCHITECTURE.md").exists()) {
                    return current
                }
                current = current.parentFile
            }
            return File(".").canonicalFile
        }

        private fun exportKotlinFixtures() {
            val reqId = UUID.randomUUID().toString()

            // 1. Valid Fixtures
            val valid = mutableMapOf<String, String>()

            // Heartbeat
            val hb = SnowMessage.createHeartbeat()
            valid["heartbeat.json"] = JsonSerialization.toJson(hb)

            // Heartbeat Ack
            val ack = SnowMessage.createHeartbeatAck(reqId)
            valid["heartbeat_ack.json"] = JsonSerialization.toJson(ack)

            // Request ping
            val reqPing = SnowMessage.createRequest("ping")
            valid["request_ping.json"] = JsonSerialization.toJson(reqPing)

            // Request with nested data
            val reqData = SnowMessage.createRequest(
                "device_query",
                mapOf(
                    "query" to "status",
                    "count" to 42,
                    "enabled" to true,
                    "nested" to mapOf("key" to "value", "list" to listOf(1, 2, 3))
                )
            )
            valid["request_with_data.json"] = JsonSerialization.toJson(reqData)

            // Request with Unicode
            val reqUnicode = SnowMessage.createRequest(
                "greeting",
                mapOf("message" to "Snow ❄️ 2026 - Multilingual こんにちは")
            )
            valid["request_unicode.json"] = JsonSerialization.toJson(reqUnicode)

            // Response pong
            val respPong = SnowMessage.createResponse(
                reqId,
                mapOf("status" to "success", "action" to "pong")
            )
            valid["response_pong.json"] = JsonSerialization.toJson(respPong)

            // Response with nested data
            val respData = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "results" to listOf(mapOf("id" to 1, "name" to "item1")),
                    "total" to 1
                )
            )
            valid["response_with_data.json"] = JsonSerialization.toJson(respData)

            // Error unsupported action
            val errUnsupported = SnowMessage.createError(
                ErrorCode.UNSUPPORTED_ACTION,
                "Action 'unknown_op' is not supported.",
                reqId
            )
            valid["error_unsupported_action.json"] = JsonSerialization.toJson(errUnsupported)

            // Error invalid json without correlation_id
            val errInvalidJson = SnowMessage.createError(
                ErrorCode.INVALID_JSON,
                "Malformed JSON received."
            )
            valid["error_invalid_json.json"] = JsonSerialization.toJson(errInvalidJson)

            // Large valid request (~20 KB)
            val largeReq = SnowMessage.createRequest(
                "bulk_transfer",
                mapOf("payload" to "A".repeat(20000))
            )
            valid["request_large_payload.json"] = JsonSerialization.toJson(largeReq)

            // --- Phase 2.1 Pairing Protocol Fixtures ---
            // 11. Request pair_request
            val reqPair = SnowMessage.createRequest(
                "pair_request",
                mapOf(
                    "device_id" to UUID.randomUUID().toString(),
                    "device_name" to "Test Client Device",
                    "pin" to "123456"
                )
            )
            valid["request_pair_request.json"] = JsonSerialization.toJson(reqPair)

            // 12. Response pair success
            val respPair = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "pair_request",
                    "data" to mapOf(
                        "session_id" to UUID.randomUUID().toString(),
                        "device_id" to UUID.randomUUID().toString(),
                        "device_name" to "SNOW Desktop Core"
                    )
                )
            )
            valid["response_pair_success.json"] = JsonSerialization.toJson(respPair)

            // 13. Error INVALID_PIN
            val errInvalidPin = SnowMessage.createError(
                ErrorCode.INVALID_PIN,
                "Invalid pairing PIN. 2 attempt(s) remaining.",
                reqId
            )
            valid["error_invalid_pin.json"] = JsonSerialization.toJson(errInvalidPin)

            // 14. Error PIN_EXPIRED
            val errPinExpired = SnowMessage.createError(
                ErrorCode.PIN_EXPIRED,
                "Pairing PIN has expired. Request a new PIN on desktop.",
                reqId
            )
            valid["error_pin_expired.json"] = JsonSerialization.toJson(errPinExpired)

            // 15. Error PAIRING_LOCKED
            val errPairingLocked = SnowMessage.createError(
                ErrorCode.PAIRING_LOCKED,
                "Too many failed pairing attempts. Locked out for 300s.",
                reqId
            )
            valid["error_pairing_locked.json"] = JsonSerialization.toJson(errPairingLocked)

            // 16. Error ALREADY_PAIRED
            val errAlreadyPaired = SnowMessage.createError(
                ErrorCode.ALREADY_PAIRED,
                "Device is already paired or session is already established.",
                reqId
            )
            valid["error_already_paired.json"] = JsonSerialization.toJson(errAlreadyPaired)

            // --- Phase 2.2 Unpairing & Security Protocol Fixtures ---
            // 17. Valid unpair_request
            val reqUnpair = SnowMessage.createRequest(
                "unpair_request",
                mapOf(
                    "device_id" to UUID.randomUUID().toString(),
                    "auth_token" to "valid-auth-token-sample-12345"
                )
            )
            valid["request_unpair_request.json"] = JsonSerialization.toJson(reqUnpair)

            // 18. Valid unpair_request response
            val respUnpair = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "unpair_request",
                    "data" to mapOf(
                        "device_id" to UUID.randomUUID().toString(),
                        "unpaired" to true
                    )
                )
            )
            valid["response_unpair_success.json"] = JsonSerialization.toJson(respUnpair)

            // 19. Error UNAUTHORIZED
            val errUnauthorized = SnowMessage.createError(
                ErrorCode.UNAUTHORIZED,
                "Invalid authentication token for unpair request.",
                reqId
            )
            valid["error_unauthorized.json"] = JsonSerialization.toJson(errUnauthorized)

            // 20. Error DEVICE_NOT_FOUND
            val errDeviceNotFound = SnowMessage.createError(
                ErrorCode.DEVICE_NOT_FOUND,
                "Device is not registered as a paired device.",
                reqId
            )
            valid["error_device_not_found.json"] = JsonSerialization.toJson(errDeviceNotFound)

            // 21. Error INVALID_TOKEN
            val errInvalidToken = SnowMessage.createError(
                ErrorCode.INVALID_TOKEN,
                "Authentication token has expired or is invalid.",
                reqId
            )
            valid["error_invalid_token.json"] = JsonSerialization.toJson(errInvalidToken)

            for ((filename, content) in valid) {
                File(ktToPyValid, filename).writeText(content, Charsets.UTF_8)
            }

            // 2. Invalid / Negative Fixtures
            val invalid = mutableMapOf<String, Pair<String, String>>()

            invalid["invalid_malformed_json.json"] = Pair(
                "{malformed: json, not quoted}",
                ErrorCode.INVALID_JSON
            )

            invalid["invalid_root_not_object.json"] = Pair(
                JSONArray(listOf("not", "an", "object")).toString(),
                ErrorCode.INVALID_PAYLOAD
            )

            invalid["invalid_missing_version.json"] = Pair(
                JSONObject().apply {
                    put("type", "heartbeat")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                }.toString(),
                ErrorCode.UNSUPPORTED_VERSION
            )

            invalid["invalid_version_is_string.json"] = Pair(
                JSONObject().apply {
                    put("version", "1")
                    put("type", "heartbeat")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                }.toString(),
                ErrorCode.UNSUPPORTED_VERSION
            )

            invalid["invalid_version_unsupported.json"] = Pair(
                JSONObject().apply {
                    put("version", 99)
                    put("type", "heartbeat")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                }.toString(),
                ErrorCode.UNSUPPORTED_VERSION
            )

            invalid["invalid_missing_type.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                }.toString(),
                ErrorCode.INVALID_MESSAGE_TYPE
            )

            invalid["invalid_unknown_type.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "unrecognized_type")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                }.toString(),
                ErrorCode.INVALID_MESSAGE_TYPE
            )

            invalid["invalid_missing_id.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "heartbeat")
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                }.toString(),
                ErrorCode.INVALID_MESSAGE_ID
            )

            invalid["invalid_id_not_uuid.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "heartbeat")
                    put("id", "not-a-valid-uuid")
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                }.toString(),
                ErrorCode.INVALID_MESSAGE_ID
            )

            invalid["invalid_id_uuidv1.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "heartbeat")
                    put("id", "6ba7b810-9dad-11d1-80b4-00c04fd430c8")
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                }.toString(),
                ErrorCode.INVALID_MESSAGE_ID
            )

            invalid["invalid_missing_timestamp.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "heartbeat")
                    put("id", UUID.randomUUID().toString())
                }.toString(),
                ErrorCode.INVALID_TIMESTAMP
            )

            invalid["invalid_timestamp_naive.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "heartbeat")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", "2026-11-15T14:30:00")
                }.toString(),
                ErrorCode.INVALID_TIMESTAMP
            )

            invalid["invalid_timestamp_nonzero_offset.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "heartbeat")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", "2026-11-15T14:30:00+05:30")
                }.toString(),
                ErrorCode.INVALID_TIMESTAMP
            )

            invalid["invalid_correlation_id_not_uuid.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "response")
                    put("id", UUID.randomUUID().toString())
                    put("correlation_id", "invalid-corr-id")
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                    put("payload", JSONObject(mapOf("status" to "success")))
                }.toString(),
                ErrorCode.INVALID_CORRELATION_ID
            )

            invalid["invalid_request_missing_payload.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "request")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                }.toString(),
                ErrorCode.INVALID_PAYLOAD
            )

            invalid["invalid_request_missing_action.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "request")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                    put("payload", JSONObject())
                }.toString(),
                ErrorCode.INVALID_PAYLOAD
            )

            invalid["invalid_response_missing_correlation.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "response")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                    put("payload", JSONObject(mapOf("status" to "success")))
                }.toString(),
                ErrorCode.INVALID_CORRELATION_ID
            )

            invalid["invalid_response_missing_payload.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "response")
                    put("id", UUID.randomUUID().toString())
                    put("correlation_id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                }.toString(),
                ErrorCode.INVALID_PAYLOAD
            )

            invalid["invalid_error_missing_error_obj.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "error")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                }.toString(),
                ErrorCode.INVALID_PAYLOAD
            )

            invalid["invalid_error_missing_code.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "error")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                    put("error", JSONObject(mapOf("message" to "Something went wrong")))
                }.toString(),
                ErrorCode.INVALID_PAYLOAD
            )

            invalid["invalid_heartbeat_ack_missing_correlation.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "heartbeat_ack")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                }.toString(),
                ErrorCode.INVALID_CORRELATION_ID
            )

            invalid["invalid_oversized_message.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "request")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                    put("payload", JSONObject(mapOf("action" to "bulk", "data" to "A".repeat(70000))))
                }.toString(),
                ErrorCode.OVERSIZED_MESSAGE
            )

            // 23. Request payload data not an object (malformed pairing payload)
            invalid["invalid_request_pair_data_not_object.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "request")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                    put("payload", JSONObject(mapOf("action" to "pair_request", "data" to "not_an_object")))
                }.toString(),
                ErrorCode.INVALID_PAYLOAD
            )

            // 24. Response missing correlation_id
            invalid["invalid_pair_response_missing_correlation.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "response")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                    put("payload", JSONObject(mapOf("status" to "success", "action" to "pair_request")))
                }.toString(),
                ErrorCode.INVALID_CORRELATION_ID
            )

            val manifest = JSONObject()
            for ((filename, pair) in invalid) {
                File(ktToPyInvalid, filename).writeText(pair.first, Charsets.UTF_8)
                manifest.put(filename, pair.second)
            }
            File(ktToPyInvalid, "expected_errors.json").writeText(manifest.toString(2), Charsets.UTF_8)
        }
    }

    @Test
    fun testValidatePythonToKotlinValidFixtures() {
        if (!pyToKtValid.exists()) return

        val files = pyToKtValid.listFiles { _, name -> name.endsWith(".json") } ?: return
        assertTrue("Python valid fixtures should be present", files.isNotEmpty())

        for (file in files) {
            val rawJson = file.readText(Charsets.UTF_8)

            // Verify clean serialization invariant: optional null fields must NOT be present
            assertFalse(
                "Fixture ${file.name} must not contain explicit null for correlation_id",
                rawJson.contains("\"correlation_id\":null")
            )
            assertFalse(
                "Fixture ${file.name} must not contain explicit null for payload",
                rawJson.contains("\"payload\":null")
            )
            assertFalse(
                "Fixture ${file.name} must not contain explicit null for error",
                rawJson.contains("\"error\":null")
            )

            val message = ProtocolValidator.validateRawMessage(rawJson)
            assertEquals("File ${file.name} version mismatch", Constants.PROTOCOL_VERSION, message.version)
            assertTrue("File ${file.name} type mismatch", MessageType.VALID_TYPES.contains(message.type))
            assertEquals(36, message.id.length)
            assertTrue("File ${file.name} timestamp must be UTC", message.timestamp.endsWith("Z") || message.timestamp.contains("+00:00"))
        }
    }

    @Test
    fun testValidatePythonToKotlinInvalidFixtures() {
        if (!pyToKtInvalid.exists()) return

        val manifestFile = File(pyToKtInvalid, "expected_errors.json")
        if (!manifestFile.exists()) return

        val manifest = JSONObject(manifestFile.readText(Charsets.UTF_8))
        val keys = manifest.keys()
        while (keys.hasNext()) {
            val filename = keys.next()
            val expectedCode = manifest.getString(filename)
            val file = File(pyToKtInvalid, filename)
            if (!file.exists()) continue

            val rawJson = file.readText(Charsets.UTF_8)
            try {
                ProtocolValidator.validateRawMessage(rawJson)
                fail("File $filename was expected to fail with code $expectedCode, but passed validation.")
            } catch (e: ProtocolValidationError) {
                assertEquals("File $filename error code mismatch", expectedCode, e.code)
            }
        }
    }
}
