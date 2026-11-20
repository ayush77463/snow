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

            val sampleManifest = mapOf(
                "manifest_version" to "2.0",
                "supported_capabilities" to listOf(
                    "android.apps.launch",
                    "android.apps.list",
                    "android.clipboard.get",
                    "android.clipboard.set",
                    "android.files.transfer",
                    "android.notifications.push",
                    "android.telemetry.get"
                ),
                "permission_states" to mapOf(
                    "POST_NOTIFICATIONS" to "GRANTED",
                    "android.telemetry.get" to "GRANTED"
                ),
                "classifications" to mapOf(
                    "android.apps.launch" to "FOREGROUND_USER_INTERACTION_REQUIRED",
                    "android.clipboard.get" to "FOREGROUND_USER_INTERACTION_REQUIRED",
                    "android.notifications.push" to "RUNTIME_PERMISSION_REQUIRED",
                    "android.telemetry.get" to "BACKGROUND_SAFE"
                )
            )

            // 11b. Request pair_request with manifest (Phase 13)
            val reqPairManifest = SnowMessage.createRequest(
                "pair_request",
                mapOf(
                    "device_id" to UUID.randomUUID().toString(),
                    "device_name" to "Test Client Device",
                    "pin" to "123456",
                    "manifest" to sampleManifest
                )
            )
            valid["request_pair_request_with_manifest.json"] = JsonSerialization.toJson(reqPairManifest)

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

            // 12b. Response pair success with manifest (Phase 13)
            val respPairManifest = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "pair_request",
                    "data" to mapOf(
                        "session_id" to UUID.randomUUID().toString(),
                        "device_id" to UUID.randomUUID().toString(),
                        "device_name" to "SNOW Desktop Core",
                        "auth_token" to "valid-token-hash-hex-sample",
                        "manifest" to sampleManifest
                    )
                )
            )
            valid["response_pair_success_with_manifest.json"] = JsonSerialization.toJson(respPairManifest)

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

            // 22. Valid auth_request request
            val reqAuth = SnowMessage.createRequest(
                "auth_request",
                mapOf(
                    "device_id" to UUID.randomUUID().toString(),
                    "auth_token" to "valid-auth-token-sample-secure"
                )
            )
            valid["request_auth_request.json"] = JsonSerialization.toJson(reqAuth)

            // 22b. Request auth_request with manifest (Phase 13)
            val reqAuthManifest = SnowMessage.createRequest(
                "auth_request",
                mapOf(
                    "device_id" to UUID.randomUUID().toString(),
                    "auth_token" to "valid-auth-token-sample-secure",
                    "manifest" to sampleManifest
                )
            )
            valid["request_auth_request_with_manifest.json"] = JsonSerialization.toJson(reqAuthManifest)

            // 23. Valid auth_request success response
            val respAuth = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "auth_request",
                    "data" to mapOf(
                        "device_id" to UUID.randomUUID().toString(),
                        "session_id" to UUID.randomUUID().toString()
                    )
                )
            )
            valid["response_auth_success.json"] = JsonSerialization.toJson(respAuth)

            // 23b. Response auth_request success with manifest (Phase 13)
            val respAuthManifest = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "auth_request",
                    "data" to mapOf(
                        "device_id" to UUID.randomUUID().toString(),
                        "session_id" to UUID.randomUUID().toString(),
                        "manifest" to sampleManifest
                    )
                )
            )
            valid["response_auth_success_with_manifest.json"] = JsonSerialization.toJson(respAuthManifest)

            // --- Phase 15 Live Manifest Update Protocol Fixtures ---
            // 23c. Valid manifest_update request
            val reqManifestUpdate = SnowMessage.createRequest(
                "manifest_update",
                mapOf(
                    "device_id" to UUID.randomUUID().toString(),
                    "manifest" to sampleManifest
                )
            )
            valid["request_manifest_update.json"] = JsonSerialization.toJson(reqManifestUpdate)

            // 23d. Valid manifest_update response
            val respManifestUpdate = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "message" to "Capability manifest updated successfully.",
                    "device_id" to UUID.randomUUID().toString()
                )
            )
            valid["response_manifest_update_success.json"] = JsonSerialization.toJson(respManifestUpdate)

            // --- Phase 16 Symmetric Mesh Protocol Fixtures ---
            // 23e. Valid mesh_list_peers request
            val reqMeshList = SnowMessage.createRequest(
                "mesh_list_peers",
                emptyMap()
            )
            valid["request_mesh_list_peers.json"] = JsonSerialization.toJson(reqMeshList)

            // 23f. Valid mesh_list_peers response
            val respMeshList = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "mesh_list_peers",
                    "data" to mapOf(
                        "peers" to listOf(
                            mapOf(
                                "device_id" to UUID.randomUUID().toString(),
                                "device_name" to "Peer Node Alpha",
                                "device_type" to "windows",
                                "reachability_state" to "CONNECTED_SESSION",
                                "reachability_profile" to "PERSISTENT_DAEMON",
                                "supported_capabilities" to listOf("desktop.status", "desktop.clipboard.read")
                            )
                        ),
                        "count" to 1
                    )
                )
            )
            valid["response_mesh_list_peers_success.json"] = JsonSerialization.toJson(respMeshList)

            // 23g. Valid peer_relay_request
            val reqPeerRelay = SnowMessage.createRequest(
                "peer_relay_request",
                mapOf(
                    "target_device_id" to UUID.randomUUID().toString(),
                    "action" to "battery_status",
                    "data" to emptyMap<String, Any?>(),
                    "hop_limit" to 2,
                    "visited_nodes" to listOf(UUID.randomUUID().toString())
                )
            )
            valid["request_peer_relay.json"] = JsonSerialization.toJson(reqPeerRelay)

            // 23h. Valid peer_relay response
            val respPeerRelay = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "peer_relay_request",
                    "data" to mapOf("level" to 88, "is_charging" to true),
                    "relayed_by" to UUID.randomUUID().toString(),
                    "target_device_id" to UUID.randomUUID().toString()
                )
            )
            valid["response_peer_relay_success.json"] = JsonSerialization.toJson(respPeerRelay)

            // --- Phase 3 File Transfer Protocol Fixtures ---
            // 24. Valid file_transfer_offer request
            val reqOffer = SnowMessage.createRequest(
                "file_transfer_offer",
                mapOf(
                    "file_name" to "photo_glacier.jpg",
                    "file_size" to 204800,
                    "sha256" to "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    "direction" to "UPLOAD"
                )
            )
            valid["request_file_transfer_offer.json"] = JsonSerialization.toJson(reqOffer)

            // 25. Valid file_transfer_offer response
            val respOffer = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "file_transfer_offer",
                    "data" to mapOf(
                        "transfer_id" to UUID.randomUUID().toString(),
                        "transfer_port" to 8766,
                        "transfer_url" to "/api/v1/transfers/upload/123",
                        "resume_offset" to 0,
                        "already_exists" to false,
                        "is_conflict" to false
                    )
                )
            )
            valid["response_file_transfer_offer.json"] = JsonSerialization.toJson(respOffer)

            // 26. Valid file_list_transfers request
            val reqList = SnowMessage.createRequest("file_list_transfers")
            valid["request_file_list_transfers.json"] = JsonSerialization.toJson(reqList)

            // 27. Valid file_list_transfers response
            val respList = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "file_list_transfers",
                    "data" to mapOf(
                        "transfers" to emptyList<Any>()
                    )
                )
            )
            valid["response_file_list_transfers.json"] = JsonSerialization.toJson(respList)

            // 28. Valid file_transfer_status request
            val reqStatus = SnowMessage.createRequest(
                "file_transfer_status",
                mapOf("transfer_id" to UUID.randomUUID().toString())
            )
            valid["request_file_transfer_status.json"] = JsonSerialization.toJson(reqStatus)

            // 29. Valid file_transfer_cancel request
            val reqCancel = SnowMessage.createRequest(
                "file_transfer_cancel",
                mapOf("transfer_id" to UUID.randomUUID().toString())
            )
            valid["request_file_transfer_cancel.json"] = JsonSerialization.toJson(reqCancel)

            // 30. Error TRANSFER_NOT_FOUND
            val errTransferNotFound = SnowMessage.createError(
                ErrorCode.TRANSFER_NOT_FOUND,
                "Requested transfer ID was not found.",
                reqId
            )
            valid["error_transfer_not_found.json"] = JsonSerialization.toJson(errTransferNotFound)

            // 31. Error INTEGRITY_MISMATCH
            val errIntegrity = SnowMessage.createError(
                ErrorCode.INTEGRITY_MISMATCH,
                "SHA-256 integrity verification failed.",
                reqId
            )
            valid["error_integrity_mismatch.json"] = JsonSerialization.toJson(errIntegrity)

            // --- Phase 6 Android Capability Protocol Fixtures ---
            // 32. Valid battery_status request
            val reqBattery = SnowMessage.createRequest(
                "battery_status",
                emptyMap<String, Any>()
            )
            valid["request_battery_status.json"] = JsonSerialization.toJson(reqBattery)

            // 33. Valid battery_status response
            val respBattery = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "battery_status",
                    "level" to 92,
                    "charging" to true,
                    "power_source" to "AC",
                    "health" to "GOOD",
                    "temperature_celsius" to 29.5,
                    "device_model" to "RMX5110",
                    "manufacturer" to "realme",
                    "android_version" to "17",
                    "sdk_int" to 34
                )
            )
            valid["response_battery_status.json"] = JsonSerialization.toJson(respBattery)

            // 34. Valid ring_phone request
            val reqRing = SnowMessage.createRequest(
                "ring_phone",
                mapOf("duration_seconds" to 5)
            )
            valid["request_ring_phone.json"] = JsonSerialization.toJson(reqRing)

            // 35. Valid ring_phone response
            val respRing = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "ring_phone",
                    "duration_seconds" to 5,
                    "message" to "Audible alert initiated on Android device for 5 seconds."
                )
            )
            valid["response_ring_phone.json"] = JsonSerialization.toJson(respRing)

            // 36. Valid clipboard_push request
            val reqClip = SnowMessage.createRequest(
                "clipboard_push",
                mapOf("text" to "Hello SNOW cross-device clipboard")
            )
            valid["request_clipboard_push.json"] = JsonSerialization.toJson(reqClip)

            // 37. Valid clipboard_push response
            val respClip = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "clipboard_push",
                    "bytes_written" to 34,
                    "message" to "Text successfully copied to Android clipboard."
                )
            )
            valid["response_clipboard_push.json"] = JsonSerialization.toJson(respClip)

            // 38. Valid list_apps request
            val reqListApps = SnowMessage.createRequest(
                "list_apps",
                mapOf("limit" to 50)
            )
            valid["request_list_apps.json"] = JsonSerialization.toJson(reqListApps)

            // 39. Valid list_apps response
            val respListApps = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "list_apps",
                    "count" to 2,
                    "apps" to listOf(
                        mapOf("package_name" to "com.android.settings", "label" to "Settings"),
                        mapOf("package_name" to "org.snow.app", "label" to "SNOW")
                    )
                )
            )
            valid["response_list_apps.json"] = JsonSerialization.toJson(respListApps)

            // 40. Valid launch_app request
            val reqLaunch = SnowMessage.createRequest(
                "launch_app",
                mapOf("package_name" to "com.android.settings")
            )
            valid["request_launch_app.json"] = JsonSerialization.toJson(reqLaunch)

            // 41. Valid launch_app response
            val respLaunch = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "launch_app",
                    "package_name" to "com.android.settings",
                    "message" to "Successfully launched application 'com.android.settings'."
                )
            )
            valid["response_launch_app.json"] = JsonSerialization.toJson(respLaunch)

            // 42. Valid file_send_request request
            val reqFileSend = SnowMessage.createRequest(
                "file_send_request",
                mapOf(
                    "transfer_id" to UUID.randomUUID().toString(),
                    "file_name" to "sample_document.pdf",
                    "file_size" to 10240,
                    "sha256" to "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    "transfer_port" to 8766
                )
            )
            valid["request_file_send_request.json"] = JsonSerialization.toJson(reqFileSend)

            // 43. Valid file_send_request response
            val respFileSend = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "file_send_request",
                    "transfer_id" to UUID.randomUUID().toString(),
                    "file_name" to "sample_document.pdf",
                    "bytes_downloaded" to 10240,
                    "sha256" to "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    "saved_path" to "/storage/emulated/0/Download/SNOW/sample_document.pdf"
                )
            )
            valid["response_file_send_request.json"] = JsonSerialization.toJson(respFileSend)

            // 44. Valid file_receive_request request
            val reqFileRecv = SnowMessage.createRequest(
                "file_receive_request",
                mapOf(
                    "file_name" to "sample_document.pdf",
                    "transfer_port" to 8766
                )
            )
            valid["request_file_receive_request.json"] = JsonSerialization.toJson(reqFileRecv)

            // 45. Valid file_receive_request response
            val respFileRecv = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "file_receive_request",
                    "transfer_id" to UUID.randomUUID().toString(),
                    "file_name" to "sample_document.pdf",
                    "bytes_uploaded" to 10240,
                    "sha256" to "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                )
            )
            valid["response_file_receive_request.json"] = JsonSerialization.toJson(respFileRecv)

            // --- Phase 10 Bidirectional Control Fixtures ---
            // 46. Valid desktop_status request and response
            val reqDesktopStatus = SnowMessage.createRequest("desktop_status")
            valid["request_desktop_status.json"] = JsonSerialization.toJson(reqDesktopStatus)

            val respDesktopStatus = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "desktop_status",
                    "data" to mapOf(
                        "hostname" to "SNOW-LAPTOP",
                        "cpu_percent" to 14.5,
                        "memory_percent" to 42.0,
                        "memory_total_mb" to 16384.0,
                        "memory_used_mb" to 6881.0,
                        "battery" to mapOf("available" to true, "percent" to 95.0, "power_plugged" to true),
                        "uptime_seconds" to 3600.0
                    )
                )
            )
            valid["response_desktop_status.json"] = JsonSerialization.toJson(respDesktopStatus)

            // 47. Valid desktop_exec request and response
            val reqExec = SnowMessage.createRequest(
                "desktop_exec",
                mapOf("command" to "python --version", "timeout" to 15.0)
            )
            valid["request_desktop_exec.json"] = JsonSerialization.toJson(reqExec)

            val respExec = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "desktop_exec",
                    "data" to mapOf(
                        "command" to "python --version",
                        "stdout" to "Python 3.13.15\n",
                        "stderr" to "",
                        "exit_code" to 0,
                        "truncated" to false,
                        "duration_seconds" to 0.08
                    )
                )
            )
            valid["response_desktop_exec.json"] = JsonSerialization.toJson(respExec)

            // 48. Valid desktop_app_launch request and response
            val reqApp = SnowMessage.createRequest(
                "desktop_app_launch",
                mapOf("app_name" to "notepad")
            )
            valid["request_desktop_app_launch.json"] = JsonSerialization.toJson(reqApp)

            val respApp = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "desktop_app_launch",
                    "data" to mapOf(
                        "success" to true,
                        "status" to "SUCCESS",
                        "app_name" to "notepad",
                        "pid" to 12345,
                        "message" to "Successfully launched notepad (PID 12345)."
                    )
                )
            )
            valid["response_desktop_app_launch.json"] = JsonSerialization.toJson(respApp)

            // 49. Valid desktop_clipboard_get request and response
            val reqClipGet = SnowMessage.createRequest("desktop_clipboard_get")
            valid["request_desktop_clipboard_get.json"] = JsonSerialization.toJson(reqClipGet)

            val respClipGet = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "desktop_clipboard_get",
                    "data" to mapOf(
                        "text" to "Cross-device synced text ❄️",
                        "length" to 28
                    )
                )
            )
            valid["response_desktop_clipboard_get.json"] = JsonSerialization.toJson(respClipGet)

            // 50. Valid desktop_clipboard_set request and response
            val reqClipSet = SnowMessage.createRequest(
                "desktop_clipboard_set",
                mapOf("text" to "New clipboard text from Phone")
            )
            valid["request_desktop_clipboard_set.json"] = JsonSerialization.toJson(reqClipSet)

            val respClipSet = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "desktop_clipboard_set",
                    "data" to mapOf(
                        "success" to true,
                        "status" to "SUCCESS",
                        "length" to 30
                    )
                )
            )
            valid["response_desktop_clipboard_set.json"] = JsonSerialization.toJson(respClipSet)

            // 51. Valid desktop_file_list request and response
            val reqFileList = SnowMessage.createRequest(
                "desktop_file_list",
                mapOf("path" to "Documents", "limit" to 20)
            )
            valid["request_desktop_file_list.json"] = JsonSerialization.toJson(reqFileList)

            val respFileList = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "desktop_file_list",
                    "data" to mapOf(
                        "directory" to "Documents",
                        "count" to 2,
                        "files" to listOf(
                            mapOf("name" to "report.pdf", "type" to "file", "size_bytes" to 10240, "modified_at" to "2026-11-17T08:00:00Z"),
                            mapOf("name" to "Projects", "type" to "directory", "size_bytes" to 0, "modified_at" to "2026-11-17T08:00:00Z")
                        )
                    )
                )
            )
            valid["response_desktop_file_list.json"] = JsonSerialization.toJson(respFileList)

            // 52. Valid desktop_file_stage_download request and response
            val reqStage = SnowMessage.createRequest(
                "desktop_file_stage_download",
                mapOf("file_path" to "report.pdf")
            )
            valid["request_desktop_file_stage_download.json"] = JsonSerialization.toJson(reqStage)

            val respStage = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "desktop_file_stage_download",
                    "data" to mapOf(
                        "transfer_id" to UUID.randomUUID().toString(),
                        "file_name" to "report.pdf",
                        "file_size" to 10240,
                        "sha256" to "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                        "transfer_port" to 8766,
                        "transfer_url" to "/api/v1/transfers/download/test-tid-10"
                    )
                )
            )
            valid["response_desktop_file_stage_download.json"] = JsonSerialization.toJson(respStage)

            // 53. Valid send_message request and response
            val reqMsg = SnowMessage.createRequest(
                "send_message",
                mapOf("recipient" to "+1234567890", "message" to "Emergency alert", "mode" to "intent")
            )
            valid["request_send_message.json"] = JsonSerialization.toJson(reqMsg)

            val respMsg = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "send_message",
                    "data" to mapOf(
                        "status" to "success",
                        "action" to "send_message",
                        "mode" to "intent",
                        "recipient" to "+1234567890",
                        "result" to "INTENT_LAUNCHED",
                        "message" to "Messaging composer intent launched on device."
                    )
                )
            )
            valid["response_send_message.json"] = JsonSerialization.toJson(respMsg)

            // --- Phase 21 Core Capabilities Protocol Fixtures ---
            // 54. Valid file_list request and responses
            val reqFileListP21 = SnowMessage.createRequest(
                "file_list",
                mapOf("subpath" to "Documents/Glacier")
            )
            valid["request_file_list.json"] = JsonSerialization.toJson(reqFileListP21)

            val respFileListP21 = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "file_list",
                    "data" to mapOf(
                        "folder_name" to "Glacier",
                        "items" to listOf(
                            mapOf("name" to "doc.pdf", "type" to "file", "size_bytes" to 2048, "uri" to "content://doc1"),
                            mapOf("name" to "SubDir", "type" to "directory", "size_bytes" to 0, "uri" to "content://doc2")
                        ),
                        "count" to 2
                    )
                )
            )
            valid["response_file_list.json"] = JsonSerialization.toJson(respFileListP21)

            val respFileListSafErr = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "error",
                    "error" to "SAF_FOLDER_NOT_CONFIGURED",
                    "message" to "SAF directory grant missing."
                )
            )
            valid["response_file_list_saf_error.json"] = JsonSerialization.toJson(respFileListSafErr)

            // 55. Valid notifications_list and dismiss request and responses
            val reqNotifList = SnowMessage.createRequest("notifications_list", emptyMap())
            valid["request_notifications_list.json"] = JsonSerialization.toJson(reqNotifList)

            val respNotifList = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "notifications_list",
                    "data" to mapOf(
                        "notifications" to listOf(
                            mapOf(
                                "key" to "notif-001",
                                "package_name" to "org.thoughtcrime.securesms",
                                "app_name" to "Signal",
                                "title" to "Bob",
                                "text" to "Meeting at 3pm",
                                "timestamp" to 1732100000000L,
                                "can_reply" to true
                            )
                        ),
                        "count" to 1
                    )
                )
            )
            valid["response_notifications_list.json"] = JsonSerialization.toJson(respNotifList)

            val reqNotifDismiss = SnowMessage.createRequest(
                "notification_dismiss",
                mapOf("key" to "notif-001")
            )
            valid["request_notification_dismiss.json"] = JsonSerialization.toJson(reqNotifDismiss)

            val respNotifDismiss = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "notification_dismiss",
                    "data" to mapOf("key" to "notif-001", "dismissed" to true)
                )
            )
            valid["response_notification_dismiss.json"] = JsonSerialization.toJson(respNotifDismiss)

            // 56. Valid media_control request and response
            val reqMedia = SnowMessage.createRequest(
                "media_control",
                mapOf("action" to "play_pause", "target" to "android")
            )
            valid["request_media_control.json"] = JsonSerialization.toJson(reqMedia)

            val respMedia = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "media_control",
                    "data" to mapOf("action" to "play_pause", "target" to "android", "executed" to true)
                )
            )
            valid["response_media_control.json"] = JsonSerialization.toJson(respMedia)

            // 57. Valid share_link request and responses
            val reqShareLink = SnowMessage.createRequest(
                "share_link",
                mapOf("url" to "https://snow.example.com", "target" to "android")
            )
            valid["request_share_link.json"] = JsonSerialization.toJson(reqShareLink)

            val respShareLinkOpened = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "success",
                    "action" to "share_link",
                    "data" to mapOf(
                        "status" to "success",
                        "action" to "opened_browser",
                        "url" to "https://snow.example.com"
                    )
                )
            )
            valid["response_share_link_opened.json"] = JsonSerialization.toJson(respShareLinkOpened)

            val respShareLinkTap = SnowMessage.createResponse(
                reqId,
                mapOf(
                    "status" to "NOTIFICATION_TAP_REQUIRED",
                    "action" to "share_link",
                    "data" to mapOf(
                        "status" to "NOTIFICATION_TAP_REQUIRED",
                        "action" to "notification_posted",
                        "url" to "https://snow.example.com",
                        "requires_tap" to true
                    )
                )
            )
            valid["response_share_link_notification_tap.json"] = JsonSerialization.toJson(respShareLinkTap)

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

            // 25. Request payload data not an object (malformed auth payload)
            invalid["invalid_auth_request_data_not_object.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "request")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                    put("payload", JSONObject(mapOf("action" to "auth_request", "data" to "not_an_object")))
                }.toString(),
                ErrorCode.INVALID_PAYLOAD
            )

            // 26. Auth response invalid correlation_id
            invalid["invalid_auth_response_invalid_correlation_id.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "response")
                    put("id", UUID.randomUUID().toString())
                    put("correlation_id", "not-a-valid-uuid")
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                    put("payload", JSONObject(mapOf("status" to "success", "action" to "auth_request")))
                }.toString(),
                ErrorCode.INVALID_CORRELATION_ID
            )

            // 27. Phase 6 Request payload data not an object (malformed battery_status payload)
            invalid["invalid_request_battery_data_not_object.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "request")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                    put("payload", JSONObject(mapOf("action" to "battery_status", "data" to "not_an_object")))
                }.toString(),
                ErrorCode.INVALID_PAYLOAD
            )

            // 28. Phase 21 media_control data not an object
            invalid["invalid_request_media_control_data_not_object.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "request")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                    put("payload", JSONObject(mapOf("action" to "media_control", "data" to "not_an_object")))
                }.toString(),
                ErrorCode.INVALID_PAYLOAD
            )

            // 29. Phase 21 share_link data not an object
            invalid["invalid_request_share_link_data_not_object.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "request")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                    put("payload", JSONObject(mapOf("action" to "share_link", "data" to 12345)))
                }.toString(),
                ErrorCode.INVALID_PAYLOAD
            )

            // 30. Phase 21 file_list data not an object
            invalid["invalid_request_file_list_data_not_object.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "request")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                    put("payload", JSONObject(mapOf("action" to "file_list", "data" to JSONArray(listOf("not", "an", "object")))))
                }.toString(),
                ErrorCode.INVALID_PAYLOAD
            )

            // 31. Phase 21 notifications_list data not an object
            invalid["invalid_request_notifications_list_data_not_object.json"] = Pair(
                JSONObject().apply {
                    put("version", 1)
                    put("type", "request")
                    put("id", UUID.randomUUID().toString())
                    put("timestamp", SnowMessage.currentIsoTimestamp())
                    put("payload", JSONObject(mapOf("action" to "notifications_list", "data" to false)))
                }.toString(),
                ErrorCode.INVALID_PAYLOAD
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
