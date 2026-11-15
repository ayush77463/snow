package org.snow.protocol

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

/**
 * Handles wire-level JSON serialization and deserialization for SNOW Device Protocol v1.
 *
 * Invariant: Optional fields (correlation_id, payload, error) MUST be completely omitted
 * when null. Never emit "field": null.
 */
object JsonSerialization {

    /**
     * Serialize a [SnowMessage] to a JSON string, strictly omitting null fields.
     */
    fun toJson(message: SnowMessage): String {
        val json = JSONObject()
        json.put("version", message.version)
        json.put("type", message.type)
        json.put("id", message.id)
        json.put("timestamp", message.timestamp)

        message.correlationId?.let {
            json.put("correlation_id", it)
        }

        message.payload?.let {
            json.put("payload", mapToJson(it))
        }

        message.error?.let {
            val errObj = JSONObject()
            errObj.put("code", it.code)
            errObj.put("message", it.message)
            json.put("error", errObj)
        }

        return json.toString()
    }

    /**
     * Parse a raw JSON string into a [SnowMessage].
     *
     * @throws ProtocolValidationError if the JSON is malformed.
     */
    @Throws(ProtocolValidationError::class)
    fun fromJson(jsonStr: String): SnowMessage {
        val root = try {
            JSONObject(jsonStr)
        } catch (e: JSONException) {
            throw ProtocolValidationError(
                code = ErrorCode.INVALID_JSON,
                message = "Malformed JSON payload: ${e.message}"
            )
        }

        val version = if (root.has("version") && !root.isNull("version")) {
            val v = root.get("version")
            if (v is Int) {
                v
            } else {
                throw ProtocolValidationError(
                    code = ErrorCode.UNSUPPORTED_VERSION,
                    message = "'version' must be an integer, got ${v.javaClass.simpleName}."
                )
            }
        } else {
            throw ProtocolValidationError(
                code = ErrorCode.UNSUPPORTED_VERSION,
                message = "Missing required field: 'version'."
            )
        }

        val type = if (root.has("type") && !root.isNull("type")) {
            val t = root.get("type")
            if (t is String) {
                t
            } else {
                throw ProtocolValidationError(
                    code = ErrorCode.INVALID_MESSAGE_TYPE,
                    message = "'type' must be a string."
                )
            }
        } else {
            throw ProtocolValidationError(
                code = ErrorCode.INVALID_MESSAGE_TYPE,
                message = "Missing required field: 'type'."
            )
        }

        val id = if (root.has("id") && !root.isNull("id")) {
            val idVal = root.get("id")
            if (idVal is String) {
                idVal
            } else {
                throw ProtocolValidationError(
                    code = ErrorCode.INVALID_MESSAGE_ID,
                    message = "'id' must be a string."
                )
            }
        } else {
            throw ProtocolValidationError(
                code = ErrorCode.INVALID_MESSAGE_ID,
                message = "Missing required field: 'id'."
            )
        }

        val timestamp = if (root.has("timestamp") && !root.isNull("timestamp")) {
            val tsVal = root.get("timestamp")
            if (tsVal is String) {
                tsVal
            } else {
                throw ProtocolValidationError(
                    code = ErrorCode.INVALID_TIMESTAMP,
                    message = "'timestamp' must be a string."
                )
            }
        } else {
            throw ProtocolValidationError(
                code = ErrorCode.INVALID_TIMESTAMP,
                message = "Missing required field: 'timestamp'."
            )
        }

        val correlationId = if (root.has("correlation_id") && !root.isNull("correlation_id")) {
            val c = root.get("correlation_id")
            if (c is String) c else null
        } else {
            null
        }

        val payload = if (root.has("payload") && !root.isNull("payload")) {
            val p = root.get("payload")
            if (p is JSONObject) {
                jsonToMap(p)
            } else {
                null
            }
        } else {
            null
        }

        val error = if (root.has("error") && !root.isNull("error")) {
            val e = root.get("error")
            if (e is JSONObject) {
                val errCode = if (e.has("code") && !e.isNull("code")) e.optString("code") else ""
                val errMsg = if (e.has("message") && !e.isNull("message")) e.optString("message") else ""
                SnowError(code = errCode, message = errMsg)
            } else {
                null
            }
        } else {
            null
        }

        return SnowMessage(
            version = version,
            type = type,
            id = id,
            timestamp = timestamp,
            correlationId = correlationId,
            payload = payload,
            error = error
        )
    }

    private fun mapToJson(map: Map<String, Any?>): JSONObject {
        val obj = JSONObject()
        for ((key, value) in map) {
            when (value) {
                null -> obj.put(key, JSONObject.NULL)
                is Map<*, *> -> @Suppress("UNCHECKED_CAST") obj.put(key, mapToJson(value as Map<String, Any?>))
                is List<*> -> obj.put(key, listToJson(value))
                else -> obj.put(key, value)
            }
        }
        return obj
    }

    private fun listToJson(list: List<*>): JSONArray {
        val arr = JSONArray()
        for (item in list) {
            when (item) {
                null -> arr.put(JSONObject.NULL)
                is Map<*, *> -> @Suppress("UNCHECKED_CAST") arr.put(mapToJson(item as Map<String, Any?>))
                is List<*> -> arr.put(listToJson(item))
                else -> arr.put(item)
            }
        }
        return arr
    }

    fun jsonToMap(jsonObj: JSONObject): Map<String, Any?> {
        val map = mutableMapOf<String, Any?>()
        val keys = jsonObj.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            val value = jsonObj.get(key)
            map[key] = when (value) {
                JSONObject.NULL -> null
                is JSONObject -> jsonToMap(value)
                is JSONArray -> jsonToList(value)
                else -> value
            }
        }
        return map
    }

    private fun jsonToList(jsonArr: JSONArray): List<Any?> {
        val list = mutableListOf<Any?>()
        for (i in 0 until jsonArr.length()) {
            val value = jsonArr.get(i)
            list.add(
                when (value) {
                    JSONObject.NULL -> null
                    is JSONObject -> jsonToMap(value)
                    is JSONArray -> jsonToList(value)
                    else -> value
                }
            )
        }
        return list
    }
}
