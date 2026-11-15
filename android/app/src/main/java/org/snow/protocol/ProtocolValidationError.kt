package org.snow.protocol

class ProtocolValidationError(
    val code: String,
    override val message: String,
    val correlationId: String? = null
) : Exception("[$code] $message")
