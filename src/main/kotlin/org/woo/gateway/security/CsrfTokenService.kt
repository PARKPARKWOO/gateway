package org.woo.gateway.security

import org.springframework.stereotype.Component
import org.woo.gateway.config.CsrfTokenProperties
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

interface CsrfTokenService {
    fun generate(): String

    fun matches(
        cookieValue: String,
        headerValue: String,
    ): Boolean
}

@Component
class SecureCsrfTokenService(
    private val properties: CsrfTokenProperties,
) : CsrfTokenService {
    private val secureRandom = SecureRandom()

    init {
        require(properties.bytes == TOKEN_BYTES) {
            "gateway.security.csrf.token.bytes must be exactly $TOKEN_BYTES"
        }
    }

    override fun generate(): String {
        val bytes = ByteArray(properties.bytes)
        secureRandom.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    override fun matches(
        cookieValue: String,
        headerValue: String,
    ): Boolean {
        if (cookieValue.isEmpty() || headerValue.isEmpty()) return false
        return MessageDigest.isEqual(
            cookieValue.toByteArray(StandardCharsets.UTF_8),
            headerValue.toByteArray(StandardCharsets.UTF_8),
        )
    }

    private companion object {
        const val TOKEN_BYTES = 32
    }
}
