package org.woo.gateway.security

import org.springframework.stereotype.Component
import org.woo.gateway.config.CsrfTokenProperties
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
        val cookieBytes = decodeCanonical(cookieValue) ?: return false
        val headerBytes = decodeCanonical(headerValue) ?: return false
        return MessageDigest.isEqual(cookieBytes, headerBytes)
    }

    private fun decodeCanonical(value: String): ByteArray? {
        if (!TOKEN_PATTERN.matches(value)) return null
        val decoded =
            try {
                Base64.getUrlDecoder().decode(value)
            } catch (_: IllegalArgumentException) {
                return null
            }
        if (decoded.size != TOKEN_BYTES) return null
        if (Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) != value) return null
        return decoded
    }

    private companion object {
        const val TOKEN_BYTES = 32
        val TOKEN_PATTERN = Regex("[A-Za-z0-9_-]{43}")
    }
}
