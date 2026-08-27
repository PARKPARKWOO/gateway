package org.woo.gateway.security

import org.springframework.core.env.Environment
import org.springframework.core.env.Profiles
import org.springframework.http.ResponseCookie
import org.springframework.stereotype.Component
import org.woo.gateway.config.GatewayAuthCookieProperties
import java.time.Duration

@Component
class GatewayAuthCookieFactory(
    private val properties: GatewayAuthCookieProperties,
    environment: Environment,
) {
    private val domain = properties.domain?.trim()?.takeIf { it.isNotEmpty() }
    private val sameSite = properties.sameSite.trim()

    init {
        require(sameSite in ALLOWED_SAME_SITE_VALUES) {
            "gateway.auth.cookie.same-site must be one of Lax, Strict, or None"
        }
        val isLocalOrTest = environment.acceptsProfiles(Profiles.of("local", "test"))
        require(sameSite != "None" || properties.secure || isLocalOrTest) {
            "SameSite=None requires Secure=true outside local and test profiles"
        }
    }

    fun issue(
        name: String,
        value: String,
        expiresInMillis: Long,
    ): ResponseCookie = build(name, value, Duration.ofMillis(expiresInMillis))

    fun clear(name: String): ResponseCookie = build(name, "", Duration.ZERO)

    private fun build(
        name: String,
        value: String,
        maxAge: Duration,
    ): ResponseCookie {
        val builder =
            ResponseCookie
                .from(name, value)
                .httpOnly(properties.httpOnly)
                .secure(properties.secure)
                .path(properties.path)
                .maxAge(maxAge)
                .sameSite(sameSite)
        domain?.let(builder::domain)
        return builder.build()
    }

    fun accessTokenName(): String = properties.accessTokenName

    fun refreshTokenName(): String = properties.refreshTokenName

    private companion object {
        val ALLOWED_SAME_SITE_VALUES = setOf("Lax", "Strict", "None")
    }
}
