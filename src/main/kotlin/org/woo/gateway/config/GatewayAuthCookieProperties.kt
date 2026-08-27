package org.woo.gateway.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("gateway.auth.cookie")
data class GatewayAuthCookieProperties(
    val accessTokenName: String = "accessToken",
    val refreshTokenName: String = "refreshToken",
    val domain: String?,
    val secure: Boolean,
    val sameSite: String,
    val path: String = "/",
    val httpOnly: Boolean = true,
)
