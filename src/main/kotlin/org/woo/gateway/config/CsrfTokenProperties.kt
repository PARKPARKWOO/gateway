package org.woo.gateway.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("gateway.security.csrf.token")
data class CsrfTokenProperties(
    val cookieName: String = "XSRF-TOKEN",
    val headerName: String = "X-XSRF-TOKEN",
    val cookieDomain: String? = ".platformholder.site",
    val secure: Boolean = true,
    val sameSite: String = "None",
    val path: String = "/",
    val httpOnly: Boolean = false,
    val bytes: Int = 32,
)
