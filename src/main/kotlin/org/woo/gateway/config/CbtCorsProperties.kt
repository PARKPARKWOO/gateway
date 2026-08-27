package org.woo.gateway.config

import org.springframework.boot.context.properties.ConfigurationProperties
import java.net.URI

@ConfigurationProperties("gateway.security.cbt-cors")
data class CbtCorsProperties(
    val allowedOrigins: Set<URI> =
        setOf(
            URI("https://mirror-view.platformholder.site"),
            URI("http://localhost:5173"),
            URI("http://127.0.0.1:4173"),
        ),
)
