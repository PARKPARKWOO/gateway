package org.woo.gateway

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication
import org.woo.gateway.config.CsrfOriginProperties
import org.woo.gateway.config.GatewayAuthCookieProperties

@SpringBootApplication
@EnableConfigurationProperties(CsrfOriginProperties::class, GatewayAuthCookieProperties::class)
class GatewayApplication

fun main(args: Array<String>) {
    runApplication<GatewayApplication>(*args)
}
