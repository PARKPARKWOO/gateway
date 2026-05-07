package org.woo.gateway

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication
import org.woo.gateway.config.CsrfOriginProperties

@SpringBootApplication
@EnableConfigurationProperties(CsrfOriginProperties::class)
class GatewayApplication

fun main(args: Array<String>) {
    runApplication<GatewayApplication>(*args)
}
