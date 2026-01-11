package org.woo.gateway.config

import io.swagger.v3.oas.annotations.OpenAPIDefinition
import io.swagger.v3.oas.annotations.info.Info
import io.swagger.v3.oas.annotations.servers.Server
import org.springframework.context.annotation.Configuration

@Configuration
@OpenAPIDefinition(
    info = Info(
        title = "Gateway API",
        version = "1.0.0",
        description = "통합 API Gateway 문서"
    ),
    servers = [
        Server(url = "/", description = "Gateway Server")
    ]
)
class SwaggerConfig
