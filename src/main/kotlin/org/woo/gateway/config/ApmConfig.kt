package org.woo.gateway.config

import brave.Span
import brave.Tracer
import jakarta.annotation.PostConstruct
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.web.server.WebFilter
import org.woo.apm.log.config.TracingConfig
import reactor.core.publisher.Hooks

@Configuration
@Import(TracingConfig::class)
class ApmConfig {
    @Bean
    fun trace(tracer: Tracer): WebFilter = TracingConfig.create(tracer)

    @PostConstruct
    fun init() {
        Hooks.enableAutomaticContextPropagation()
    }
}