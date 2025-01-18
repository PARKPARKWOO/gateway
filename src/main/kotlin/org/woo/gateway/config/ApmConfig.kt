package org.woo.gateway.config

import brave.Span
import brave.Tracer
import jakarta.annotation.PostConstruct
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.web.server.WebFilter
import org.woo.apm.log.config.TracingConfig
import org.woo.apm.log.constant.ContextConstant.TRACE_ID
import reactor.core.publisher.Hooks

@Configuration
@Import(TracingConfig::class)
class ApmConfig {
    @Bean
    fun trace(tracer: Tracer): WebFilter = WebFilter { exchange, chain ->
        val currentSpan = tracer.currentSpan()
        if (currentSpan != null) {
            exchange.response.headers.add(TRACE_ID, currentSpan.context().traceIdString())
        } else {
            exchange.response.headers.add(TRACE_ID, "no-span")
        }
        chain.filter(exchange)
    }

    @PostConstruct
    fun init() {
        Hooks.enableAutomaticContextPropagation()
    }
}