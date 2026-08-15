package org.woo.gateway

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class LogbackSecurityContractTest {
    @Test
    fun `logback patterns never render the raw request id MDC key`() {
        val resource = requireNotNull(javaClass.classLoader.getResource("logback-spring.xml"))
        val config = resource.openStream().bufferedReader().use { it.readText() }
        val safeTracePattern = "%X{traceId:-NONE}"

        assertThat(config).doesNotContain("%X{X-Request-ID")
        assertThat(Regex(Regex.escape(safeTracePattern)).findAll(config).count()).isEqualTo(2)
        assertThat(config).contains(
            "<logger name=\"org.springframework.web.server.adapter.HttpWebHandlerAdapter\" level=\"OFF\"/>",
        )
    }
}
