package org.woo.gateway

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull

class CbtWebSessionContractFixtureTest {
    private val mapper = jacksonObjectMapper()

    @Test
    fun `web session fixture freezes the exact cookie csrf and operation contract`() {
        val stream = assertNotNull(javaClass.classLoader.getResourceAsStream("contracts/cbt-web-session.json"))
        val contract = mapper.readTree(stream)

        assertEquals(1, contract["version"].asInt())
        assertEquals("HTTP_ONLY_COOKIE", contract["authTransport"]["web"].asText())
        assertEquals("GATEWAY", contract["authTransport"]["rotationOwner"].asText())
        assertFalse(contract["authTransport"]["webDirectReissue"].asBoolean())
        assertEquals(
            listOf(
                "https://mirror-view.platformholder.site",
                "http://localhost:5173",
                "http://127.0.0.1:4173",
            ),
            contract["allowedWebOrigins"].map { it.asText() },
        )
        assertEquals("XSRF-TOKEN", contract["cookies"]["csrf"]["cookieName"].asText())
        assertEquals("X-XSRF-TOKEN", contract["cookies"]["csrf"]["headerName"].asText())
        assertEquals(emptyList(), contract["operationHeaders"]["attemptCreate"]["optional"].map { it.asText() })
        assertEquals(
            listOf("X-CBT-Attempt-Token"),
            contract["operationHeaders"]["attemptClaim"]["optional"].map { it.asText() },
        )
    }
}
