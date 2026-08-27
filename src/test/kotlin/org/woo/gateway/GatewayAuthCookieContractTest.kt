package org.woo.gateway

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.mock.env.MockEnvironment
import org.woo.gateway.config.GatewayAuthCookieProperties
import org.woo.gateway.security.GatewayAuthCookieFactory
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GatewayAuthCookieContractTest {
    @Test
    fun `production issue and clear cookies share one identity tuple`() {
        val factory =
            GatewayAuthCookieFactory(
                GatewayAuthCookieProperties(
                    domain = ".platformholder.site",
                    secure = true,
                    sameSite = "None",
                ),
                MockEnvironment(),
            )

        val issued = factory.issue("accessToken", "access-token-sentinel", 1_500)
        val cleared = factory.clear("accessToken")

        assertEquals("accessToken", issued.name)
        assertEquals(issued.name, cleared.name)
        assertEquals(issued.domain, cleared.domain)
        assertEquals(issued.path, cleared.path)
        assertEquals(issued.isHttpOnly, cleared.isHttpOnly)
        assertEquals(issued.isSecure, cleared.isSecure)
        assertEquals(issued.sameSite, cleared.sameSite)
        assertEquals(".platformholder.site", issued.domain)
        assertEquals("/", issued.path)
        assertTrue(issued.isHttpOnly)
        assertTrue(issued.isSecure)
        assertEquals("None", issued.sameSite)
        assertEquals(Duration.ofMillis(1_500), issued.maxAge)
        assertEquals(Duration.ZERO, cleared.maxAge)
    }

    @Test
    fun `local and test cookies omit domain and use lax insecure tuple`() {
        listOf("local", "test").forEach { profile ->
            val environment = MockEnvironment().apply { setActiveProfiles(profile) }
            val factory =
                GatewayAuthCookieFactory(
                    GatewayAuthCookieProperties(
                        domain = "  ",
                        secure = false,
                        sameSite = "Lax",
                    ),
                    environment,
                )

            val issued = factory.issue("refreshToken", "refresh-token-sentinel", 2_500)
            val cleared = factory.clear("refreshToken")

            assertNull(issued.domain)
            assertNull(cleared.domain)
            assertFalse(issued.isSecure)
            assertEquals("Lax", issued.sameSite)
            assertEquals(issued.path, cleared.path)
            assertEquals(issued.isHttpOnly, cleared.isHttpOnly)
            assertEquals(issued.isSecure, cleared.isSecure)
            assertEquals(issued.sameSite, cleared.sameSite)
        }
    }

    @Test
    fun `same site none with insecure cookie is rejected outside local and test`() {
        assertThrows<IllegalArgumentException> {
            GatewayAuthCookieFactory(
                GatewayAuthCookieProperties(
                    domain = ".platformholder.site",
                    secure = false,
                    sameSite = "None",
                ),
                MockEnvironment(),
            )
        }
    }

    @Test
    fun `unsupported same site value is rejected`() {
        assertThrows<IllegalArgumentException> {
            GatewayAuthCookieFactory(
                GatewayAuthCookieProperties(
                    domain = null,
                    secure = true,
                    sameSite = "Anything",
                ),
                MockEnvironment(),
            )
        }
    }
}
