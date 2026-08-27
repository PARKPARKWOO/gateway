package org.woo.gateway

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.http.HttpCookie
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.web.server.WebFilterChain
import org.woo.gateway.config.CsrfOriginProperties
import org.woo.gateway.config.CsrfTokenProperties
import org.woo.gateway.filter.OriginVerificationFilter
import org.woo.gateway.security.SecureCsrfTokenService
import reactor.core.publisher.Mono
import java.util.concurrent.atomic.AtomicBoolean

class OriginVerificationFilterTest {
    private val props =
        CsrfOriginProperties(
            allowedHostSuffixes = listOf(".platformholder.site"),
            allowedExactHosts = listOf("forest-front-psi.vercel.app"),
            allowedLocalhostHosts = listOf("localhost", "127.0.0.1"),
        )
    private val tokenProperties = CsrfTokenProperties()
    private val filter =
        OriginVerificationFilter(
            props,
            tokenProperties,
            SecureCsrfTokenService(tokenProperties),
        )

    private fun build(
        method: HttpMethod,
        path: String = NON_CBT_PATH,
        origin: String? = null,
        referer: String? = null,
        authorization: String? = null,
        installationId: String? = null,
        csrfCookie: String? = null,
        csrfHeader: String? = null,
        authCookieName: String? = null,
    ): MockServerWebExchange {
        val builder = MockServerHttpRequest.method(method, path)
        origin?.let { builder.header("Origin", it) }
        referer?.let { builder.header("Referer", it) }
        authorization?.let { builder.header("Authorization", it) }
        installationId?.let { builder.header("X-CBT-Installation-Id", it) }
        csrfHeader?.let { builder.header("X-XSRF-TOKEN", it) }
        csrfCookie?.let { builder.cookie(HttpCookie("XSRF-TOKEN", it)) }
        authCookieName?.let { builder.cookie(HttpCookie(it, "auth-cookie-sentinel")) }
        return MockServerWebExchange.from(builder.build())
    }

    private fun execute(exchange: MockServerWebExchange): Boolean {
        val passed = AtomicBoolean(false)
        val chain =
            WebFilterChain {
                passed.set(true)
                Mono.empty()
            }
        filter.filter(exchange, chain).block()
        return passed.get()
    }

    @Test
    fun `allowed web origin with matching cookie and header passes every unsafe CBT method`() {
        UNSAFE_METHODS.forEach { method ->
            val exchange =
                build(
                    method = method,
                    path = CBT_PATH,
                    origin = ALLOWED_ORIGIN,
                    csrfCookie = VALID_CSRF_TOKEN,
                    csrfHeader = VALID_CSRF_TOKEN,
                )

            assertThat(execute(exchange)).describedAs("$method must pass").isTrue()
            assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
        }
    }

    @Test
    fun `allowed web origin with a missing or mismatched token is forbidden for every unsafe CBT method`() {
        UNSAFE_METHODS.forEach { method ->
            listOf(
                null to null,
                VALID_CSRF_TOKEN to null,
                null to VALID_CSRF_TOKEN,
                VALID_CSRF_TOKEN to "different-csrf-token",
            ).forEach { (cookie, header) ->
                val exchange =
                    build(
                        method = method,
                        path = CBT_PATH,
                        origin = ALLOWED_ORIGIN,
                        csrfCookie = cookie,
                        csrfHeader = header,
                    )

                assertThat(execute(exchange))
                    .describedAs("$method with cookie=$cookie and header=$header must be blocked")
                    .isFalse()
                assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
            }
        }
    }

    @Test
    fun `disallowed origin is forbidden even with matching token for every unsafe CBT method`() {
        UNSAFE_METHODS.forEach { method ->
            val exchange =
                build(
                    method = method,
                    path = CBT_PATH,
                    origin = "https://attacker.example.com",
                    csrfCookie = VALID_CSRF_TOKEN,
                    csrfHeader = VALID_CSRF_TOKEN,
                )

            assertThat(execute(exchange)).isFalse()
            assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
        }
    }

    @Test
    fun `exact auth cookies without origin or referer are forbidden for every unsafe CBT method`() {
        UNSAFE_METHODS.forEach { method ->
            listOf("accessToken", "refreshToken").forEach { cookieName ->
                val exchange =
                    build(
                        method = method,
                        path = CBT_PATH,
                        installationId = VALID_INSTALLATION_ID,
                        authCookieName = cookieName,
                    )

                assertThat(execute(exchange)).describedAs("$method with $cookieName must be blocked").isFalse()
                assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
            }
        }
    }

    @Test
    fun `bearer request bypasses origin and token checks for every unsafe CBT method`() {
        UNSAFE_METHODS.forEach { method ->
            val exchange = build(method = method, path = CBT_PATH, authorization = "Bearer native-token")

            assertThat(execute(exchange)).describedAs("$method bearer request must pass").isTrue()
            assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
        }
    }

    @Test
    fun `browserless CBT guest with a valid installation id passes every unsafe method`() {
        UNSAFE_METHODS.forEach { method ->
            val exchange = build(method = method, path = CBT_PATH, installationId = VALID_INSTALLATION_ID)

            assertThat(execute(exchange)).describedAs("$method native guest request must pass").isTrue()
            assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
        }
    }

    @Test
    fun `browserless CBT guest ignores unrelated cookies when installation id is valid`() {
        UNSAFE_METHODS.forEach { method ->
            val exchange =
                build(
                    method = method,
                    path = CBT_PATH,
                    installationId = VALID_INSTALLATION_ID,
                    authCookieName = "unrelatedCookie",
                )

            assertThat(execute(exchange)).isTrue()
            assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
        }
    }

    @Test
    fun `browserless CBT guest without a syntactically valid installation id is forbidden for every unsafe method`() {
        UNSAFE_METHODS.forEach { method ->
            listOf(
                null,
                "too-short",
                "invalid.installation.id.12345",
                "a".repeat(129),
            ).forEach { installationId ->
                val exchange = build(method = method, path = CBT_PATH, installationId = installationId)

                assertThat(execute(exchange))
                    .describedAs("$method with installation id presence=${installationId != null} must be blocked")
                    .isFalse()
                assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
            }
        }
    }

    @Test
    fun `non CBT unsafe request with an allowed origin keeps origin only compatibility`() {
        UNSAFE_METHODS.forEach { method ->
            val exchange = build(method = method, origin = ALLOWED_ORIGIN)

            assertThat(execute(exchange)).describedAs("$method non-CBT request must pass").isTrue()
            assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
        }
    }

    @Test
    fun `non CBT unsafe request without origin and auth cookie is forbidden`() {
        UNSAFE_METHODS.forEach { method ->
            val exchange = build(method = method)

            assertThat(execute(exchange)).isFalse()
            assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
        }
    }

    @Test
    fun `safe method passes regardless of origin`() {
        val exchange = build(method = HttpMethod.GET, origin = "https://evil.example.com")

        assertThat(execute(exchange)).isTrue()
        assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `oauth callback path bypasses origin check`() {
        val exchange = build(method = HttpMethod.POST, path = "/login/oauth2/code/google")

        assertThat(execute(exchange)).isTrue()
        assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `non bearer authorization does not bypass origin check`() {
        val exchange = build(method = HttpMethod.POST, path = CBT_PATH, authorization = "Basic credentials")

        assertThat(execute(exchange)).isFalse()
        assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `forest vercel host is allowed via exact match for non CBT request`() {
        val exchange = build(method = HttpMethod.POST, origin = "https://forest-front-psi.vercel.app")

        assertThat(execute(exchange)).isTrue()
    }

    @Test
    fun `unrelated vercel host is rejected`() {
        val exchange = build(method = HttpMethod.POST, origin = "https://attacker.vercel.app")

        assertThat(execute(exchange)).isFalse()
        assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `referer is used when origin missing for non CBT request`() {
        val exchange =
            build(
                method = HttpMethod.POST,
                referer = "https://forest-front-psi.vercel.app/programs/create",
            )

        assertThat(execute(exchange)).isTrue()
    }

    private companion object {
        val UNSAFE_METHODS = listOf(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE)
        const val CBT_PATH = "/api/v1/cbt/attempts"
        const val NON_CBT_PATH = "/api/v1/program/information"
        const val ALLOWED_ORIGIN = "https://mirror-view.platformholder.site"
        const val VALID_CSRF_TOKEN = "csrf-token-sentinel"
        const val VALID_INSTALLATION_ID = "installation_12345678901234567890"
    }
}
