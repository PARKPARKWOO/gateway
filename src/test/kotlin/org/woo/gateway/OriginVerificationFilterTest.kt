package org.woo.gateway

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.http.HttpCookie
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.web.server.WebFilterChain
import org.woo.gateway.config.CbtCorsProperties
import org.woo.gateway.config.CsrfOriginProperties
import org.woo.gateway.config.CsrfTokenProperties
import org.woo.gateway.filter.OriginVerificationFilter
import org.woo.gateway.security.CbtWebOriginMatcher
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
            CbtWebOriginMatcher(CbtCorsProperties()),
        )

    private fun build(
        method: HttpMethod,
        path: String = NON_CBT_PATH,
        origin: String? = null,
        referer: String? = null,
        authorization: String? = null,
        authorizations: List<String>? = null,
        installationId: String? = null,
        csrfCookie: String? = null,
        csrfHeader: String? = null,
        csrfCookies: List<String>? = null,
        csrfHeaders: List<String>? = null,
        authCookieName: String? = null,
    ): MockServerWebExchange {
        val builder = MockServerHttpRequest.method(method, path)
        origin?.let { builder.header("Origin", it) }
        referer?.let { builder.header("Referer", it) }
        when {
            authorizations != null -> builder.header("Authorization", *authorizations.toTypedArray())
            authorization != null -> builder.header("Authorization", authorization)
        }
        installationId?.let { builder.header("X-CBT-Installation-Id", it) }
        when {
            csrfHeaders != null -> builder.header("X-XSRF-TOKEN", *csrfHeaders.toTypedArray())
            csrfHeader != null -> builder.header("X-XSRF-TOKEN", csrfHeader)
        }
        (csrfCookies ?: csrfCookie?.let(::listOf).orEmpty()).forEach {
            builder.cookie(HttpCookie("XSRF-TOKEN", it))
        }
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

    @ParameterizedTest
    @ValueSource(
        strings = [
            "https://mirror-view.platformholder.site",
            "http://localhost:5173",
            "http://127.0.0.1:4173",
        ],
    )
    fun `each exact CBT web origin passes an unsafe credentialed request`(origin: String) {
        val exchange =
            build(
                method = HttpMethod.POST,
                path = CBT_PATH,
                origin = origin,
                csrfCookie = VALID_CSRF_TOKEN,
                csrfHeader = VALID_CSRF_TOKEN,
            )

        assertThat(execute(exchange)).isTrue()
        assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "https://web.mirror-view.platformholder.site",
            "https://mirror-view.platformholder.site.attacker.example",
            "http://mirror-view.platformholder.site",
            "https://mirror-view.platformholder.site:8443",
            "https://mirror-view.platformholder.site:",
            "https://localhost:5173",
            "http://localhost:4173",
            "https://127.0.0.1:4173",
            "http://127.0.0.1:5173",
            "https://mirror-view-pr-123.vercel.app",
            "https://user@mirror-view.platformholder.site",
            "null",
            "mirror-view.platformholder.site",
            "https://mirror-view.platformholder.site/cbt/exam",
            "https://mirror-view.platformholder.site?next=attacker",
            "https://mirror-view.platformholder.site#fragment",
        ],
    )
    fun `CBT unsafe request rejects every non-exact Origin even with matching CSRF`(origin: String) {
        val exchange =
            build(
                method = HttpMethod.POST,
                path = CBT_PATH,
                origin = origin,
                csrfCookie = VALID_CSRF_TOKEN,
                csrfHeader = VALID_CSRF_TOKEN,
            )

        assertThat(execute(exchange)).isFalse()
        assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "https://mirror-view.platformholder.site/cbt/exam",
            "http://localhost:5173/cbt/exam",
            "http://127.0.0.1:4173/cbt/exam",
        ],
    )
    fun `each exact CBT web Referer passes an unsafe credentialed request when Origin is absent`(referer: String) {
        val exchange =
            build(
                method = HttpMethod.POST,
                path = CBT_PATH,
                referer = referer,
                csrfCookie = VALID_CSRF_TOKEN,
                csrfHeader = VALID_CSRF_TOKEN,
            )

        assertThat(execute(exchange)).isTrue()
        assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "https://web.mirror-view.platformholder.site/cbt/exam",
            "https://mirror-view.platformholder.site.attacker.example/cbt/exam",
            "http://mirror-view.platformholder.site/cbt/exam",
            "https://mirror-view.platformholder.site:8443/cbt/exam",
            "https://mirror-view.platformholder.site:/cbt/exam",
            "https://user@mirror-view.platformholder.site/cbt/exam",
            "null",
            "mirror-view.platformholder.site/cbt/exam",
        ],
    )
    fun `CBT unsafe request rejects every non-exact or malformed Referer even with matching CSRF`(referer: String) {
        val exchange =
            build(
                method = HttpMethod.POST,
                path = CBT_PATH,
                referer = referer,
                csrfCookie = VALID_CSRF_TOKEN,
                csrfHeader = VALID_CSRF_TOKEN,
            )

        assertThat(execute(exchange)).isFalse()
        assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
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
    fun `unsafe CBT request requires exactly one CSRF cookie and one header`() {
        val duplicateCookies =
            build(
                method = HttpMethod.POST,
                path = CBT_PATH,
                origin = ALLOWED_ORIGIN,
                csrfCookies = listOf(VALID_CSRF_TOKEN, VALID_CSRF_TOKEN),
                csrfHeader = VALID_CSRF_TOKEN,
            )
        val duplicateHeaders =
            build(
                method = HttpMethod.POST,
                path = CBT_PATH,
                origin = ALLOWED_ORIGIN,
                csrfCookie = VALID_CSRF_TOKEN,
                csrfHeaders = listOf(VALID_CSRF_TOKEN, VALID_CSRF_TOKEN),
            )

        assertThat(execute(duplicateCookies)).isFalse()
        assertThat(duplicateCookies.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
        assertThat(execute(duplicateHeaders)).isFalse()
        assertThat(duplicateHeaders.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `unsafe CBT request rejects malformed CSRF cookie and header values`() {
        listOf(
            "",
            " ",
            " $VALID_CSRF_TOKEN",
            "$VALID_CSRF_TOKEN ",
            "$VALID_CSRF_TOKEN=",
            "+${VALID_CSRF_TOKEN.drop(1)}",
            "/${VALID_CSRF_TOKEN.drop(1)}",
            "A".repeat(42),
            "A".repeat(44),
            "A".repeat(42) + "B",
            "csrf-token-sentinel",
        ).forEach { invalid ->
            val invalidCookie =
                build(
                    method = HttpMethod.POST,
                    path = CBT_PATH,
                    origin = ALLOWED_ORIGIN,
                    csrfCookie = invalid,
                    csrfHeader = VALID_CSRF_TOKEN,
                )
            val invalidHeader =
                build(
                    method = HttpMethod.POST,
                    path = CBT_PATH,
                    origin = ALLOWED_ORIGIN,
                    csrfCookie = VALID_CSRF_TOKEN,
                    csrfHeader = invalid,
                )

            assertThat(execute(invalidCookie)).describedAs("invalid cookie=$invalid").isFalse()
            assertThat(invalidCookie.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
            assertThat(execute(invalidHeader)).describedAs("invalid header=$invalid").isFalse()
            assertThat(invalidHeader.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
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
    fun `bearer bypass requires exactly one canonical Authorization value`() {
        val singleBearer =
            build(
                method = HttpMethod.POST,
                path = "/api/v1/cbt/attempts",
                authorizations = listOf("Bearer native-token"),
            )

        assertThat(execute(singleBearer)).isTrue()
        assertThat(singleBearer.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)

        listOf(
            listOf("Bearer native-token", "Bearer second-token"),
            listOf("Bearer native-token", ""),
            listOf("Bearer native-token", "Basic credentials"),
        ).forEach { authorizations ->
            val exchange =
                build(
                    method = HttpMethod.POST,
                    path = "/api/v1/cbt/attempts",
                    authorizations = authorizations,
                )

            assertThat(execute(exchange)).describedAs("multiple Authorization values must fail").isFalse()
            assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
        }
    }

    @Test
    fun `browserless installation id passes only the exact anonymous CBT mutation routes`() {
        listOf(
            HttpMethod.POST to "/api/v1/cbt/attempts",
            HttpMethod.PUT to "/api/v1/cbt/attempts/1/answers/2",
            HttpMethod.POST to "/api/v1/cbt/attempts/1/answers/2/check",
            HttpMethod.POST to "/api/v1/cbt/attempts/1/submit",
        ).forEach { (method, path) ->
            val exchange = build(method = method, path = path, installationId = VALID_INSTALLATION_ID)

            assertThat(execute(exchange)).describedAs("$method $path native guest request must pass").isTrue()
            assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
        }
    }

    @Test
    fun `browserless installation id requires Authorization to be completely absent on every exact route`() {
        val exactRoutes =
            listOf(
                HttpMethod.POST to "/api/v1/cbt/attempts",
                HttpMethod.PUT to "/api/v1/cbt/attempts/1/answers/2",
                HttpMethod.POST to "/api/v1/cbt/attempts/1/answers/2/check",
                HttpMethod.POST to "/api/v1/cbt/attempts/1/submit",
            )
        val presentAuthorizationValues =
            listOf(
                listOf(""),
                listOf("   "),
                listOf("", ""),
                listOf("", "Bearer native-token"),
                listOf("", "Basic credentials"),
                listOf("Bearer native-token", ""),
            )

        exactRoutes.forEach { (method, path) ->
            presentAuthorizationValues.forEach { authorizations ->
                val exchange =
                    build(
                        method = method,
                        path = path,
                        authorizations = authorizations,
                        installationId = VALID_INSTALLATION_ID,
                    )

                assertThat(execute(exchange))
                    .describedAs("$method $path with present Authorization must fail")
                    .isFalse()
                assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
            }
        }
    }

    @Test
    fun `browserless installation id rejects non-contract methods and paths`() {
        listOf(
            HttpMethod.PATCH to "/api/v1/cbt/attempts/1/answers/2",
            HttpMethod.DELETE to "/api/v1/cbt/attempts/1/answers/2",
            HttpMethod.POST to "/api/v1/cbt/attempts/1/claim",
            HttpMethod.POST to "/api/v1/cbt/me/wrong-answers/2/resolve",
            HttpMethod.POST to "/api/v1/cbt/me/wrong-answers/retry-attempt",
            HttpMethod.POST to "/api/v1/cbt/printable-sets",
            HttpMethod.POST to "/api/v1/admin/cbt/exams",
            HttpMethod.POST to "/api/v1/cbt",
            HttpMethod.POST to "/api/v1/cbt/attempts/0/submit",
            HttpMethod.POST to "/api/v1/cbt/attempts/-1/submit",
            HttpMethod.POST to "/api/v1/cbt/attempts/not-a-number/submit",
            HttpMethod.POST to "/api/v1/cbt/attempts/${"9".repeat(40)}/submit",
            HttpMethod.PUT to "/api/v1/cbt/attempts/1/answers/0",
            HttpMethod.PUT to "/api/v1/cbt/attempts/1/answers/not-a-number",
            HttpMethod.POST to "/api/v1/cbt/attempts/1/answers/2",
            HttpMethod.PUT to "/api/v1/cbt/attempts/1/answers/2/check",
            HttpMethod.POST to "/api/v1/cbt/attempts/1/submit/extra",
            HttpMethod.POST to "/api/v1/cbt/attempts/1/future",
            HttpMethod.POST to "/api/v1/cbt/future",
        ).forEach { (method, path) ->
            val exchange = build(method = method, path = path, installationId = VALID_INSTALLATION_ID)

            assertThat(execute(exchange)).describedAs("$method $path must not use the guest bypass").isFalse()
            assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
        }
    }

    @Test
    fun `browserless installation id rejects mixed bearer or auth cookie classification`() {
        val bearer =
            build(
                method = HttpMethod.POST,
                path = "/api/v1/cbt/attempts",
                installationId = VALID_INSTALLATION_ID,
                authorization = "Bearer native-token",
            )
        val authCookie =
            build(
                method = HttpMethod.POST,
                path = "/api/v1/cbt/attempts",
                installationId = VALID_INSTALLATION_ID,
                authCookieName = "accessToken",
            )

        assertThat(execute(bearer)).isFalse()
        assertThat(bearer.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
        assertThat(execute(authCookie)).isFalse()
        assertThat(authCookie.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `browserless CBT guest ignores unrelated cookies on an exact mutation route`() {
        val exchange =
            build(
                method = HttpMethod.PUT,
                path = "/api/v1/cbt/attempts/1/answers/2",
                installationId = VALID_INSTALLATION_ID,
                authCookieName = "unrelatedCookie",
            )

        assertThat(execute(exchange)).isTrue()
        assertThat(exchange.response.statusCode).isNotEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun `exact guest mutation route rejects a missing or malformed installation id`() {
        listOf(
            null,
            "too-short",
            "invalid.installation.id.12345",
            "a".repeat(129),
        ).forEach { installationId ->
            val exchange =
                build(
                    method = HttpMethod.POST,
                    path = "/api/v1/cbt/attempts",
                    installationId = installationId,
                )

            assertThat(execute(exchange))
                .describedAs("installation id presence=${installationId != null} must be blocked")
                .isFalse()
            assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
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
        const val VALID_CSRF_TOKEN = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        const val VALID_INSTALLATION_ID = "installation_12345678901234567890"
    }
}
