package org.woo.gateway

import org.junit.jupiter.api.Test
import org.springframework.http.HttpCookie
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.mock.env.MockEnvironment
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import org.woo.gateway.config.CbtCorsProperties
import org.woo.gateway.config.CsrfOriginProperties
import org.woo.gateway.config.CsrfTokenProperties
import org.woo.gateway.config.GatewayAuthCookieProperties
import org.woo.gateway.filter.CbtCorsOriginFilter
import org.woo.gateway.filter.CsrfTokenCookieFilter
import org.woo.gateway.filter.OriginVerificationFilter
import org.woo.gateway.security.CbtWebOriginMatcher
import org.woo.gateway.security.CsrfTokenService
import org.woo.gateway.security.GatewayAuthCookieFactory
import org.woo.gateway.security.SecureCsrfTokenService
import reactor.core.publisher.Mono
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFails
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CbtWebSessionContractFixtureTest {
    private val decoder = ClosedCbtWebSessionContractDecoder()
    private val fixture by lazy {
        requireNotNull(javaClass.classLoader.getResource("contracts/cbt-web-session.json")).readText()
    }

    @Test
    fun `closed decoder rejects unknown missing wrongly typed and invalid enum fields`() {
        val mutations =
            listOf(
                fixture.replaceFirst("{\"version\":1", "{\"unexpected\":true,\"version\":1"),
                fixture.replaceFirst("\"version\":1,", ""),
                fixture.replaceFirst("\"version\":1", "\"version\":\"1\""),
                fixture.replaceFirst("\"web\":\"HTTP_ONLY_COOKIE\"", "\"web\":\"COOKIE\""),
                fixture.replaceFirst("\"webDirectReissue\":false", "\"webDirectReissue\":null"),
                fixture.replaceFirst("\"httpOnly\":false", "\"httpOnly\":null"),
                fixture.replaceFirst(
                    "\"publicCatalogRead\":{\"methods\":",
                    "\"publicCatalogRead\":{\"method\":null,\"methods\":",
                ),
                fixture.replaceFirst(
                    "\"publicCatalogRead\":{\"methods\":",
                    "\"publicCatalogRead\":{\"auth\":null,\"methods\":",
                ),
                fixture.replaceFirst(
                    "\"publicQuestionPreviewRead\":{\"method\":",
                    "\"publicQuestionPreviewRead\":{\"anonymousMobileRequired\":null,\"method\":",
                ),
                fixture.replaceFirst(
                    "\"authTransport\":{\"web\":\"HTTP_ONLY_COOKIE\",\"mobile\":\"BEARER\",\"rotationOwner\":\"GATEWAY\",\"webDirectReissue\":false}",
                    "\"authTransport\":null",
                ),
                fixture.replaceFirst(
                    "\"allowedWebOrigins\":[\"https://mirror-view.platformholder.site\",\"http://localhost:5173\",\"http://127.0.0.1:4173\"]",
                    "\"allowedWebOrigins\":null",
                ),
                fixture.replaceFirst(
                    "\"allowedWebOrigins\":[\"https://mirror-view.platformholder.site\"",
                    "\"allowedWebOrigins\":[null,\"https://mirror-view.platformholder.site\"",
                ),
                fixture.replaceFirst("{\"version\":1", "{\"version\":1,\"version\":1"),
            )

        mutations.forEach { mutation -> assertFails { decoder.decode(mutation) } }
    }

    @Test
    fun `fixture matches every independently declared security field and backend operation`() {
        val contract = decoder.decode(fixture)

        assertEquals(expectedSecurityContract(), contract.withoutOperations())
        assertEquals(expectedOperations(), contract.operationHeaders.entries())
    }

    @Test
    fun `fixture security values match Gateway properties and cookie factories`() {
        val contract = decoder.decode(fixture)
        val auth = contract.cookies.auth
        val csrf = contract.cookies.csrf
        val productionAuth = bindGatewayConfig("gateway.auth.cookie", GatewayAuthCookieProperties::class.java)
        val localAuth = bindGatewayConfig("gateway.auth.cookie", GatewayAuthCookieProperties::class.java, "application-local.yml")
        val authFactory = GatewayAuthCookieFactory(productionAuth, MockEnvironment())
        val issued = authFactory.issue(productionAuth.accessTokenName, "value-sentinel", 1_500)
        val cleared = authFactory.clear(productionAuth.accessTokenName)
        val localAuthFactory =
            GatewayAuthCookieFactory(
                localAuth,
                MockEnvironment().apply { setActiveProfiles("local") },
            )
        val localIssued = localAuthFactory.issue(localAuth.accessTokenName, "local-value-sentinel", 1_500)

        assertEquals(auth.names, listOf(authFactory.accessTokenName(), authFactory.refreshTokenName()))
        assertEquals(auth.path, issued.path)
        assertEquals(auth.httpOnly, issued.isHttpOnly)
        assertEquals(auth.production.domain, issued.domain)
        assertEquals(auth.production.secure, issued.isSecure)
        assertEquals(auth.production.sameSite.wire, issued.sameSite)
        assertEquals(Duration.ofMillis(1_500), issued.maxAge)
        assertEquals(Duration.ZERO, cleared.maxAge)
        assertEquals(auth.names, listOf(localAuthFactory.accessTokenName(), localAuthFactory.refreshTokenName()))
        assertEquals(auth.path, localAuth.path)
        assertEquals(auth.httpOnly, localAuth.httpOnly)
        assertEquals(auth.localTest.domain, normalizedDomain(localAuth.domain))
        assertEquals(auth.localTest.secure, localAuth.secure)
        assertEquals(auth.localTest.sameSite.wire, localAuth.sameSite)
        assertNull(localIssued.domain)
        assertFalse(localIssued.isSecure)
        assertEquals(auth.localTest.sameSite.wire, localIssued.sameSite)
        assertTrue(localIssued.isHttpOnly)

        val csrfProperties = bindGatewayConfig("gateway.security.csrf.token", CsrfTokenProperties::class.java)
        val localCsrf = bindGatewayConfig("gateway.security.csrf.token", CsrfTokenProperties::class.java, "application-local.yml")
        assertEquals(csrf.cookieName, csrfProperties.cookieName)
        assertEquals(csrf.headerName, csrfProperties.headerName)
        assertEquals(csrf.path, csrfProperties.path)
        assertEquals(csrf.httpOnly, csrfProperties.httpOnly)
        assertEquals(csrf.production.domain, csrfProperties.cookieDomain)
        assertEquals(csrf.production.secure, csrfProperties.secure)
        assertEquals(csrf.production.sameSite.wire, csrfProperties.sameSite)
        assertEquals(csrf.cookieName, localCsrf.cookieName)
        assertEquals(csrf.headerName, localCsrf.headerName)
        assertEquals(csrf.path, localCsrf.path)
        assertEquals(csrf.httpOnly, localCsrf.httpOnly)
        assertEquals(csrf.localTest.domain, normalizedDomain(localCsrf.cookieDomain))
        assertEquals(csrf.localTest.secure, localCsrf.secure)
        assertEquals(csrf.localTest.sameSite.wire, localCsrf.sameSite)

        val productionExchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/cbt/exams").build())
        CsrfTokenCookieFilter(csrfProperties, fixedTokenService())
            .filter(productionExchange, WebFilterChain { Mono.empty() }).block()
        val productionCookie = requireNotNull(productionExchange.response.cookies.getFirst(csrf.cookieName))
        assertEquals(csrf.production.domain, productionCookie.domain)
        assertEquals(csrf.production.secure, productionCookie.isSecure)
        assertEquals(csrf.production.sameSite.wire, productionCookie.sameSite)
        assertEquals(csrf.path, productionCookie.path)
        assertEquals(csrf.httpOnly, productionCookie.isHttpOnly)

        val localFilter =
            CsrfTokenCookieFilter(
                localCsrf,
                fixedTokenService(),
            )
        val localExchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/cbt/exams").build())
        localFilter.filter(localExchange, WebFilterChain { Mono.empty() }).block()
        val localCookie = requireNotNull(localExchange.response.cookies.getFirst(csrf.cookieName))
        assertNull(localCookie.domain)
        assertFalse(localCookie.isSecure)
        assertEquals(csrf.localTest.sameSite.wire, localCookie.sameSite)
        assertFalse(localCookie.isHttpOnly)
    }

    @Test
    fun `fixture origins and client columns match actual Gateway browser and native gates`() {
        val contract = decoder.decode(fixture)
        val corsProperties = bindGatewayConfig("gateway.security.cbt-cors", CbtCorsProperties::class.java)
        val localCorsProperties = bindGatewayConfig("gateway.security.cbt-cors", CbtCorsProperties::class.java, "application-local.yml")
        val tokenProperties = bindGatewayConfig("gateway.security.csrf.token", CsrfTokenProperties::class.java)
        val tokenService = SecureCsrfTokenService(tokenProperties)
        val filter =
            OriginVerificationFilter(
                bindGatewayConfig("gateway.security.csrf", CsrfOriginProperties::class.java),
                tokenProperties,
                tokenService,
                CbtWebOriginMatcher(corsProperties),
            )
        val corsFilter = CbtCorsOriginFilter(CbtWebOriginMatcher(corsProperties))

        assertEquals(contract.allowedWebOrigins.toSet(), corsProperties.allowedOrigins.map { it.toString() }.toSet())
        assertEquals(contract.allowedWebOrigins.toSet(), localCorsProperties.allowedOrigins.map { it.toString() }.toSet())

        val unsafeRoutes =
            contract.operationHeaders.entries().values
                .filter { operation -> operation.allMethods().any { it != ContractHttpMethod.GET } }
                .flatMap { operation -> operation.expandedRoutes().map { route -> operation to route } }
        unsafeRoutes.forEach { (operation, route) ->
            val (method, path) = route
            assertEquals(listOf(tokenProperties.headerName), operation.webRequired)
            val missingToken =
                MockServerWebExchange.from(
                    MockServerHttpRequest
                        .method(HttpMethod.valueOf(method.name), materialize(path))
                        .header(HttpHeaders.ORIGIN, contract.allowedWebOrigins.first())
                        .build(),
                )
            assertFalse(execute(filter, missingToken), "Web gate accepted missing CSRF token for $method $path")

            val token = tokenService.generate()
            val exchange =
                MockServerWebExchange.from(
                    MockServerHttpRequest
                        .method(HttpMethod.valueOf(method.name), materialize(path))
                        .header(HttpHeaders.ORIGIN, contract.allowedWebOrigins.first())
                        .header(tokenProperties.headerName, token)
                        .cookie(HttpCookie(tokenProperties.cookieName, token))
                        .build(),
                )
            assertTrue(execute(filter, exchange), "Web gate rejected $method $path")
        }

        contract.operationHeaders.entries().values
            .flatMap { operation -> operation.expandedRoutes().map { route -> operation to route } }
            .forEach { (operation, route) ->
                val (method, path) = route
                val builder =
                    MockServerHttpRequest
                        .options(materialize(path))
                        .header(HttpHeaders.ORIGIN, contract.allowedWebOrigins.first())
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, method.name)
                operation.webHeaderNames().takeIf { it.isNotEmpty() }?.let { headers ->
                    builder.header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, headers.joinToString(","))
                }
                assertTrue(
                    execute(corsFilter, MockServerWebExchange.from(builder.build())),
                    "CORS rejected fixture Web headers for $method $path",
                )
            }
        val nativeHeaderPreflight =
            MockServerWebExchange.from(
                MockServerHttpRequest
                    .options("/api/v1/cbt/attempts")
                    .header(HttpHeaders.ORIGIN, contract.allowedWebOrigins.first())
                    .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "X-CBT-Installation-Id")
                    .build(),
            )
        assertFalse(execute(corsFilter, nativeHeaderPreflight))

        val anonymousMobileRoutes =
            contract.operationHeaders.entries().values
                .filter { it.anonymousMobileRequired == listOf("X-CBT-Installation-Id") }
                .flatMap { it.expandedRoutes() }
        assertEquals(
            setOf(
                ContractHttpMethod.POST to "/api/v1/cbt/attempts",
                ContractHttpMethod.PUT to "/api/v1/cbt/attempts/{id}/answers/{attemptQuestionId}",
                ContractHttpMethod.POST to "/api/v1/cbt/attempts/{id}/answers/{attemptQuestionId}/check",
                ContractHttpMethod.POST to "/api/v1/cbt/attempts/{id}/submit",
            ),
            anonymousMobileRoutes.toSet(),
        )
        anonymousMobileRoutes.forEach { (method, path) ->
            val exchange =
                MockServerWebExchange.from(
                    MockServerHttpRequest
                        .method(HttpMethod.valueOf(method.name), materialize(path))
                        .header("X-CBT-Installation-Id", "installation-id-1234567890")
                        .build(),
                )
            assertTrue(execute(filter, exchange), "native gate rejected $method $path")
        }
    }

    private fun expectedSecurityContract() =
        SecurityContractProjection(
            version = 1,
            authTransport = AuthTransportContract(WebAuthTransport.HTTP_ONLY_COOKIE, MobileAuthTransport.BEARER, RotationOwner.GATEWAY, false),
            allowedWebOrigins = listOf("https://mirror-view.platformholder.site", "http://localhost:5173", "http://127.0.0.1:4173"),
            cookies =
                CookiesContract(
                    auth =
                        AuthCookiesContract(
                            names = listOf("accessToken", "refreshToken"),
                            path = "/",
                            httpOnly = true,
                            production = CookieProfileContract(".platformholder.site", true, SameSiteContract.NONE),
                            localTest = CookieProfileContract(null, false, SameSiteContract.LAX),
                            maxAge = MaxAgeContract(IssueMaxAge.JWT_EXPIRES_IN_MILLIS, ClearMaxAge.ZERO),
                        ),
                    csrf =
                        CsrfCookieContract(
                            cookieName = "XSRF-TOKEN",
                            headerName = "X-XSRF-TOKEN",
                            path = "/",
                            httpOnly = false,
                            production = CookieProfileContract(".platformholder.site", true, SameSiteContract.NONE),
                            localTest = CookieProfileContract(null, false, SameSiteContract.LAX),
                        ),
                ),
        )

    private fun expectedOperations() =
        linkedMapOf(
            "publicCatalogRead" to op(methods = listOf(ContractHttpMethod.GET), paths = listOf("/api/v1/cbt/exams", "/api/v1/cbt/exams/{examSlug}", "/api/v1/cbt/exams/{examSlug}/papers", "/api/v1/cbt/papers/{paperId}"), required = emptyList(), optional = emptyList(), mobile = emptyList()),
            "publicQuestionPreviewRead" to op(method = ContractHttpMethod.GET, path = "/api/v1/cbt/questions", auth = ContractAuth.NONE, client = ContractClient.WEB_ONLY, required = emptyList(), optional = emptyList()),
            "publicAssetRead" to op(method = ContractHttpMethod.GET, path = "/api/v1/cbt/assets/{assetId}", auth = ContractAuth.NONE, required = emptyList(), optional = emptyList(), mobile = emptyList()),
            "attemptCreate" to op(method = ContractHttpMethod.POST, path = "/api/v1/cbt/attempts", auth = ContractAuth.OPTIONAL, required = listOf("Idempotency-Key"), optional = emptyList(), web = listOf("X-XSRF-TOKEN"), mobile = listOf("X-CBT-Installation-Id")),
            "guestAttemptRead" to op(methods = listOf(ContractHttpMethod.GET), paths = listOf("/api/v1/cbt/attempts/{id}", "/api/v1/cbt/attempts/{id}/result"), auth = ContractAuth.OPTIONAL, guest = listOf("X-CBT-Attempt-Token"), mobile = emptyList()),
            "guestAttemptSaveCheckSubmit" to op(methods = listOf(ContractHttpMethod.PUT, ContractHttpMethod.POST), paths = listOf("/api/v1/cbt/attempts/{id}/answers/{attemptQuestionId}", "/api/v1/cbt/attempts/{id}/answers/{attemptQuestionId}/check", "/api/v1/cbt/attempts/{id}/submit"), auth = ContractAuth.OPTIONAL, guest = listOf("X-CBT-Attempt-Token"), web = listOf("X-XSRF-TOKEN"), mobile = listOf("X-CBT-Installation-Id")),
            "attemptClaim" to op(method = ContractHttpMethod.POST, path = "/api/v1/cbt/attempts/{id}/claim", auth = ContractAuth.REQUIRED, required = listOf("Idempotency-Key"), optional = listOf("X-CBT-Attempt-Token"), web = listOf("X-XSRF-TOKEN"), mobile = emptyList()),
            "userRead" to op(methods = listOf(ContractHttpMethod.GET), paths = listOf("/api/v1/cbt/me/attempts", "/api/v1/cbt/me/wrong-answers"), auth = ContractAuth.REQUIRED, required = emptyList(), optional = emptyList(), mobile = emptyList()),
            "wrongAnswerResolve" to op(method = ContractHttpMethod.POST, path = "/api/v1/cbt/me/wrong-answers/{questionId}/resolve", auth = ContractAuth.REQUIRED, required = emptyList(), optional = emptyList(), web = listOf("X-XSRF-TOKEN"), mobile = emptyList()),
            "wrongAnswerRetry" to op(method = ContractHttpMethod.POST, path = "/api/v1/cbt/me/wrong-answers/retry-attempt", auth = ContractAuth.REQUIRED, required = listOf("Idempotency-Key"), optional = emptyList(), web = listOf("X-XSRF-TOKEN"), mobile = emptyList()),
            "publicPrintableCreate" to op(method = ContractHttpMethod.POST, path = "/api/v1/cbt/printable-sets", auth = ContractAuth.OPTIONAL, client = ContractClient.WEB_ONLY, required = listOf("Idempotency-Key"), optional = emptyList(), web = listOf("X-XSRF-TOKEN")),
            "wrongPrintableCreate" to op(method = ContractHttpMethod.POST, path = "/api/v1/cbt/me/wrong-answers/printable-set", auth = ContractAuth.REQUIRED, client = ContractClient.WEB_ONLY, required = listOf("Idempotency-Key"), optional = emptyList(), web = listOf("X-XSRF-TOKEN")),
            "guestPrintableRead" to op(method = ContractHttpMethod.GET, paths = listOf("/api/v1/cbt/printable-sets/{id}", "/api/v1/cbt/printable-sets/{id}/preview"), auth = ContractAuth.OPTIONAL, client = ContractClient.WEB_ONLY, guest = listOf("X-CBT-Printable-Token")),
        )

    private fun op(
        method: ContractHttpMethod? = null,
        methods: List<ContractHttpMethod>? = null,
        path: String? = null,
        paths: List<String>? = null,
        auth: ContractAuth? = null,
        client: ContractClient? = null,
        required: List<String>? = null,
        optional: List<String>? = null,
        guest: List<String>? = null,
        web: List<String> = emptyList(),
        mobile: List<String>? = null,
    ) = OperationContract(method, methods, path, paths, auth, client, required, optional, guest, web, mobile)

    private fun execute(
        filter: WebFilter,
        exchange: MockServerWebExchange,
    ): Boolean {
        val passed = AtomicBoolean(false)
        filter.filter(exchange, WebFilterChain { passed.set(true); Mono.empty() }).block()
        return passed.get()
    }

    private fun fixedTokenService() =
        object : CsrfTokenService {
            override fun generate() = "generated-csrf-token"
            override fun matches(cookieValue: String, headerValue: String) = cookieValue == headerValue
        }

    private fun materialize(path: String) =
        path.replace("{examSlug}", "exam").replace("{paperId}", "1").replace("{assetId}", "1")
            .replace("{id}", "1").replace("{attemptQuestionId}", "2").replace("{questionId}", "3")

    private fun normalizedDomain(domain: String?): String? = domain?.trim()?.takeIf { it.isNotEmpty() }

    private fun OperationContract.webHeaderNames(): List<String> =
        (required.orEmpty() + optional.orEmpty() + requiredWhenGuest.orEmpty() + webRequired).distinct()
}
