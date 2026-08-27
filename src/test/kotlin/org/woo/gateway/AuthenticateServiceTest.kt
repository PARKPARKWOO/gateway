package org.woo.gateway

import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.classic.spi.IThrowableProxy
import ch.qos.logback.core.read.ListAppender
import exception.ErrorCode
import exception.ExpiredJwtException
import io.grpc.Status
import io.grpc.StatusException
import io.grpc.StatusRuntimeException
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import org.mockito.kotlin.whenever
import org.slf4j.LoggerFactory
import org.woo.gateway.client.GrpcAuthClient
import org.woo.gateway.service.AuthenticateService
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AuthenticateServiceTest {
    private val authClient = mock(GrpcAuthClient::class.java)
    private val service = AuthenticateService(authClient)

    @Test
    fun `checked exact unauthenticated expired marker becomes expired jwt`() =
        runTest {
            val failure = expiredStatus().asException()
            whenever(authClient.getUserInfo(INPUT_ACCESS_TOKEN)).thenAnswer { throw failure }

            assertFailsWith<ExpiredJwtException> {
                service.getPassport(INPUT_ACCESS_TOKEN)
            }
        }

    @Test
    fun `runtime exact unauthenticated expired marker becomes expired jwt`() =
        runTest {
            val failure = expiredStatus().asRuntimeException()
            whenever(authClient.getUserInfo(INPUT_ACCESS_TOKEN)).thenThrow(failure)

            assertFailsWith<ExpiredJwtException> {
                service.getPassport(INPUT_ACCESS_TOKEN)
            }
        }

    @Test
    fun `checked internal failure returns null without secret diagnostics`() =
        runTest {
            val failure = Status.INTERNAL.withDescription(CHECKED_SECRET).asException()
            whenever(authClient.getUserInfo(INPUT_ACCESS_TOKEN)).thenAnswer { throw failure }

            val rendered = captureLogs {
                assertNull(service.getPassport(INPUT_ACCESS_TOKEN))
            }

            assertBoundedDiagnostic(rendered, StatusException::class.java.simpleName, CHECKED_SECRET)
        }

    @Test
    fun `runtime internal failure returns null without secret diagnostics`() =
        runTest {
            val failure = Status.INTERNAL.withDescription(RUNTIME_SECRET).asRuntimeException()
            whenever(authClient.getUserInfo(INPUT_ACCESS_TOKEN)).thenThrow(failure)

            val rendered = captureLogs {
                assertNull(service.getPassport(INPUT_ACCESS_TOKEN))
            }

            assertBoundedDiagnostic(rendered, StatusRuntimeException::class.java.simpleName, RUNTIME_SECRET)
        }

    private fun expiredStatus(): Status =
        Status.UNAUTHENTICATED.withDescription(ErrorCode.EXPIRED_JWT.name)

    private fun assertBoundedDiagnostic(
        rendered: String,
        exceptionClass: String,
        secret: String,
    ) {
        assertTrue(rendered.contains(exceptionClass))
        assertTrue(rendered.contains(Status.Code.INTERNAL.name))
        assertFalse(rendered.contains(secret))
        assertFalse(rendered.contains(INPUT_ACCESS_TOKEN))
    }

    private suspend fun captureLogs(action: suspend () -> Unit): String {
        val classLogger = LoggerFactory.getLogger(AuthenticateService::class.java) as Logger
        val actualLogger = LoggerFactory.getLogger(AuthenticateService::class.java.simpleName) as Logger
        val appender = ListAppender<ILoggingEvent>().also { it.start() }
        classLogger.addAppender(appender)
        actualLogger.addAppender(appender)
        return try {
            action()
            assertTrue(appender.list.isNotEmpty(), "expected the AuthenticateService logger to be exercised")
            appender.list.joinToString("\n", transform = ::render)
        } finally {
            classLogger.detachAppender(appender)
            actualLogger.detachAppender(appender)
            appender.stop()
        }
    }

    private fun render(event: ILoggingEvent): String =
        buildString {
            append(event.formattedMessage)
            event.throwableProxy?.let {
                append('\n')
                append(render(it))
            }
        }

    private fun render(throwable: IThrowableProxy): String =
        buildString {
            append(throwable.className)
            append(':')
            append(throwable.message)
            throwable.stackTraceElementProxyArray?.forEach {
                append('\n')
                append(it.steAsString)
            }
            throwable.cause?.let {
                append('\n')
                append(render(it))
            }
            throwable.suppressed?.forEach {
                append('\n')
                append(render(it))
            }
        }

    private companion object {
        const val INPUT_ACCESS_TOKEN = "authenticate-service-access-token-sentinel"
        const val CHECKED_SECRET = "checked-status-description-secret-sentinel"
        const val RUNTIME_SECRET = "runtime-status-description-secret-sentinel"
    }
}
