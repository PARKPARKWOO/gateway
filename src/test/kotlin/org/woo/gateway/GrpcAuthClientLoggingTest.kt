package org.woo.gateway

import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.classic.spi.IThrowableProxy
import ch.qos.logback.core.read.ListAppender
import io.grpc.ManagedChannel
import io.grpc.Status
import io.grpc.StatusRuntimeException
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import org.mockito.kotlin.any
import org.mockito.kotlin.whenever
import org.slf4j.LoggerFactory
import org.woo.auth.grpc.UserInfoServiceGrpcKt
import org.woo.gateway.client.GrpcAuthClient
import org.woo.gateway.factory.NettyChannelFactory
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GrpcAuthClientLoggingTest {
    @Test
    fun `status failure log exposes only bounded class and status metadata`() =
        runTest {
            val secret = "grpc-status-description-secret-sentinel"
            val failure = Status.INTERNAL.withDescription(secret).asRuntimeException()
            val channelFactory = mock(NettyChannelFactory::class.java)
            val channel = mock(ManagedChannel::class.java)
            `when`(channelFactory.getChannel("auth-service")).thenReturn(channel)
            val client = GrpcAuthClient("auth-service", channelFactory)
            val stub = mock(UserInfoServiceGrpcKt.UserInfoServiceCoroutineStub::class.java)
            whenever(stub.withInterceptors(any())).thenReturn(stub)
            whenever(stub.getPassportByBearer(any(), any())).thenThrow(failure)
            client.javaClass.getDeclaredField("userInfoService").apply {
                isAccessible = true
                set(client, stub)
            }

            val rendered = captureLogs {
                assertFailsWith<StatusRuntimeException> {
                    client.getUserInfo("access-token-input-sentinel")
                }
            }

            assertTrue(rendered.contains("StatusRuntimeException"))
            assertTrue(rendered.contains("INTERNAL"))
            assertFalse(rendered.contains(secret))
            assertFalse(rendered.contains("access-token-input-sentinel"))
        }

    private suspend fun captureLogs(action: suspend () -> Unit): String {
        val classLogger = LoggerFactory.getLogger(GrpcAuthClient::class.java) as Logger
        val actualLogger = LoggerFactory.getLogger(GrpcAuthClient::class.java.simpleName) as Logger
        val appender = ListAppender<ILoggingEvent>().also { it.start() }
        classLogger.addAppender(appender)
        actualLogger.addAppender(appender)
        return try {
            action()
            assertTrue(appender.list.isNotEmpty(), "expected the GrpcAuthClient logger to be exercised")
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
}
