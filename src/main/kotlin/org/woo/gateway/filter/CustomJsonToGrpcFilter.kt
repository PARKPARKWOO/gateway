package org.woo.gateway.filter

import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.ObjectReader
import com.fasterxml.jackson.databind.ObjectWriter
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.dataformat.protobuf.ProtobufFactory
import com.fasterxml.jackson.dataformat.protobuf.schema.ProtobufSchema
import com.fasterxml.jackson.dataformat.protobuf.schema.ProtobufSchemaLoader
import com.google.protobuf.DescriptorProtos
import com.google.protobuf.Descriptors
import com.google.protobuf.DynamicMessage
import io.grpc.CallOptions
import io.grpc.Channel
import io.grpc.ClientCall
import io.grpc.ManagedChannel
import io.grpc.MethodDescriptor
import io.grpc.StatusRuntimeException
import io.grpc.netty.NettyChannelBuilder
import io.grpc.protobuf.ProtoUtils
import io.grpc.stub.ClientCalls
import io.netty.buffer.PooledByteBufAllocator
import org.reactivestreams.Publisher
import org.springframework.cloud.gateway.config.GrpcSslConfigurer
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.NettyWriteResponseFilter
import org.springframework.cloud.gateway.filter.OrderedGatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.cloud.gateway.route.Route
import org.springframework.cloud.gateway.support.GatewayToStringStyler.filterToStringCreator
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils
import org.springframework.core.ResolvableType
import org.springframework.core.io.Resource
import org.springframework.core.io.ResourceLoader
import org.springframework.core.io.buffer.DataBuffer
import org.springframework.core.io.buffer.NettyDataBufferFactory
import org.springframework.http.codec.json.Jackson2JsonDecoder
import org.springframework.http.server.reactive.ServerHttpResponseDecorator
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.woo.gateway.factory.NettyChannelFactory
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.io.IOException
import java.io.InputStream
import java.net.URI
import java.util.*
import java.util.function.Function as JavaUtilFunctionFunction


@Component
class CustomJsonToGrpcFilter(
    private val resourceLoader: ResourceLoader,
    private val channelFactory: NettyChannelFactory,
) : AbstractGatewayFilterFactory<CustomJsonToGrpcFilter.Config>(Config::class.java) {
    companion object {
        const val GRPC_PORT = 9090
    }

    override fun shortcutFieldOrder(): List<String> {
        return listOf("protoDescriptor", "protoFile", "service", "method")
    }

    override fun apply(config: Config): GatewayFilter {
        val filter: GatewayFilter = object : GatewayFilter {
            override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
                val modifiedResponse = GRPCResponseDecorator(exchange, config)

                ServerWebExchangeUtils.setAlreadyRouted(exchange)
                return modifiedResponse.writeWith(exchange.request.body)
                    .then(chain.filter(exchange.mutate().response(modifiedResponse).build()))
            }

            override fun toString(): String {
                return filterToStringCreator(this@CustomJsonToGrpcFilter).toString()
            }
        }

        val order = NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER - 1
        return OrderedGatewayFilter(filter, order)
    }

    class Config(
        val protoDescriptor: String,
        var protoFile: String,
        var service: String,
        var method: String,
    )

    inner class GRPCResponseDecorator internal constructor(
        private val exchange: ServerWebExchange,
        private val config: Config
    ) :
        ServerHttpResponseDecorator(exchange.response) {
        private lateinit var descriptor: Descriptors.Descriptor

        private lateinit var objectWriter: ObjectWriter

        private lateinit var objectReader: ObjectReader

        private lateinit var clientCall: ClientCall<DynamicMessage, DynamicMessage>

        private lateinit var objectNode: ObjectNode

        init {
            try {
                val descriptorFile: Resource = resourceLoader.getResource(config.protoDescriptor)
                val protoFile: Resource = resourceLoader.getResource(config.protoFile)

                descriptor = DescriptorProtos.FileDescriptorProto.parseFrom(descriptorFile.inputStream)
                    .descriptorForType

                val methodDescriptor: Descriptors.MethodDescriptor = getMethodDescriptor(
                    config,
                    descriptorFile.inputStream
                )
                val serviceDescriptor: Descriptors.ServiceDescriptor = methodDescriptor.service
                val outputType: Descriptors.Descriptor = methodDescriptor.outputType

                clientCall = createClientCallForType(config, serviceDescriptor, outputType)

                val schema: ProtobufSchema = ProtobufSchemaLoader.std.load(protoFile.inputStream)
                val responseType = schema.withRootType(outputType.name)

                val objectMapper = ObjectMapper(ProtobufFactory())
                objectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
                objectWriter = objectMapper.writer(schema)
                objectReader = objectMapper.readerFor(JsonNode::class.java).with(responseType)
                objectNode = objectMapper.createObjectNode()
            } catch (e: IOException) {
                throw RuntimeException(e)
            } catch (e: Descriptors.DescriptorValidationException) {
                throw RuntimeException(e)
            }
        }

        override fun writeWith(body: Publisher<out DataBuffer>): Mono<Void> {
            exchange.response.headers["Content-Type"] = "application/json"

            return delegate.writeWith(
                deserializeJSONRequest()
                    .map(callGRPCServer())
                    .map(serialiseGRPCResponse())
                    .map(wrapGRPCResponse())
                    .cast(DataBuffer::class.java)
                    .last()
            )
        }

        private fun createClientCallForType(
            config: Config,
            serviceDescriptor: Descriptors.ServiceDescriptor, outputType: Descriptors.Descriptor
        ): ClientCall<DynamicMessage, DynamicMessage> {
            val marshaller: MethodDescriptor.Marshaller<DynamicMessage> = ProtoUtils
                .marshaller(DynamicMessage.newBuilder(outputType).build())
            val methodDescriptor: MethodDescriptor<DynamicMessage, DynamicMessage> = MethodDescriptor
                .newBuilder<DynamicMessage?, DynamicMessage?>()
                .setType(MethodDescriptor.MethodType.UNKNOWN)
                .setFullMethodName(
                    MethodDescriptor.generateFullMethodName(serviceDescriptor.getFullName(), config.method)
                )
                .setRequestMarshaller(marshaller)
                .setResponseMarshaller(marshaller)
                .build()
            val channel: Channel = createChannel()
            return channel.newCall(methodDescriptor, CallOptions.DEFAULT)
        }

        @Throws(IOException::class, Descriptors.DescriptorValidationException::class)
        private fun getMethodDescriptor(config: Config, descriptorFile: InputStream): Descriptors.MethodDescriptor {
            val fileDescriptorSet: DescriptorProtos.FileDescriptorSet = DescriptorProtos.FileDescriptorSet
                .parseFrom(descriptorFile)
            val fileProto: DescriptorProtos.FileDescriptorProto = fileDescriptorSet.getFile(0)
            val fileDescriptor: Descriptors.FileDescriptor = Descriptors.FileDescriptor.buildFrom(
                fileProto,
                arrayOfNulls<Descriptors.FileDescriptor>(0)
            )

            val serviceDescriptor: Descriptors.ServiceDescriptor = fileDescriptor.findServiceByName(config.service)
                ?: throw NoSuchElementException("No Service found")

            val methods: List<Descriptors.MethodDescriptor> = serviceDescriptor.getMethods()

            return methods.stream()
                .filter { method: Descriptors.MethodDescriptor -> method.getName().equals(config.method) }
                .findFirst()
                .orElseThrow<NoSuchElementException> { NoSuchElementException("No Method found") }
        }

        private fun createChannel(): ManagedChannel {
            val requestURI: URI = (exchange.attributes[ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR] as Route).uri
            return createChannelChannel(requestURI.host)
        }

        private fun callGRPCServer(): JavaUtilFunctionFunction<JsonNode, DynamicMessage> {
            return JavaUtilFunctionFunction { jsonRequest ->
                try {
                    val request: ByteArray = objectWriter.writeValueAsBytes(jsonRequest)
                    val dynamicRequest = DynamicMessage.parseFrom(descriptor, request)

                    return@JavaUtilFunctionFunction ClientCalls.blockingUnaryCall(
                        clientCall,
                        dynamicRequest
                    )
                } catch (e: IOException) {
                    throw RuntimeException("Error during JSON serialization", e)
                } catch (e: StatusRuntimeException) {
                    throw RuntimeException("gRPC call failed: ${e.status}", e)
                }
            }
        }


        private fun serialiseGRPCResponse(): JavaUtilFunctionFunction<DynamicMessage, Any> {
            return JavaUtilFunctionFunction<DynamicMessage, Any> { gRPCResponse ->
                try {
                    return@JavaUtilFunctionFunction objectReader.readValue(gRPCResponse.toByteArray())
                } catch (e: IOException) {
                    throw RuntimeException(e)
                }
            }
        }

        private fun deserializeJSONRequest(): Flux<JsonNode> {
            return exchange.request.body.mapNotNull { dataBufferBody: DataBuffer ->
                if (dataBufferBody.capacity() == 0) {
                    return@mapNotNull objectNode
                }
                val targetType =
                    ResolvableType.forType(JsonNode::class.java)
                Jackson2JsonDecoder().decode(dataBufferBody, targetType, null, null)
            }.cast(JsonNode::class.java)
        }

        private fun wrapGRPCResponse(): JavaUtilFunctionFunction<Any, DataBuffer> {
            return JavaUtilFunctionFunction<Any, DataBuffer> { jsonResponse ->
                try {
                    return@JavaUtilFunctionFunction NettyDataBufferFactory(PooledByteBufAllocator())
                        .wrap(Objects.requireNonNull(ObjectMapper().writeValueAsBytes(jsonResponse)))
                } catch (e: JsonProcessingException) {
                    return@JavaUtilFunctionFunction NettyDataBufferFactory(PooledByteBufAllocator()).allocateBuffer()
                }
            }
        }

        // We are creating this on every call, should optimize?
        private fun createChannelChannel(host: String): ManagedChannel {
            return channelFactory.getChannel(host)!!
        }
    }
}