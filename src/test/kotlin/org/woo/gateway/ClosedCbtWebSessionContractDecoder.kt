package org.woo.gateway

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.core.StreamReadFeature
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.MapperFeature
import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.module.kotlin.KotlinFeature
import com.fasterxml.jackson.module.kotlin.KotlinModule
import org.springframework.boot.context.properties.bind.Binder
import org.springframework.boot.context.properties.bind.PropertySourcesPlaceholdersResolver
import org.springframework.boot.context.properties.source.ConfigurationPropertySources
import org.springframework.boot.env.YamlPropertySourceLoader
import org.springframework.core.env.MutablePropertySources
import org.springframework.core.io.ClassPathResource

class ClosedCbtWebSessionContractDecoder {
    private val mapper =
        JsonMapper
            .builder()
            .addModule(
                KotlinModule
                    .Builder()
                    .enable(KotlinFeature.StrictNullChecks)
                    .build(),
            )
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS)
            .build()

    fun decode(json: String): CbtWebSessionContract {
        val root = mapper.readTree(json)
        validateOperationShapes(root)
        return mapper.treeToValue(root, CbtWebSessionContract::class.java)
    }

    private fun validateOperationShapes(root: JsonNode) {
        val operations = requireNotNull(root["operationHeaders"])
        require(operations.isObject)
        require(operations.fieldNames().asSequence().toSet() == OPERATION_FIELDS.keys)
        OPERATION_FIELDS.forEach { (name, expectedFields) ->
            val operation = requireNotNull(operations[name])
            require(operation.isObject)
            require(operation.fieldNames().asSequence().toSet() == expectedFields)
            require(operation.elements().asSequence().none(JsonNode::isNull))
        }
    }

    private companion object {
        val OPERATION_FIELDS =
            linkedMapOf(
                "publicCatalogRead" to setOf("methods", "paths", "required", "optional", "webRequired", "anonymousMobileRequired"),
                "publicQuestionPreviewRead" to setOf("method", "path", "auth", "client", "required", "optional", "webRequired"),
                "publicAssetRead" to setOf("method", "path", "auth", "required", "optional", "webRequired", "anonymousMobileRequired"),
                "attemptCreate" to setOf("method", "path", "auth", "required", "optional", "webRequired", "anonymousMobileRequired"),
                "guestAttemptRead" to setOf("methods", "paths", "auth", "requiredWhenGuest", "webRequired", "anonymousMobileRequired"),
                "guestAttemptSaveCheckSubmit" to setOf("methods", "paths", "auth", "requiredWhenGuest", "webRequired", "anonymousMobileRequired"),
                "attemptClaim" to setOf("method", "path", "auth", "required", "optional", "webRequired", "anonymousMobileRequired"),
                "userRead" to setOf("methods", "paths", "auth", "required", "optional", "webRequired", "anonymousMobileRequired"),
                "wrongAnswerResolve" to setOf("method", "path", "auth", "required", "optional", "webRequired", "anonymousMobileRequired"),
                "wrongAnswerRetry" to setOf("method", "path", "auth", "required", "optional", "webRequired", "anonymousMobileRequired"),
                "publicPrintableCreate" to setOf("method", "path", "auth", "client", "required", "optional", "webRequired"),
                "wrongPrintableCreate" to setOf("method", "path", "auth", "client", "required", "optional", "webRequired"),
                "guestPrintableRead" to setOf("method", "paths", "auth", "client", "requiredWhenGuest", "webRequired"),
            )
    }
}

fun <T : Any> bindGatewayConfig(
    prefix: String,
    type: Class<T>,
    profileResource: String? = null,
): T = bindYamlConfig(prefix, type, profileResource)

private fun <T : Any> bindYamlConfig(
    prefix: String,
    type: Class<T>,
    profileResource: String?,
): T {
    val propertySources = MutablePropertySources()
    val loader = YamlPropertySourceLoader()

    loader.load("contract-application", ClassPathResource("application.yml"))
        .forEach(propertySources::addLast)
    profileResource?.let { resourceName ->
        loader.load("contract-$resourceName", ClassPathResource(resourceName))
            .asReversed()
            .forEach(propertySources::addFirst)
    }

    return Binder(
        ConfigurationPropertySources.from(propertySources),
        PropertySourcesPlaceholdersResolver(propertySources),
    ).bind(prefix, type).get()
}

data class CbtWebSessionContract(
    val version: Int,
    val authTransport: AuthTransportContract,
    val allowedWebOrigins: List<String>,
    val cookies: CookiesContract,
    val operationHeaders: OperationHeadersContract,
) {
    fun withoutOperations() = SecurityContractProjection(version, authTransport, allowedWebOrigins, cookies)
}

data class SecurityContractProjection(
    val version: Int,
    val authTransport: AuthTransportContract,
    val allowedWebOrigins: List<String>,
    val cookies: CookiesContract,
)

data class AuthTransportContract(
    val web: WebAuthTransport,
    val mobile: MobileAuthTransport,
    val rotationOwner: RotationOwner,
    val webDirectReissue: Boolean,
)

enum class WebAuthTransport { HTTP_ONLY_COOKIE }
enum class MobileAuthTransport { BEARER }
enum class RotationOwner { GATEWAY }

data class CookiesContract(
    val auth: AuthCookiesContract,
    val csrf: CsrfCookieContract,
)

data class AuthCookiesContract(
    val names: List<String>,
    val path: String,
    val httpOnly: Boolean,
    val production: CookieProfileContract,
    val localTest: CookieProfileContract,
    val maxAge: MaxAgeContract,
)

data class CsrfCookieContract(
    val cookieName: String,
    val headerName: String,
    val path: String,
    val httpOnly: Boolean,
    val production: CookieProfileContract,
    val localTest: CookieProfileContract,
)

data class CookieProfileContract(
    val domain: String?,
    val secure: Boolean,
    val sameSite: SameSiteContract,
)

enum class SameSiteContract(val wire: String) {
    @JsonProperty("None")
    NONE("None"),

    @JsonProperty("Lax")
    LAX("Lax"),
}

data class MaxAgeContract(
    val issue: IssueMaxAge,
    val clear: ClearMaxAge,
)

enum class IssueMaxAge { JWT_EXPIRES_IN_MILLIS }
enum class ClearMaxAge { ZERO }
enum class ContractHttpMethod { GET, POST, PUT }
enum class ContractAuth { NONE, OPTIONAL, REQUIRED }
enum class ContractClient { WEB_ONLY }

data class OperationContract(
    val method: ContractHttpMethod? = null,
    val methods: List<ContractHttpMethod>? = null,
    val path: String? = null,
    val paths: List<String>? = null,
    val auth: ContractAuth? = null,
    val client: ContractClient? = null,
    val required: List<String>? = null,
    val optional: List<String>? = null,
    val requiredWhenGuest: List<String>? = null,
    val webRequired: List<String>,
    val anonymousMobileRequired: List<String>? = null,
) {
    fun allMethods(): List<ContractHttpMethod> = method?.let(::listOf) ?: requireNotNull(methods)

    fun expandedRoutes(): List<Pair<ContractHttpMethod, String>> {
        val routePaths = path?.let(::listOf) ?: requireNotNull(paths)
        val routeMethods = allMethods()
        return when {
            routeMethods.size == 1 -> routePaths.map { routeMethods.single() to it }
            routeMethods.size == routePaths.size -> routeMethods.zip(routePaths)
            routeMethods == listOf(ContractHttpMethod.PUT, ContractHttpMethod.POST) && routePaths.size == 3 ->
                listOf(ContractHttpMethod.PUT to routePaths.first()) +
                    routePaths.drop(1).map { ContractHttpMethod.POST to it }
            else -> error("ambiguous operation method/path matrix")
        }
    }
}

data class OperationHeadersContract(
    val publicCatalogRead: OperationContract,
    val publicQuestionPreviewRead: OperationContract,
    val publicAssetRead: OperationContract,
    val attemptCreate: OperationContract,
    val guestAttemptRead: OperationContract,
    val guestAttemptSaveCheckSubmit: OperationContract,
    val attemptClaim: OperationContract,
    val userRead: OperationContract,
    val wrongAnswerResolve: OperationContract,
    val wrongAnswerRetry: OperationContract,
    val publicPrintableCreate: OperationContract,
    val wrongPrintableCreate: OperationContract,
    val guestPrintableRead: OperationContract,
) {
    fun entries(): Map<String, OperationContract> =
        linkedMapOf(
            "publicCatalogRead" to publicCatalogRead,
            "publicQuestionPreviewRead" to publicQuestionPreviewRead,
            "publicAssetRead" to publicAssetRead,
            "attemptCreate" to attemptCreate,
            "guestAttemptRead" to guestAttemptRead,
            "guestAttemptSaveCheckSubmit" to guestAttemptSaveCheckSubmit,
            "attemptClaim" to attemptClaim,
            "userRead" to userRead,
            "wrongAnswerResolve" to wrongAnswerResolve,
            "wrongAnswerRetry" to wrongAnswerRetry,
            "publicPrintableCreate" to publicPrintableCreate,
            "wrongPrintableCreate" to wrongPrintableCreate,
            "guestPrintableRead" to guestPrintableRead,
        )
}
