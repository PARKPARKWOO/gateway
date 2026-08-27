package org.woo.gateway.security

import org.springframework.stereotype.Component
import org.woo.gateway.config.CbtCorsProperties
import java.net.IDN
import java.net.URI
import java.util.Locale

@Component
class CbtWebOriginMatcher(
    properties: CbtCorsProperties,
) {
    private val allowedOrigins =
        properties.allowedOrigins.map { configuredOrigin ->
            requireNotNull(canonicalize(configuredOrigin, allowResourceParts = false)) {
                "CBT CORS allowed origin must be an absolute HTTP(S) origin"
            }
        }.toSet()

    fun matchesOrigin(origin: String): Boolean =
        parse(origin)?.let { canonicalize(it, allowResourceParts = false) in allowedOrigins } == true

    fun matchesReferer(referer: String): Boolean =
        parse(referer)?.let { canonicalize(it, allowResourceParts = true) in allowedOrigins } == true

    private fun parse(value: String): URI? =
        try {
            URI(value)
        } catch (_: IllegalArgumentException) {
            null
        }

    private fun canonicalize(
        uri: URI,
        allowResourceParts: Boolean,
    ): CanonicalOrigin? {
        if (!uri.isAbsolute || uri.isOpaque || uri.rawAuthority.isNullOrBlank()) return null
        if (uri.rawUserInfo != null) return null
        if (!allowResourceParts && (!uri.rawPath.isNullOrEmpty() || uri.rawQuery != null || uri.rawFragment != null)) {
            return null
        }

        val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: return null
        if (scheme != "http" && scheme != "https") return null
        val authority = parseAuthority(uri) ?: return null
        val host =
            try {
                IDN.toASCII(authority.host, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
            } catch (_: IllegalArgumentException) {
                return null
            }
        if (host.isBlank()) return null

        val effectivePort =
            when {
                authority.port != null -> authority.port
                scheme == "https" -> 443
                else -> 80
            }
        if (effectivePort !in 1..65535) return null
        return CanonicalOrigin(scheme, host, effectivePort)
    }

    private fun parseAuthority(uri: URI): Authority? {
        uri.host?.let { host ->
            if (uri.port < 0 && uri.rawAuthority?.endsWith(':') == true) return null
            return Authority(host, uri.port.takeIf { it >= 0 })
        }

        val rawAuthority = uri.rawAuthority ?: return null
        if ('@' in rawAuthority || rawAuthority.startsWith('[')) return null
        val colonIndex = rawAuthority.lastIndexOf(':')
        if (colonIndex < 0) return Authority(rawAuthority, null)

        val portText = rawAuthority.substring(colonIndex + 1)
        if (portText.isEmpty() || portText.any { !it.isDigit() }) return null
        val port = portText.toIntOrNull() ?: return null
        val host = rawAuthority.substring(0, colonIndex)
        return Authority(host, port)
    }

    private data class Authority(
        val host: String,
        val port: Int?,
    )

    private data class CanonicalOrigin(
        val scheme: String,
        val host: String,
        val port: Int,
    )
}
