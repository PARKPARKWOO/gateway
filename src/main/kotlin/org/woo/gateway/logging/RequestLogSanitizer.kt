package org.woo.gateway.logging

/** Request 로그에서 사용할 수 있는 제한된 식별자만 반환한다. */
internal object RequestLogSanitizer {
    private val requestIdPattern = Regex("[A-Za-z0-9._:-]{1,128}")

    fun requestId(requestId: String?): String =
        requestId?.takeIf(requestIdPattern::matches) ?: "-"
}
