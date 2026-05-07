package org.woo.gateway.config

import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * CSRF Origin/Referer 화이트리스트 설정.
 *
 * - [allowedHostSuffixes]: `.platformholder.site` 처럼 서브도메인 통째로 허용할 패밀리 도메인.
 * - [allowedExactHosts]: vercel preview 등 패밀리 와일드카드를 줄 수 없는 외부 호스트의 정확 매칭.
 * - [allowedLocalhostHosts]: 로컬 개발 편의용 호스트.
 *
 * 정책: `OriginVerificationFilter` 가 unsafe method 요청에 대해 Origin/Referer 호스트를 위 목록과 비교한다.
 * `.vercel.app` 같이 통째로 suffix 허용은 **금지** (제3자 vercel 사이트가 우리 백엔드로 CSRF 가능).
 * 외부 정적 호스팅을 추가할 때는 [allowedExactHosts] 에 정확한 호스트네임을 등록한다.
 */
@ConfigurationProperties(prefix = "gateway.security.csrf")
data class CsrfOriginProperties(
    val allowedHostSuffixes: List<String> = listOf(".platformholder.site"),
    val allowedExactHosts: List<String> = emptyList(),
    val allowedLocalhostHosts: List<String> = listOf("localhost", "127.0.0.1"),
)
