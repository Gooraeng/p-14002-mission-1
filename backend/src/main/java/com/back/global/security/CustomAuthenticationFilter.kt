package com.back.global.security

import com.back.domain.member.member.entity.Member
import com.back.domain.member.member.service.MemberService
import com.back.global.exception.ServiceException
import com.back.global.rq.Rq
import com.back.standard.util.Ut
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import lombok.RequiredArgsConstructor
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
@RequiredArgsConstructor
class CustomAuthenticationFilter(
    private val memberService: MemberService,
    private val rq: Rq
) : OncePerRequestFilter() {

    private val publicApiList = listOf(
        "/api/v1/members/login",
        "/api/v1/members/logout",
        "/api/v1/members/join"
    )

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        logger.debug("Processing request for " + request.requestURI)

        try {
            work(request, response, filterChain)
        } catch (e: ServiceException) {
            val rsData = e.rsData
            response.contentType = "application/json;charset=UTF-8"
            response.status = rsData.statusCode
            response.writer.write(Ut.json.toString(rsData))
        }
    }

    private fun extractTokens(): Pair<String, String> {
        val headerAuthorization = rq.getHeader("Authorization", "")

        return if (headerAuthorization.isNotBlank()) {
            if (!headerAuthorization.startsWith("Bearer ")) throw ServiceException(
                "401-2",
                "Authorization 헤더가 Bearer 형식이 아닙니다."
            )

            val headerAuthorizationBits = headerAuthorization.split(" ", limit = 3)

            headerAuthorizationBits.getOrNull(1).orEmpty() to headerAuthorizationBits.getOrNull(2).orEmpty()

        } else {
            rq.getCookieValue("apiKey", "") to rq.getCookieValue("accessToken", "")
        }
    }

    private fun getMemberFromTokens(accessToken: String): Member? {
        if (accessToken.isBlank()) return null

        val payload = memberService.payload(accessToken) ?: return null

        val id = payload["id"] as Int
        val username = payload["username"] as String
        val name = payload["name"] as String

        return Member(id, username, name)
    }

    private fun resolveMember(apiKey: String, accessToken: String): Pair<Member, Boolean> {
        getMemberFromTokens(accessToken)?.let { return it to true}

        return memberService.findByApiKey(apiKey)
            .orElse(null)
            ?.let { it to false }
            ?: throw ServiceException("401-3", "API 키가 유효하지 않습니다.")
    }

    private fun work(request: HttpServletRequest, response: HttpServletResponse?, filterChain: FilterChain) {
        // API 요청이 아니거나 인증이 필요하지 않은 요청이라면 패스
        if (!checkApiRequest(request) || checkPublicApiRequest(request)) {
            filterChain.doFilter(request, response)
            return
        }

        val (apiKey, accessToken) = extractTokens()

        logger.debug("apiKey : $apiKey")
        logger.debug("accessToken : $accessToken")

        if (apiKey.isBlank() && accessToken.isBlank()) {
            filterChain.doFilter(request, response)
            return
        }

        val (member, isAccessTokenValid) = resolveMember(apiKey, accessToken)

        if (accessToken.isNotBlank() && !isAccessTokenValid) {
            refreshAccessToken(member)
        }

        doAuthenticate(member)

        filterChain.doFilter(request, response)
    }

    private fun refreshAccessToken(member: Member) {
        val newAccessToken = memberService.genAccessToken(member)

        rq.setCookie("accessToken", newAccessToken)
        rq.setHeader("Authorization", newAccessToken)
    }

    private fun doAuthenticate(member: Member) {
        val user: UserDetails = SecurityUser(
            member.id,
            member.username,
            "",
            member.nickname,
            member.authorities
        )

        // 이 시점 이후부터는 시큐리티가 이 요청을 인증된 사용자의 요청으로 본다.
        SecurityContextHolder.getContext().authentication = UsernamePasswordAuthenticationToken(
            user,
            user.password,
            user.authorities
        )
    }


    private fun checkApiRequest(request: HttpServletRequest): Boolean =
        request.requestURI.startsWith("/api/")

    private fun checkPublicApiRequest(request: HttpServletRequest): Boolean =
        request.requestURI in publicApiList
}
