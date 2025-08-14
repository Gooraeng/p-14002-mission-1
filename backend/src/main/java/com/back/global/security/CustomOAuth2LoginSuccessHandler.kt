package com.back.global.security

import com.back.domain.member.member.service.MemberService
import com.back.global.rq.Rq
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.stereotype.Component
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.*

@Component
class CustomOAuth2LoginSuccessHandler(
    private val memberService: MemberService,
    private val rq: Rq
): AuthenticationSuccessHandler {

    @Throws(IOException::class, ServletException::class)
    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse?,
        authentication: Authentication?
    ) {
        val actor = rq.actorFromDb

        val accessToken = memberService.genAccessToken(actor)

        rq.setCookie("apiKey", actor.apiKey)
        rq.setCookie("accessToken", accessToken)

        // ✅ 기본 리다이렉트 URL
        val redirectUrl = request.getParameter("state")?.let {
            String(
                Base64.getUrlDecoder().decode(it),
                StandardCharsets.UTF_8
            )
        }
            ?.substringBefore("#")
            ?.takeIf { it.isNotBlank() }
            ?: "/"

        rq.sendRedirect(redirectUrl)
    }
}
