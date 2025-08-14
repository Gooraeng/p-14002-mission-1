package com.back.global.security

import com.back.domain.member.member.service.MemberService
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class CustomOAuth2UserService (
    private val memberService: MemberService
) : DefaultOAuth2UserService() {

    private val logger = LoggerFactory.getLogger(javaClass)

    private enum class OAuth2ProviderType {
        GOOGLE,
        KAKAO,
        NAVER;

        companion object {
            fun from(registrationId: String): OAuth2ProviderType {
                return entries.firstOrNull {
                    it.name.equals(registrationId, ignoreCase = true)
                } ?: error("Invalid registration ID : $registrationId")
            }
        }
    }

    // 카카오톡 로그인이 성공할 때 마다 이 함수가 실행된다.
    @Transactional
    @Throws(OAuth2AuthenticationException::class)
    override fun loadUser(userRequest: OAuth2UserRequest): OAuth2User {
        val oAuth2User = super.loadUser(userRequest)

        val provider = OAuth2ProviderType.from(userRequest.clientRegistration.registrationId)

        val (oAuthUserId, nickname, profileImgUrl) = when (provider) {
            OAuth2ProviderType.GOOGLE -> {
                val properties = oAuth2User.attributes.getValue("properties") as Map<String, Any>

                Triple(
                    oAuth2User.name,
                    properties.getValue("nickname") as String,
                    properties.getValue("profile_image") as String
                )
            }

            OAuth2ProviderType.KAKAO -> {
                val attributes = oAuth2User.attributes

                Triple(
                    oAuth2User.name,
                    attributes.getValue("name") as String,
                    attributes.getValue("picture") as String
                )
            }

            OAuth2ProviderType.NAVER -> {
                val response = oAuth2User.attributes.getValue("response") as Map<String, Any>

                Triple(
                    response.getValue("id") as String,
                    response.getValue("nickname") as String,
                    response.getValue("profile_image") as String
                )
            }
        }

        val username = "${provider.name}__$oAuthUserId"
        val password = ""

        logger.debug("[OAuth2 Login Succeed] provider={}, oauthUserId={}, username={}", provider.name, oAuthUserId, username)

        val member = memberService.modifyOrJoin(username, password, nickname, profileImgUrl).data

        return SecurityUser(
            member.id,
            member.username,
            member.password ?: "",
            member.name,
            member.authorities
        )
    }
}