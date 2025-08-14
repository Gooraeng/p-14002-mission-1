package com.back.global.security

import com.back.global.rsData.RsData
import com.back.standard.util.Ut
import lombok.RequiredArgsConstructor
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
@RequiredArgsConstructor
class SecurityConfig (
    private val customAuthenticationFilter: CustomAuthenticationFilter,
    private val customOAuth2LoginSuccessHandler: AuthenticationSuccessHandler,
    private val customOAuth2AuthorizationRequestResolver: CustomOAuth2AuthorizationRequestResolver
){
    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain? {
        http {
            authorizeHttpRequests {
                authorize("/favicon.ico", permitAll)
                authorize("/h2-console/**", permitAll)
                authorize(HttpMethod.GET, "/api/*/posts/{id:\\d+}", permitAll)
                authorize(HttpMethod.GET, "/api/*/posts", permitAll)
                authorize(HttpMethod.GET, "/api/*/posts/{postId:\\d+}/comments", permitAll)
                authorize(HttpMethod.GET, "/api/*/posts/{postId:\\d+}/comments/{id:\\d+}", permitAll)
                authorize("/api/*/members/login", permitAll)
                authorize("/api/*/members/logout", permitAll)
                authorize(HttpMethod.POST, "/api/*/members", permitAll)
                authorize("/api/*/adm/**", hasRole("ADMIN"))
                authorize("/api/*/**", authenticated)
                authorize(anyRequest, permitAll)
            }

            headers {
                frameOptions { sameOrigin = true }
            }

            csrf { disable() }
            formLogin { disable() }
            logout { disable() }
            httpBasic { disable() }

            sessionManagement { sessionCreationPolicy = SessionCreationPolicy.STATELESS }

            oauth2Login {
                authenticationSuccessHandler = customOAuth2LoginSuccessHandler

                authorizationEndpoint { authorizationRequestResolver = customOAuth2AuthorizationRequestResolver }
            }

            addFilterBefore<UsernamePasswordAuthenticationFilter>(customAuthenticationFilter)

            exceptionHandling {
                authenticationEntryPoint = AuthenticationEntryPoint { request, response, authException ->
                    response.contentType = "application/json; charset=utf-8"
                    response.status = HttpStatus.UNAUTHORIZED.value()
                    response.writer.write(
                        Ut.json.toString(RsData<Void>("401-1", "로그인 후 이용해주세요."))
                    )
                }

                accessDeniedHandler = AccessDeniedHandler { request, response, authException ->
                    response.contentType = "application/json; charset=utf-8"
                    response.status = HttpStatus.FORBIDDEN.value()
                    response.writer.write(
                        Ut.json.toString(RsData<Void>("403-1", "권한이 없습니다."))
                    )
                }
            }
        }

        return http.build()
    }

    @Bean
    fun corsConfigurationSource(): UrlBasedCorsConfigurationSource {
        val configuration = CorsConfiguration().apply {
            allowedOrigins = listOf("https://cdpn.io", "http://localhost:3000")
            allowedMethods = listOf("GET", "POST", "PUT", "PATCH", "DELETE")
            allowedHeaders = listOf("*")
            allowCredentials = true
        }

        // CORS 설정을 소스에 등록
        return UrlBasedCorsConfigurationSource().apply {
            registerCorsConfiguration("/api/**", configuration)
        }
    }
}
