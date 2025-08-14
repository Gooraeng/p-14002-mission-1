package com.back.global.app

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.stereotype.Component

@Component
@ConfigurationProperties(prefix = "custom")
class CustomConfigProperties {
    lateinit var notProdMembers: MutableList<NotProdMember>

    @JvmRecord
    data class NotProdMember(
        @JvmField val username: String,
        @JvmField val apiKey: String,
        @JvmField val nickname: String,
        @JvmField val profileImgUrl: String
    )
}
