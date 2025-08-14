package com.back.domain.member.member.repository

import com.back.domain.member.member.entity.Member
import org.springframework.data.jpa.repository.JpaRepository
import java.util.*

interface MemberRepository : JpaRepository<Member, Int> {
    fun findByUsername(username: String): Optional<Member>

    fun findByApiKey(apiKey: String): Optional<Member>
}