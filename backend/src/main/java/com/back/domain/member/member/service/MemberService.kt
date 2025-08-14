package com.back.domain.member.member.service

import com.back.domain.member.member.entity.Member
import com.back.domain.member.member.repository.MemberRepository
import com.back.global.exception.ServiceException
import com.back.global.rsData.RsData
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import java.util.*
import java.util.function.Consumer

@Service
class MemberService(
    private val authTokenService: AuthTokenService,
    private val memberRepository: MemberRepository,
    private val passwordEncoder: PasswordEncoder
) {
    fun count(): Long {
        return memberRepository.count()
    }

    @JvmOverloads
    fun join(username: String, password: String?, nickname: String, profileImgUrl: String? = null): Member {
        var password = password
        memberRepository
            .findByUsername(username)
            .ifPresent(Consumer { _member: Member ->
                throw ServiceException("409-1", "이미 존재하는 아이디입니다.")
            })

        password = if (password.isNullOrBlank()) null else passwordEncoder.encode(password)

        val member = Member(username, password, nickname, profileImgUrl)

        return memberRepository.save(member)
    }

    fun findByUsername(username: String): Optional<Member> {
        return memberRepository.findByUsername(username)
    }

    fun findByApiKey(apiKey: String): Optional<Member> {
        return memberRepository.findByApiKey(apiKey)
    }

    fun genAccessToken(member: Member): String {
        return authTokenService.genAccessToken(member)
    }

    fun payload(accessToken: String): Map<String, Any>? {
        return authTokenService.payload(accessToken)
    }

    fun findById(id: Int): Optional<Member> {
        return memberRepository.findById(id)
    }

    fun findAll(): List<Member> {
        return memberRepository.findAll()
    }

    fun checkPassword(member: Member, password: String) {
        if (!passwordEncoder.matches(password, member.password))
            throw ServiceException("401-1", "비밀번호가 일치하지 않습니다.")
    }

    fun modifyOrJoin(username: String, password: String?, nickname: String, profileImgUrl: String?): RsData<Member> {
        var member = findByUsername(username).orElse(null)

        if (member == null) {
            member = join(username, password, nickname, profileImgUrl)
            return RsData("201-1", "회원가입이 완료되었습니다.", member)
        }

        modify(member, nickname, profileImgUrl)

        return RsData("200-1", "회원 정보가 수정되었습니다.", member)
    }

    private fun modify(member: Member, nickname: String, profileImgUrl: String?) {
        member.modify(nickname, profileImgUrl)
    }
}