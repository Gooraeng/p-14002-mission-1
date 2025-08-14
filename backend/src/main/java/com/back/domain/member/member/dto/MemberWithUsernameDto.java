package com.back.domain.member.member.dto;

import com.back.domain.member.member.entity.Member;
import lombok.Getter;

@Getter
public class MemberWithUsernameDto extends MemberDto {
    private final String username;

    public MemberWithUsernameDto(Member member) {
        super(member);
        this.username = member.getUsername();
    }
}
