package com.back.domain.member.member.dto;

import com.back.domain.member.member.entity.Member;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
public class MemberDto {
    private final int id;
    private final LocalDateTime createDate;
    private final LocalDateTime modifyDate;
    private final String name;
    @JsonProperty("isAdmin")
    private final boolean admin;
    private final String profileImageUrl;

    public MemberDto(Member member) {
        id = member.getId();
        createDate = member.getCreateDate();
        modifyDate = member.getModifyDate();
        name = member.getName();
        admin = member.isAdmin();
        profileImageUrl = member.getProfileImgUrlOrDefault();
    }
}
