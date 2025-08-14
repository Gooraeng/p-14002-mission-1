package com.back.domain.post.post.dto;

import com.back.domain.post.post.entity.Post;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
public class PostDto {
    private final int id;
    private final LocalDateTime createDate;
    private final LocalDateTime modifyDate;
    private final int authorId;
    private final String authorName;
    private final String title;

    public PostDto(Post post) {
        id = post.getId();
        createDate = post.getCreateDate();
        modifyDate = post.getModifyDate();
        authorId = post.getAuthor().getId();
        authorName = post.getAuthor().getName();
        title = post.getTitle();
    }
}