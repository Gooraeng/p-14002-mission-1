package com.back.domain.post.postComment.dto;

import com.back.domain.post.postComment.entity.PostComment;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
public class PostCommentDto {
    private final int id;
    private final LocalDateTime createDate;
    private final LocalDateTime modifyDate;
    private final int authorId;
    private final String authorName;
    private final int postId;
    private final String content;

    public PostCommentDto(PostComment postComment) {
        id = postComment.getId();
        createDate = postComment.getCreateDate();
        modifyDate = postComment.getModifyDate();
        authorId = postComment.getAuthor().getId();
        authorName = postComment.getAuthor().getName();
        postId = postComment.getPost().getId();
        content = postComment.getContent();
    }
}