package com.mipo.userservice.controller.response;

import java.time.LocalDateTime;

import com.mipo.userservice.global.entity.RoleType;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CreateUserRes {
	private String email;
	private String name;
	private RoleType role;
	private LocalDateTime createdAt;

	@Builder
	public CreateUserRes(String email, String name, RoleType role, LocalDateTime createdAt) {
		this.email = email;
		this.name = name;
		this.role = role;
		this.createdAt = createdAt;
	}
}
