package com.mipo.userservice.controller.request;

import com.mipo.userservice.global.entity.RoleType;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CreateUserReq {
	@NotNull(message = "Email cannot be null")
	@Email
	private String email;

	@NotNull(message = "Password cannot be null")
	@Size(min = 8, max = 16, message = "Password must be equal or grater than 8 characters and less than 16 characters")
	private String password;

	@NotNull(message = "Name cannot be null")
	@Size(min=2, message = "Name must be grater than 2 characters")
	private String name;

	@NotNull(message = "Role cannot be null")
	private RoleType role;
	@Builder
	public CreateUserReq(String email, String password, String name, RoleType role) {
		this.email = email;
		this.password = password;
		this.name = name;
		this.role = role;
	}
}
