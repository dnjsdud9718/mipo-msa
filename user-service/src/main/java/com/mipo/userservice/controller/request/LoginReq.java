package com.mipo.userservice.controller.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class LoginReq {
	@NotNull(message = "Email cannot be null")
	@Email
	private String email;

	@NotNull(message = "Password cannot be null")
	@Size(min = 8, max = 16, message = "Password must be equal or grater than 8 characters and less than 16 characters")
	private String password;

	@Builder
	public LoginReq(String email, String password) {
		this.email = email;
		this.password = password;
	}
}
