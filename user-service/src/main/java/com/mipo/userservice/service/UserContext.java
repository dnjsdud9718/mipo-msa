package com.mipo.userservice.service;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.mipo.userservice.entity.User;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Data
public class UserContext implements UserDetails {
	private final User user;
	private final List<GrantedAuthority> authorities;

	public UserContext(User user, List<GrantedAuthority> authorities) {
		this.user = user;
		this.authorities = authorities;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getEmail();
	}
}
