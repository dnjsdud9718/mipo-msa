package com.mipo.userservice.service;

import java.util.List;
import java.util.UUID;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.mipo.userservice.controller.request.CreateUserReq;
import com.mipo.userservice.controller.response.CreateUserRes;
import com.mipo.userservice.entity.User;
import com.mipo.userservice.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{
	private final UserRepository userRepository;
	private final PasswordEncoder encoder;

	@Transactional
	@Override
	public CreateUserRes createUser(CreateUserReq req) {
		User user = User.builder()
			.email(req.getEmail())
			// .password(req.getPassword())
			.name(req.getName())
			.userUUID(UUID.randomUUID().toString())
			.role(req.getRole())
			.build();
		user.encryptPassword(encoder, req.getPassword());
		userRepository.save(user);
		return CreateUserRes.builder()
			.email(user.getEmail())
			.name(user.getName())
			.role(user.getRole())
			.createdAt(user.getCreatedAt()).build();
	}

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		User user = userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException(email));
		List<GrantedAuthority> authorities = List.of(
			new SimpleGrantedAuthority(user.getRole().name()));

		return new UserContext(user, authorities);
	}
}
