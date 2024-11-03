package com.mipo.userservice.controller;

import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mipo.userservice.controller.request.CreateUserReq;
import com.mipo.userservice.controller.response.CreateUserRes;
import com.mipo.userservice.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequiredArgsConstructor
@RequestMapping
@Slf4j
public class UserController {

	private final Environment environment;
	private final UserService userService;

	@PostMapping("/users")
	public ResponseEntity<CreateUserRes> createUser(@RequestBody CreateUserReq userReq) {
		CreateUserRes res = userService.createUser(userReq);
		return ResponseEntity.status(HttpStatus.CREATED).body(res);
	}

	@GetMapping("/users")
	public String check(HttpServletRequest request) {
		log.info("Server port = {}", request.getServerPort());
		log.info("Env={}", environment.getProperty("server.port"));
		return "hello";
	}
}
