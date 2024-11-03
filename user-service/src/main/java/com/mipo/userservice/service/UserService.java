package com.mipo.userservice.service;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.mipo.userservice.controller.request.CreateUserReq;
import com.mipo.userservice.controller.response.CreateUserRes;
import com.mipo.userservice.entity.User;

public interface UserService extends UserDetailsService {
	CreateUserRes createUser(CreateUserReq req);
}
