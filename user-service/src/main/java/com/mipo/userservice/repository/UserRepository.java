package com.mipo.userservice.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.mipo.userservice.entity.User;

public interface UserRepository extends CrudRepository<User, Long> {
	Optional<User> findByEmail(String email);
}
