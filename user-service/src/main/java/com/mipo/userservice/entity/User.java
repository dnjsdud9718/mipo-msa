package com.mipo.userservice.entity;

import java.io.Serializable;

import org.springframework.security.crypto.password.PasswordEncoder;

import com.mipo.userservice.global.entity.BaseEntity;
import com.mipo.userservice.global.entity.RoleType;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "users")
@NoArgsConstructor
@Getter
public class User extends BaseEntity implements Serializable{

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String email;
	private String password;
	private String name;
	private String userUUID;
	@Enumerated(EnumType.STRING)
	private RoleType role;
	@Builder
	public User(Long id, String email, String password, String name, String userUUID, RoleType role) {
		this.id = id;
		this.email = email;
		this.password = password;
		this.name = name;
		this.userUUID = userUUID;
		this.role = role;
	}

	// 비밀번호 암호화
	public void encryptPassword(PasswordEncoder encoder, String password) {
		this.password = encoder.encode(password);
	}
}
