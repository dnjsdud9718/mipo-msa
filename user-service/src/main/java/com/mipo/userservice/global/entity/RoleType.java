package com.mipo.userservice.global.entity;

public enum RoleType {
	ROLE_USER, ROLE_OWNER, ROLE_ADMIN;

	public static RoleType fromString(String role) {
		return RoleType.valueOf(role.toUpperCase());
	}
}
