package com.mipo.userservice.global.config;

import java.util.function.Supplier;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import com.mipo.userservice.global.filter.AuthenticationFilter;
import com.mipo.userservice.service.UserService;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final UserService userService;
	private final PasswordEncoder passwordEncoder;
	private final Environment env;

	public static final String ALLOWED_IP_ADDRESS = "127.0.0.1";
	public static final String SUBNET = "/32";
	public final IpAddressMatcher ALLOWED_IP_ADDRESS_MATCHER = new IpAddressMatcher(ALLOWED_IP_ADDRESS + SUBNET);

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		AuthenticationManagerBuilder managerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
		managerBuilder.userDetailsService(userService).passwordEncoder(passwordEncoder);
		AuthenticationManager authenticationManager = managerBuilder.build();

		return http.csrf(AbstractHttpConfigurer::disable)
			.authorizeHttpRequests(auth -> auth
				.requestMatchers(new AntPathRequestMatcher("/users", "POST")).permitAll()
				.requestMatchers(new AntPathRequestMatcher("/healthcheck")).permitAll()
				.requestMatchers("/**").access(
					new WebExpressionAuthorizationManager("hasIpAddress('127.0.0.1')")
				)
				.anyRequest().authenticated()
			)
			.authenticationManager(authenticationManager)
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.addFilterBefore(getAuthenticationFilter(authenticationManager),
				UsernamePasswordAuthenticationFilter.class)
			.httpBasic(Customizer.withDefaults())
			.build();
	}
	private AuthorizationDecision hasIpAddress(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
		return new AuthorizationDecision(ALLOWED_IP_ADDRESS_MATCHER.matches(object.getRequest()));
	}
	private AuthenticationFilter getAuthenticationFilter(AuthenticationManager authenticationManager) {
		AuthenticationFilter authenticationFilter = new AuthenticationFilter(env);
		authenticationFilter.setAuthenticationManager(authenticationManager);
		return authenticationFilter;
	}
}
