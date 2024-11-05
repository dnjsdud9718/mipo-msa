package com.mipo.userservice.global.filter;

import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mipo.userservice.controller.request.LoginReq;
import com.mipo.userservice.entity.User;
import com.mipo.userservice.service.UserContext;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final ObjectMapper mapper = new ObjectMapper();
	private final Environment env;

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws
		AuthenticationException {
		if (!HttpMethod.POST.name().equals(request.getMethod())) {
			throw new IllegalArgumentException("Authentication method not supported");
		}
		LoginReq req = null;
		try {
			req = mapper.readValue(request.getReader(), LoginReq.class);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		if (!StringUtils.hasText(req.getEmail()) || !StringUtils.hasText(req.getPassword())) {
			throw new AuthenticationServiceException("Username or Password is not provided");
		}

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(req.getEmail(),
			req.getPassword());
		return getAuthenticationManager().authenticate(token);

	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
		Authentication authResult) throws IOException, ServletException {
		UserContext userContext = (UserContext)authResult.getPrincipal();
		User user = userContext.getUser();

		Instant now = Instant.now();
		byte[] secretKeyBytes = Base64.getEncoder().encode(env.getProperty("token.secret").getBytes());
		SecretKey secretKey = Keys.hmacShaKeyFor(secretKeyBytes);
		String token = Jwts.builder()
			.subject(user.getUserUUID())
			.claim("role", user.getRole())
			.expiration(Date.from(now.plusMillis(Long.parseLong(env.getProperty("token.expiration_time")))))
			.issuedAt(Date.from(now))
			.signWith(secretKey)
			.compact();

		response.addHeader("token", token);
		response.addHeader("uuid", user.getUserUUID());
	}
}
