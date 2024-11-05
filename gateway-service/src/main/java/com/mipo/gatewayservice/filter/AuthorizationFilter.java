package com.mipo.gatewayservice.filter;

import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class AuthorizationFilter extends AbstractGatewayFilterFactory<AuthorizationFilter.Config> {

	private final Environment env;

	public AuthorizationFilter(Environment env) {
		super(Config.class);
		this.env = env;
	}

	@Override
	public GatewayFilter apply(Config config) {
		return (((exchange, chain) -> {
			ServerHttpRequest request = exchange.getRequest();
			if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
				return onError(exchange, "no authorization header", HttpStatus.UNAUTHORIZED);
			}
			String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
			String jwt = authorizationHeader.replace("Bearer ", "");
			String requiredRole = config.getRequiredRole();
			Map<String, String> map = getSubjectAndRole(jwt);
			if (map == null) {
				return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
			}
			if (!isRoleValid(requiredRole, map.get("role"))) {
				return onError(exchange, "ROLE is not valid", HttpStatus.FORBIDDEN);
			}
			return chain.filter(exchange);
		}));
	}

	private boolean isRoleValid(String requiredRole, String role) {
		if(requiredRole == null)
			return true;
		return requiredRole.equals(role);
	}

	private Map<String, String> getSubjectAndRole(String jwt) {
		byte[] secretKeyBytes = Base64.getEncoder().encode(env.getProperty("token.secret").getBytes());
		SecretKey signingKey = Keys.hmacShaKeyFor(secretKeyBytes);

		String subject = null;
		String role = null;
		try {
			JwtParser jwtParser = Jwts.parser().verifyWith(signingKey).build();
			subject = jwtParser.parseSignedClaims(jwt).getPayload().getSubject();
			role = jwtParser.parseSignedClaims(jwt).getPayload().get("role", String.class);
		} catch (Exception ex) {
			return null;
		}
		if (subject == null || subject.isEmpty()) {
			return null;
		}
		Map<String, String> map = new HashMap<>();
		map.put("subject", subject);
		map.put("role", role);
		return map;
	}

	private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus httpStatus) {
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(httpStatus);
		log.info("error = {}", message);
		return response.setComplete();
	}

	public static class Config {
		private String requiredRole;

		public String getRequiredRole() {
			return requiredRole;
		}

		public void setRequiredRole(String requiredRole) {
			this.requiredRole = requiredRole;
		}
	}

}
