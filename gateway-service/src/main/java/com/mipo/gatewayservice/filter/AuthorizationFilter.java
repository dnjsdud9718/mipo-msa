package com.mipo.gatewayservice.filter;

import java.util.Base64;

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
			if (!isJwtValid(jwt)) {
				return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
			}
			return chain.filter(exchange);
		}));
	}

	private boolean isJwtValid(String jwt) {
		byte[] secretKeyBytes = Base64.getEncoder().encode(env.getProperty("token.secret").getBytes());
		SecretKey signingKey = Keys.hmacShaKeyFor(secretKeyBytes);

		boolean returnValue = true;
		String subject = null;

		try {
			JwtParser jwtParser = Jwts.parser().verifyWith(signingKey).build();

			subject = jwtParser.parseSignedClaims(jwt).getPayload().getSubject();
		} catch (Exception ex) {
			returnValue = false;
		}

		if (subject == null || subject.isEmpty()) {
			returnValue = false;
		}
		// TODO -> subject 와 email 비교:(로그인 계정 이메일을 레디스에 보관해두었다가 비교하면 어떨까?)
		return returnValue;
	}

	private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus httpStatus) {
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(httpStatus);
		log.info("error = {}", message);
		return response.setComplete();
	}

	public static class Config {

	}

}
