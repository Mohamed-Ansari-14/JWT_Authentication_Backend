package com.jwt.JwtAuthentication.security.jwt;

import java.security.Key;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.jwt.JwtAuthentication.security.services.UserDetailsImpl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;


@Component
public class JwtUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtils.class);
	
	@Value("${mohamedansari.app.jwtSecret}")
	private String jwtSecret;
	
	@Value("${mohamedansari.app.jwtExpirationMs}")
	private int jwtExpirationMs;
	
	public String generateToken(Authentication authentication) {
		UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
		
		return Jwts.builder()
				.setSubject((userPrincipal.getUsername()))
				.setIssuedAt(new Date())
				.setExpiration(new Date((new Date()).getTime()+jwtExpirationMs))
				.signWith(key(), SignatureAlgorithm.HS256)
				.compact();
	}
	
	public String getUserNameFromJwtToken(String token) {
		return Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(token).getBody().getSubject();
	}
	
	public Key key() {
		return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
	}
	
	public boolean validateJwtToken(String authToken) {
		try {
			Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
			return true;
		}catch(MalformedJwtException e) {
			LOGGER.error("Invalid JWT token: {}", e.getMessage());
		}catch(ExpiredJwtException e) {
			LOGGER.error("JWT token is expired: {}", e.getMessage());
		}catch(UnsupportedJwtException e) {
			LOGGER.error("JWT token is unsupported: {}" ,e.getMessage());
		}catch(IllegalArgumentException e){
			LOGGER.error("JWT claims string is empty: {}" ,e.getMessage());
		}
		return false;
	}
}












