package com.example.demo.utils;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenUtil {

    private static final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_TIME = 86400000; // 24 hours
    private static final long RESET_TOKEN_EXPIRATION = 3600000; // 1 hour
    public static final String CLAIM_ROLE = "role";
    public static final String CLAIM_TYPE = "type";
    public static final String TYPE_ACCESS = "access";
    public static final String TYPE_RESET = "reset";

    public static String generateToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY, SignatureAlgorithm.HS256)
                .compact();
    }

    public static String generateTokenWithRole(String email, String role) {
        return Jwts.builder()
                .setSubject(email)
                .claim(CLAIM_ROLE, role != null ? role : "USER")
                .claim(CLAIM_TYPE, TYPE_ACCESS)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY, SignatureAlgorithm.HS256)
                .compact();
    }

    public static String generateResetToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .claim(CLAIM_TYPE, TYPE_RESET)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + RESET_TOKEN_EXPIRATION))
                .signWith(SECRET_KEY, SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    public String extractEmail(String token) {
        return getClaims(token).getSubject();
    }

    public String extractRole(String token) {
        Object role = getClaims(token).get(CLAIM_ROLE);
        return role != null ? role.toString() : "USER";
    }

    public boolean isAccessToken(String token) {
        try {
            Object type = getClaims(token).get(CLAIM_TYPE);
            return TYPE_ACCESS.equals(type);
        } catch (Exception e) {
            return false;
        }
    }

    private Claims getClaims(String token) {
        JwtParser jwtParser = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build();
        return jwtParser.parseClaimsJws(token).getBody();
    }

    private boolean isTokenExpired(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }
}
