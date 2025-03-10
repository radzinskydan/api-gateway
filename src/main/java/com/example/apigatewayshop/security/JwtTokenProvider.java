package com.example.apigatewayshop.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import java.util.Date;

@Component
public class JwtTokenProvider {
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private int jwtExpiration;
    private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);

    public String generateToken(Authentication authentication) {
        log.info("Generating token for authentication: {}", authentication);

        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();
        log.info("User principal: {}", userPrincipal);

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);

        log.info("Token details: Issued at {}, Expiration date {}", now, expiryDate);

        String token = Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(Keys.hmacShaKeyFor(jwtSecret.getBytes()))
                .compact();

        log.info("Generated token: {}", token);

        return token;
    }

    public String getUsernameFromToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes()))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return claims.getSubject();
        } catch (Exception e) {
            throw new RuntimeException("Неверный JWT токен");
        }
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes()))
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (SignatureException ex) {
            throw new RuntimeException("Неверная подпись JWT");
        } catch (MalformedJwtException ex) {
            throw new RuntimeException("Неверный JWT токен");
        } catch (ExpiredJwtException ex) {
            throw new RuntimeException("JWT токен истек");
        } catch (UnsupportedJwtException ex) {
            throw new RuntimeException("JWT токен не поддерживается");
        } catch (IllegalArgumentException ex) {
            throw new RuntimeException("JWT claims строка пуста");
        }
    }
}
