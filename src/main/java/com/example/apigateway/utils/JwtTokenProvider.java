package com.example.apigateway.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String jwtSecret;

    private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);

    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(jwtSecret.getBytes())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Authentication getAuthentication(String token) {
        log.info("Получение аутентификации из JWT токена: {}", token);

        Claims claims = parseClaims(token);
        log.info("JWT Claims: {}", claims);

        String username = claims.getSubject();
        log.info("Имя пользователя из токена: {}", username);

        String rolesString = claims.get("roles", String.class);
        log.info("Роли из токена: {}", rolesString);

        if (rolesString == null || rolesString.isEmpty()) {
            log.error("Поле 'roles' отсутствует или пустое в JWT токене");
            throw new RuntimeException("Поле 'roles' отсутствует или пустое в JWT токене");
        }

        List<GrantedAuthority> authorities = Arrays.stream(rolesString.split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        log.info("Список ролей: {}", authorities);

        UserDetails userDetails = new User(username, "", authorities);
        log.info("Создание UserDetails для аутентификации");

        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
        log.info("Аутентификация успешно получена");

        return authentication;
    }


    public boolean validateToken(String token) {
        try {
            parseClaims(token);
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

