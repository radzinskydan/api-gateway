package com.example.apigatewayshop.controller;

import com.example.apigatewayshop.payload.AuthResponse;
import com.example.apigatewayshop.payload.LoginRequest;
import com.example.apigatewayshop.repository.AuthRepository;
import com.example.apigatewayshop.security.JwtTokenProvider;
import com.example.apigatewayshop.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
import com.example.apigatewayshop.model.User;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final AuthService authService;
    private final JwtTokenProvider tokenProvider;
    private final AuthRepository authRepository;

    public AuthController(AuthenticationManager authenticationManager, AuthService authService, JwtTokenProvider tokenProvider, AuthRepository authRepository) {
        this.authenticationManager = authenticationManager;
        this.authService = authService;
        this.tokenProvider = tokenProvider;
        this.authRepository = authRepository;
    }


    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = tokenProvider.generateToken(authentication);

        User user = authRepository.findByUsername(loginRequest.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("Пользователь не найден"));

        AuthResponse response = AuthResponse.builder()
                .token(jwt)
                .username(user.getUsername())
                .build();

        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User user) {
        return authService.createUser(user)
                .map(newUser -> {
                    AuthResponse response = AuthResponse.builder()
                            .username(newUser.getUsername())
                            .build();
                    return ResponseEntity.status(HttpStatus.CREATED).body(response);
                })
                .orElse(ResponseEntity.badRequest().build());
    }

    @GetMapping("/getById")
    public ResponseEntity<?> getUser(@RequestParam Long userId) {
        return ResponseEntity.ok(authService.getUserById(userId));
    }

//    @GetMapping("/me")
//    public ResponseEntity<?> getCurrentUser(HttpServletRequest request) {
//        try {
//            String token = request.getHeader("Authorization");
//            if (token != null && token.startsWith("Bearer ")) {
//                token = token.substring(7);
//                String username = tokenProvider.getUsernameFromToken(token);
//
//                User user = authRepository.findByUsername(username)
//                        .orElseThrow(() -> new UsernameNotFoundException("Пользователь не найден"));
//
//                return ResponseEntity.ok(AuthResponse.builder()
//                        .username(user.getUsername())
//                        .build());
//            }
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
//                    .body(Map.of("error", "Токен не найден"));
//        } catch (Exception e) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
//                    .body(Map.of("error", e.getMessage()));
//        }
//    }
}
