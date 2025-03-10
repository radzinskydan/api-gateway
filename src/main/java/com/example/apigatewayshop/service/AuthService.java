package com.example.apigatewayshop.service;

import com.example.apigatewayshop.exceptions.EmailAlreadyExistsException;
import com.example.apigatewayshop.exceptions.UserAlreadyExistsException;
import com.example.apigatewayshop.model.User;
import com.example.apigatewayshop.repository.AuthRepository;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
public class AuthService {

    private final AuthRepository authRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(AuthRepository authRepository, PasswordEncoder passwordEncoder) {
        this.authRepository = authRepository;
        this.passwordEncoder = passwordEncoder;
    }


    public Optional<User> createUser(User user) {
        if (authRepository.findByUsername(user.getUsername()).isPresent()) {
            throw new UserAlreadyExistsException("Пользователь с таким именем уже существует.");
        }

        if (authRepository.findByEmail(user.getEmail()).isPresent()) {
            throw new EmailAlreadyExistsException("Пользователь с такой электронной почтой уже существует.");
        }

        return Optional.of(createUserWithRole(user, "ROLE_USER"));
    }

    public Optional<User> createAdmin(User user) {

        return Optional.of(createUserWithRole(user, "ROLE_ADMIN"));
    }

    private User createUserWithRole(User user, String role) {
        User newUser = new User();
        newUser.setUsername(user.getUsername());
        newUser.setBalance(user.getBalance());
        newUser.setPassword(passwordEncoder.encode(user.getPassword()));
        newUser.setEmail(user.getEmail());
        List<String> roles = Collections.singletonList(role);
        newUser.setRoles(roles);

        return authRepository.save(newUser);
    }

    public Optional<User> getUserById(Long id) {
        return authRepository.findById(id);
    }


    public Optional<User> findByUsername(String username) {
        return authRepository.findByUsername(username);
    }

    public boolean deleteUser(Long id) {
        if (authRepository.existsById(id)) {
            authRepository.deleteById(id);
            return true;
        }
        return false;
    }

    public List<User> getAllUsers() {
        return authRepository.findAll();
    }

}
