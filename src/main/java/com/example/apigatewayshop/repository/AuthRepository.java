package com.example.apigatewayshop.repository;

import com.example.apigatewayshop.model.User;
import org.springframework.data.jpa.repository.JpaRepository;


import java.util.Optional;

public interface AuthRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    Optional<Object> findByEmail(String email);
}
