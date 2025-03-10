package com.example.apigatewayshop.exceptions;

public class EmailAlreadyExistsException extends RuntimeException {
    public EmailAlreadyExistsException(String s) {
        super(s);
    }
}
