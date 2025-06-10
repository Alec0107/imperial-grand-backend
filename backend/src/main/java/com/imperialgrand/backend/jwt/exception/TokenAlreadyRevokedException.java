package com.imperialgrand.backend.jwt.exception;

public class TokenAlreadyRevokedException extends RuntimeException {
    public TokenAlreadyRevokedException(String message) {
        super(message);
    }
}
