package com.imperialgrand.backend.exception;

public class EmailTokenNotFoundException extends RuntimeException {
    public EmailTokenNotFoundException(String message) {
        super(message);
    }
}
