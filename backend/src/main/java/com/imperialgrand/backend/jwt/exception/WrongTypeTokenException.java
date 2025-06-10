package com.imperialgrand.backend.jwt.exception;

public class WrongTypeTokenException extends RuntimeException {
    public WrongTypeTokenException(String message) {
        super(message);
    }
}
