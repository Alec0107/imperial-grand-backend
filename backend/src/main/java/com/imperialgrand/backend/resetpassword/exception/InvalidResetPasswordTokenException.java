package com.imperialgrand.backend.resetpassword.exception;

public class InvalidResetPasswordTokenException extends RuntimeException {
    public InvalidResetPasswordTokenException(String message) {
        super(message);
    }
}
