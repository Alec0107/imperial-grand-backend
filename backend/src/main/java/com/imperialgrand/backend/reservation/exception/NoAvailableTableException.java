package com.imperialgrand.backend.reservation.exception;

public class NoAvailableTableException extends RuntimeException {
    public NoAvailableTableException(String message) {
        super(message);
    }
}
