package com.imperialgrand.backend.reservation.exception;

public class ReservationLockNotFoundException extends RuntimeException {
    public ReservationLockNotFoundException(String message) {
        super(message);
    }
}
