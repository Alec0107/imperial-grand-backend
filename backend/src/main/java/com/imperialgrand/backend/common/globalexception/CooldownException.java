package com.imperialgrand.backend.common.globalexception;

public class CooldownException extends RuntimeException {
    public CooldownException(String message) {
        super(message);
    }
}
