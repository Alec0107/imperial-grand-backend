package com.imperialgrand.backend.auth.utils;

import com.imperialgrand.backend.auth.dto.RegisterRequest;

public class FieldsNullChecker {

    public static boolean missingFields(RegisterRequest reg) throws IllegalArgumentException {
        return isBlank(reg.getFirstName()) ||
                isBlank(reg.getLastName()) ||
                isBlank(reg.getEmail()) ||
                isBlank(reg.getPassword()) ||
                isBlank(reg.getPhoneNumber());
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
