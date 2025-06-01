package com.imperialgrand.backend.common.utils;

public class InputValidator {

    private static String EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@(.+)$";
    private static String PASS_REGEX = "^(?=.*[A-Z])(?=.*[a-z])(?=.*[\\d]).{8,}$";


    public static void validateEmail(String email) {
        if(email == null || !email.matches(EMAIL_REGEX)) {
            throw new IllegalArgumentException("Invalid email format");
        }
    }

    public static void validatePassword(String password) {
        if(password == null || !password.matches(PASS_REGEX)) {
            throw new IllegalArgumentException("Password must have at least 8 characters, 1 lowercase, 1 uppercase, and 1 digit");
        }
    }

    public static void validatePhoneNumber(String username) {}

}
