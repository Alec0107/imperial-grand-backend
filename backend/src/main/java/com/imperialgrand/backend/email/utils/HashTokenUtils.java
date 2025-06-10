package com.imperialgrand.backend.email.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class HashTokenUtils {


    public static String generateRandomToken() {
        SecureRandom random = new SecureRandom();
        byte[] token = new byte[16];
        random.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }

    public static String generateSalt(){
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(salt);
    }


    public static String hashToken(String token, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(Base64.getUrlDecoder().decode(salt));
            byte[] hashBytes = digest.digest(Base64.getUrlDecoder().decode(token));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA-256 Algorithm not available", ex);
        }
    }

    public static String hashRefreshToken(String refreshToken, String salt) {
        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(Base64.getUrlDecoder().decode(salt));
            byte[] refreshHashBytes = digest.digest(refreshToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(refreshHashBytes);
        }catch (NoSuchAlgorithmException ex){
            throw new RuntimeException("SHA-256 Algorithm not available", ex);
        }
    }

}
