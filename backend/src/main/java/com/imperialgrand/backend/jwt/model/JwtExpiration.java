package com.imperialgrand.backend.jwt.model;

public enum JwtExpiration {
    ACCESS_TOKEN(1000L * 60 * 1),
    REFRESH_TOKEN_DEFAULT(1000L * 60 * 3),
    REFRESH_TOKEN_REMEMBER(1000L * 60 * 5);

    private final long expirationMillis;

    JwtExpiration(long expirationMillis) {
        this.expirationMillis = expirationMillis;
    }

    public long getExpirationMillis() {
        return expirationMillis;
    }
}
