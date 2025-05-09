package com.imperialgrand.backend.jwt;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface JwtTokenRepository extends JpaRepository<JwtToken, Long> {
    @Query("SELECT t FROM JwtToken t WHERE t.user.userId = :userId AND t.revoked = false AND t.expired = false")
    Optional<JwtToken> findByUserAndRevokedFalseAndExpiredFalse(@Param("userId") int userId);
    Optional<JwtToken> findByToken(String token);
}
