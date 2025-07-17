package com.imperialgrand.backend.jwt.repository;

import com.imperialgrand.backend.jwt.model.JwtToken;
import io.jsonwebtoken.Claims;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.Optional;

@Repository
public interface JwtTokenRepository extends JpaRepository<JwtToken, Long> {
    @Query("SELECT t FROM JwtToken t WHERE t.user.userId = :userId AND t.revoked = false")
    Optional<JwtToken> findByUserAndRevokedFalseAndExpiredFalse(@Param("userId") int userId);

    Optional<JwtToken> findByToken(String token);

    @Query(value = "SELECT * FROM jwt_tokens WHERE user_id = :userId AND device_id = :deviceId AND revoked = false", nativeQuery = true)
    Optional<JwtToken> findJwtTokenByDeviceIdAndUserId(@Param("userId") int userId, @Param("deviceId") String deviceId);
}



