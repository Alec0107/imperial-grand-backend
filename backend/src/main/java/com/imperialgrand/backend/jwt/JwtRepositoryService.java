package com.imperialgrand.backend.jwt;

import com.imperialgrand.backend.jwt.exception.MissingRefreshTokenException;
import com.imperialgrand.backend.jwt.model.JwtToken;
import com.imperialgrand.backend.jwt.model.TokenType;
import com.imperialgrand.backend.jwt.repository.JwtTokenRepository;
import com.imperialgrand.backend.user.model.User;
import lombok.Builder;
import lombok.Data;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;

@Data
@Builder
@Repository
public class JwtRepositoryService {

    private final JwtTokenRepository tokenRepository;

    public JwtToken getMatchingTokenFromDb(int userId){
        return tokenRepository.findByUserAndRevokedFalseAndExpiredFalse(userId)
                .orElseThrow(()-> new MissingRefreshTokenException("Refresh token is missing."));
    }

    public void saveOldToken(JwtToken token){
        tokenRepository.save(token);
    }

    public void saveNewToken(String jwtToken, String salt, User userObject, String deviceId, boolean rememberMe) {
        // make an instance of jwtObject

        LocalDateTime expiryDate = rememberMe ? LocalDateTime.now().plus(Duration.ofMinutes(3)) : LocalDateTime.now().plus(Duration.ofMinutes(2));

        JwtToken jwtTokenObject = JwtToken.builder()
                .token(jwtToken)
                .tokenType(TokenType.REFRESH_TOKEN.toString())
                .salt(salt)
                .deviceId(deviceId)
                .expired(false)
                .revoked(false)
                .rememberMe(rememberMe)
                .issuedAt(LocalDateTime.now())
                .expiresAt(expiryDate)
                .user(userObject)
                .build();
        // save jwt object in db
        tokenRepository.save(jwtTokenObject);
    }

    public JwtToken getTokenByUserIdAndDeviceId(int userId, String deviceId) {
       return tokenRepository.findJwtTokenByDeviceIdAndUserId(userId, deviceId)
                .orElseThrow(()-> new MissingRefreshTokenException("Refresh token is missing."));
    }


}
