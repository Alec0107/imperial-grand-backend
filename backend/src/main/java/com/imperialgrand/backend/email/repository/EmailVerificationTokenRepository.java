package com.imperialgrand.backend.email.repository;

import com.imperialgrand.backend.email.model.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Integer> {
    Optional<EmailVerificationToken> findByToken(String token);
    Optional<EmailVerificationToken> findByUser_userId(Integer userId);
    void deleteByUser_userId(Integer userId);
}
