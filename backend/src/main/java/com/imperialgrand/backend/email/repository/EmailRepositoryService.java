package com.imperialgrand.backend.email.repository;

import com.imperialgrand.backend.email.exception.EmailTokenException;
import com.imperialgrand.backend.email.exception.EmailTokenExpiredException;
import com.imperialgrand.backend.email.model.EmailVerificationToken;
import com.imperialgrand.backend.user.model.User;
import lombok.Data;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Data
@Repository
public class EmailRepositoryService {

    private final EmailVerificationTokenRepository emailRepository;

    public EmailVerificationToken saveEmailVerifToken(User userData, String hashedEmailToken, String plainToken, String salt){

        EmailVerificationToken newToken = EmailVerificationToken.builder()
                .token(hashedEmailToken)
                .salt(salt)
                .plainToken(plainToken)
                .expiryTime(LocalDateTime.now().plusMinutes(1))
                .createdAt(LocalDateTime.now())
                .used(false)
                .user(userData)
                .build();

       return emailRepository.save(newToken);
    }

    public EmailVerificationToken getEmailVerificationToken(int tokenId){
        return emailRepository.findById(tokenId)
                .orElseThrow(()-> EmailTokenException.builder().status("invalid").build());
    }

    public Optional<EmailVerificationToken> getByUserId(int userId){
        return emailRepository.findByUser_userId(userId);
    }

    public void isEmailTokenExpired(LocalDateTime expiryTime, int tokenId){
        if(expiryTime.isBefore(LocalDateTime.now())){
            System.out.println("Email token expired");
            throw EmailTokenExpiredException.builder().tokenId(tokenId).status("expired").build();
        }
    }
}
