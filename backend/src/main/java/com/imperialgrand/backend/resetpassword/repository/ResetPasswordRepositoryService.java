package com.imperialgrand.backend.resetpassword.repository;


import com.imperialgrand.backend.resetpassword.exception.InvalidResetPasswordTokenException;
import com.imperialgrand.backend.resetpassword.model.ResetPasswordToken;
import lombok.Data;
import org.springframework.stereotype.Repository;

@Data
@Repository
public class ResetPasswordRepositoryService {

    private final ResetPasswordTokenRepository resetRepository;

    public void saveResetPasswordToken(ResetPasswordToken resetPasswordToken) {
        resetRepository.save(resetPasswordToken);
    }

    public ResetPasswordToken getResetPasswordTokenById(int tokenId) {
        return resetRepository.findById(tokenId)
                .orElseThrow(()-> new InvalidResetPasswordTokenException("Invalid reset token. Reset token not found."));
    }


}
