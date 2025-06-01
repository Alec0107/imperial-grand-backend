package com.imperialgrand.backend.resetpassword.repository;

import com.imperialgrand.backend.resetpassword.model.ResetPasswordToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ResetPasswordTokenRepository extends JpaRepository<ResetPasswordToken, Integer> {

}
