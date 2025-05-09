package com.imperialgrand.backend.auth;

import com.imperialgrand.backend.dto.LoginRequest;
import com.imperialgrand.backend.dto.RegisterRequest;
import com.imperialgrand.backend.dto.ResetPasswordRequest;
import com.imperialgrand.backend.responseWrapper.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<String>> register(@RequestBody RegisterRequest registerRequest) {
        ApiResponse<String> response = authService.register(registerRequest);
        return ResponseEntity.ok(response);
    }

    // To verify user's email when clicking the email verification link in user's email inbox
    @GetMapping("/verify")
    public ResponseEntity<String> verify(@RequestParam("token") String rawToken,
                                         @RequestParam("id") Integer tokenId) {
        authService.verifyEmailToken(rawToken, tokenId);
        return ResponseEntity.ok("Email verified successfully!");
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<String>> login(@RequestBody LoginRequest loginRequest) {
        ApiResponse<String> response =  authService.login(loginRequest);
        return ResponseEntity.ok(response);
    }


    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(HttpServletRequest request) {
        ApiResponse<String> response = authService.logout(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<ApiResponse<String>> resendVerification(@RequestParam("email") String userEmail) {
        ApiResponse<String> response = authService.resendVerificationToken(userEmail);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    public void forgotPassword() {

    }

    @PostMapping("/reset-password")
    public void resetPassword(@RequestBody ResetPasswordRequest resetPasswordRequest) {

    }

    @GetMapping("/profile")
    public void getProfile() {

    }


}
