package com.imperialgrand.backend.dto_response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class SignUpResponse {
    private String email;
    private String message;
    private LocalDateTime expiryTime;
}
