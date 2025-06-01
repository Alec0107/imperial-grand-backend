package com.imperialgrand.backend.email.exception;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class EmailTokenExpiredException extends RuntimeException {
    private int tokenId;
    private String status;
}
