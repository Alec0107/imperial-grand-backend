package com.imperialgrand.backend.email.exception;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class EmailTokenException extends RuntimeException {
    private String status;
}
