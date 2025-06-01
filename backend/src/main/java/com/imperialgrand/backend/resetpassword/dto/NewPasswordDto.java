package com.imperialgrand.backend.resetpassword.dto;

import lombok.Data;

@Data
public class NewPasswordDto {
    private String token;
    private String tokenId;
    private String newPassword;
}
