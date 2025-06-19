package com.imperialgrand.backend.jwt.model;


import com.imperialgrand.backend.user.model.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.cglib.core.Local;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "jwt_tokens")
public class JwtToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int jwtId;

    @Column(length = 1000)
    private String token;
    private String tokenType;
    private String salt;
    private String deviceId;
    private boolean expired;
    private boolean revoked;
    private boolean rememberMe;
    private LocalDateTime issuedAt;
    private LocalDateTime expiresAt;

    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "userId")
    private User user;
}
