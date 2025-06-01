package com.imperialgrand.backend.email.model;

import com.imperialgrand.backend.user.model.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "email_verification_table")
public class EmailVerificationToken{

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer emailTokenId;

    private String token;
    private String plainToken;
    private String salt;

    private LocalDateTime expiryTime ;
    private LocalDateTime createdAt;
    private boolean used;


    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "userId")
    private User user;



}
