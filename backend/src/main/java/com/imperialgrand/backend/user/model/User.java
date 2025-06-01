package com.imperialgrand.backend.user.model;

import com.imperialgrand.backend.email.model.EmailVerificationToken;
import com.imperialgrand.backend.jwt.model.JwtToken;
import com.imperialgrand.backend.resetpassword.model.ResetPasswordToken;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer userId;

    private String firstName;
    private String lastName;
    private String email;
    private String password;
    private String phoneNumber;
    private LocalDate dob;

    @Enumerated(EnumType.STRING)
    private Role role;

    private boolean enabled;
    private LocalDateTime createdAt;
    private  LocalDateTime updatedAt;

    // ⚠️ IMPORTANT:
    // Lombok's @Builder will IGNORE this default value (e.g., new ArrayList<>())
    // unless we explicitly add @Builder.Default.
    // Without @Builder.Default, this field will be null if not set manually in builder().
    // Always use @Builder.Default if you want default values to apply during .build()
    @Builder.Default
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<EmailVerificationToken> emailVerificationTokens = new ArrayList<>();


    @Builder.Default
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<JwtToken> jwtToken = new ArrayList<>();

    @Builder.Default
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ResetPasswordToken> resetPasswordTokens = new ArrayList<>();



    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

}
