package com.imperialgrand.backend.config;

import com.imperialgrand.backend.filter.JWTAuthenticationFilter;

import lombok.RequiredArgsConstructor;
import org.hibernate.annotations.ConcreteProxy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JWTAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authenticationProvider;

    @Value("${localhost.origin}")
    private String localhostOrigin;



    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http
                .cors(cors -> cors.configurationSource(corsConfiguration()))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth.requestMatchers(
                                                    "/api/v1/auth/register","/api/v1/auth/verify","/api/v1/auth/login",
                                                    "/api/v1/auth/resend-verification","/api/v1/auth/inbox-resend-verification",
                                                    "/api/v1/test/publicHello", "/api/v1/auth/detailsTest", "/api/v1/auth/forgot-password",
                                                    "/api/v1/auth/reset-password", "/api/v1/auth/reset-password/validate", "/api/v1/auth/refresh-token",
                                                    "/api/v1/contact","/api/v1/reservation/availability", "/api/v1/reservation/lock_status", "api/v1/reservation/submit").permitAll() /// PUBLIC: ALLOW WITHOUT TOKEN
//                                                    .requestMatchers("api/v1/reservation/submit").hasRole("USER") /// REQUIRE ROLE: USER MAINLY
                                                    .anyRequest().authenticated()) /// CATCH ALL: A FALLBACK MEANS MUST LOGGED IN
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


    private CorsConfigurationSource corsConfiguration() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:63342", "http://127.0.0.1:5500", "http://localhost:8080",localhostOrigin));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "x-device-id", "x-auth-intent"));
        configuration.setExposedHeaders(List.of("Set-Cookie"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PUT","OPTIONS","PATCH", "DELETE"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
