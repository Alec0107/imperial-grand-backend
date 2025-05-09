package com.imperialgrand.backend.jwt;

import com.imperialgrand.backend.exception.InvalidJwtTokenException;
import com.imperialgrand.backend.user.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;
    private final JwtTokenRepository jwtTokenRepository;
    private final UserDetailsService userDetailsService;

    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();


        claims.put("subject", user.getEmail());
        claims.put("firstname", user.getFirstName());
        claims.put("lastname", user.getLastName());
        claims.put("dob", user.getDob().toString());
        claims.put("role", user.getRole());

        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignKey())
                .compact();

        return token;
    }



    public UserDetails validateAndLoadUserFromToken(String token) {
        UserDetails userDetails = null;

        try{
            // fetch the token to see if it is in the db
            Optional<JwtToken> tokenDb = jwtTokenRepository.findByToken(token);

            // to check if token is in the db
            if(!tokenDb.isPresent()){
                throw new InvalidJwtTokenException("Invalid JWT token");
            }

            // to check if token is revoked
            if(tokenDb.get().isRevoked()){
                throw new InvalidJwtTokenException("Your session has been revoked. Please log in again.");
            }

            // to check if token is not expired
            if(isTokenExpired(token)){
                throw new InvalidJwtTokenException("Your session has expired. Please log in again.");
            }

            String userEmail = getUserEmail(token);

            // to check if the email from token is in the db then return in filter
            userDetails = userDetailsService.loadUserByUsername(userEmail);

        }catch (JwtException e){
            throw new InvalidJwtTokenException(e.getMessage());
        }



        return userDetails;
    }

    private boolean isTokenExpired(String token) {
        Claims claims = extractAllClaims(token);
        return claims.getExpiration().before(new Date());
    }

    private String getUserEmail(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("subject", String.class);
    }


    private Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignKey(){
        byte[] keyBytes = Base64.getDecoder().decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
