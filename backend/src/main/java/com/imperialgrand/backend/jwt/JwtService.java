package com.imperialgrand.backend.jwt;

import com.imperialgrand.backend.jwt.exception.InvalidJwtTokenException;
import com.imperialgrand.backend.jwt.model.JwtToken;
import com.imperialgrand.backend.jwt.repository.JwtTokenRepository;
import com.imperialgrand.backend.user.exception.EmailNotFoundException;
import com.imperialgrand.backend.user.exception.EmailNotVerifiedException;
import com.imperialgrand.backend.user.model.User;
import com.imperialgrand.backend.user.repository.UserRepository;
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
import java.util.*;
import java.util.logging.Logger;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final UserRepository userRepository;
    @Value("${jwt.secret}")
    private String secretKey;
    private final JwtTokenRepository jwtTokenRepository;
    private final UserDetailsService userDetailsService;
    private final Logger logger = Logger.getLogger(JwtService.class.getName());

    public String generateToken(User user, long expirationMillis, String tokenType) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("firstname", user.getFirstName());
        claims.put("lastname", user.getLastName());
        claims.put("role", user.getRole());
        claims.put("type", tokenType);

        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getEmail())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationMillis))
                .signWith(getSignKey())
                .compact();

        return token;
    }


    public UserDetails validateAccessToken(String token){
        try{
            // validate if its expired and throw an exception let the filter catches it
            Claims claim = extractAllClaims(token);
            String userEmail = claim.getSubject();
            System.out.println(userEmail);

            // validate if access token is expired
            if(claim.getExpiration().before(new Date())) throw new InvalidJwtTokenException("Access token expired");

            // get the user subject (email in this case) and find in db
            UserDetails userDetails =  userRepository.findByEmail(userEmail).orElseThrow(() -> new EmailNotFoundException("Email not found"));

            logger.info("Access token validated for: {" + userEmail+ "}");

            // returnm the user details object
            return userDetails;

        }catch (JwtException e){
            throw new InvalidJwtTokenException(e.getMessage());
        }
    }

    public Claims extractAllClaims(String token){
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

    public String getUserEmail(String token) {
        Claims claims = extractAllClaims(token);
        return claims.getSubject();
    }





}
