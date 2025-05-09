package com.imperialgrand.backend.auth;

import com.imperialgrand.backend.dto.LoginRequest;
import com.imperialgrand.backend.dto.RegisterRequest;
import com.imperialgrand.backend.email.EmailService;
import com.imperialgrand.backend.email.EmailVerificationToken;
import com.imperialgrand.backend.email.EmailVerificationTokenRepository;
import com.imperialgrand.backend.exception.*;
import com.imperialgrand.backend.jwt.JwtService;
import com.imperialgrand.backend.jwt.JwtToken;
import com.imperialgrand.backend.jwt.JwtTokenRepository;
import com.imperialgrand.backend.jwt.TokenType;
import com.imperialgrand.backend.responseWrapper.ApiResponse;
import com.imperialgrand.backend.user.Role;
import com.imperialgrand.backend.user.User;
import com.imperialgrand.backend.user.UserRepository;
import com.imperialgrand.backend.email.EmailTokenGenerator;
import com.imperialgrand.backend.utils.InputValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;


import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtService jwtService;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtTokenRepository jwtTokenRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;

    // For registration
    public ApiResponse<String> register(RegisterRequest registerRequest) {

        Optional<User> user = userRepository.findByEmail(registerRequest.getEmail());

        // If email is already in use. Hence, throw an exception.
        if(user.isPresent()) {
            throw new EmailAlreadyUsedException("Email is already in use.");
        }

        // If any fields are missing then throw an exception.
        if(missingFields(registerRequest) == true){
            throw new IllegalArgumentException("Missing required fields.");
        }

        // Validate email and pass using RegEx
        InputValidator.validateEmail(registerRequest.getEmail());
        InputValidator.validatePassword(registerRequest.getPassword());


        // Saves user data into database
        var userData = User.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .phoneNumber(registerRequest.getPhoneNumber())
                .dob(registerRequest.getDob())
                .role(Role.USER)
                .enabled(false)
                .createdAt(LocalDateTime.now())
                .build();

        userRepository.save(userData);

        // Must be converted back to byte array in order to use for validation later
        // Generate token for email verification link
        String token = EmailTokenGenerator.generateRandomToken();
        // Generate salt for email verification link
        String salt = EmailTokenGenerator.generateSalt();

        // generate token and save in db
       EmailVerificationToken emailToken = emailVerificationTokenRepository.save(generateEmailToken(userData, token, salt));

        // Send email verification link
        String message = emailService.sendSimpleEmailVerif(registerRequest, token, emailToken.getEmailTokenId());


        return new ApiResponse<>(message, "Registration successful.");
    }

    private boolean missingFields(RegisterRequest reg) throws IllegalArgumentException {
        return isBlank(reg.getFirstName()) ||
                isBlank(reg.getLastName()) ||
                isBlank(reg.getEmail()) ||
                isBlank(reg.getPassword()) ||
                isBlank(reg.getPhoneNumber()) ||
                reg.getDob() == null;
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    // Verifying email verification token
    public void verifyEmailToken(String rawToken, int tokenId){
        EmailVerificationToken emailToken = emailVerificationTokenRepository.getReferenceById(tokenId);

        if(emailToken == null){
            throw new EmailTokenNotFoundException("Email token not found");
        }

        String salt = emailToken.getSalt();
        String hashedEmailToken = emailToken.getToken();
        String rawTokenHashed = EmailTokenGenerator.hashToken(rawToken, salt);

        if(!hashedEmailToken.equals(rawTokenHashed)){
            throw new IllegalArgumentException("Invalid email token");
        }

        if(emailToken.isUsed()){
            throw new IllegalStateException("Token already used");
        }

        // sends this to user and let user decide to whether resend an email verification
        if(emailToken.getExpiryTime().isBefore(LocalDateTime.now())){
            throw new IllegalArgumentException("Token expired");
        }

        emailToken.setUsed(true);
        User user = emailToken.getUser();
        user.setEnabled(true);

        userRepository.save(user);
        emailVerificationTokenRepository.delete(emailToken);
    }

    public ApiResponse<String> login(LoginRequest loginRequest) {
        String jwtToken = null;
        Optional<User> user = userRepository.findByEmail(loginRequest.getEmail());


        if(!user.isPresent()) {
            throw new EmailNotFoundException("Email not found");
        }

        if(user.get().isEnabled() == false) {
            throw new EmailNotVerifiedException("Email not verified. Please verify your email before logging in.");
        }

        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
            User userObject = user.get();

            // Check db if user already has the jwt token
            Optional<JwtToken> jwt = jwtTokenRepository.findByUserAndRevokedFalseAndExpiredFalse(user.get().getUserId());

            // if jwt is not in db / jwt is expired / jwt is revoked => generate token and send back ton the user
            if(jwt.isEmpty() || jwt.get().isExpired() || jwt.get().isRevoked()) {
                jwtToken = jwtService.generateToken(userObject);
                saveJwtToken(jwtToken, userObject);
            }

            jwtToken = jwt.get().getToken();

        }catch(BadCredentialsException ex){
            throw new BadCredentialsException("Bad credentials", ex);
        }

        return new ApiResponse<>(jwtToken, "Login successful.");
    }

    private void saveJwtToken(String jwtToken, User userObject) {
        // make an instance of jwtObject
        JwtToken jwtTokenObject = JwtToken.builder()
                .token(jwtToken)
                .tokenTyp(TokenType.BEARER.toString())
                .expired(false)
                .revoked(false)
                .issuedAt(LocalDateTime.now())
                .user(userObject)
                .build();
        // save jwt object in db
        jwtTokenRepository.save(jwtTokenObject);
    }

    public ApiResponse<String> logout(HttpServletRequest request) {
       String authHeader = request.getHeader("Authorization");

       // check the header if it has the bearer token
       if(authHeader == null || !authHeader.startsWith("Bearer ")) {
           throw new InvalidJwtTokenException("Missing or invalid Authorization header");
       }

       String jwtToken = authHeader.substring(7);
       Optional<JwtToken> jwtTokenOptional = jwtTokenRepository.findByToken(jwtToken);
       if(!jwtTokenOptional.isPresent()) {
           throw new InvalidJwtTokenException("Invalid token. Token not found");
       }

       JwtToken jwtTokenObject = jwtTokenOptional.get();
       jwtTokenObject.setRevoked(true);
       jwtTokenObject.setExpired(true);
       jwtTokenRepository.save(jwtTokenObject);

       return new ApiResponse<>("" ,"Logout successful.");
    }





    @Transactional
    public ApiResponse<String> resendVerificationToken(String email) {

        LocalDateTime now = LocalDateTime.now();

        Optional<User> userOpt = userRepository.findByEmail(email);
        if(!userOpt.isPresent()) {
            throw new EmailNotFoundException("Email not found");
        }

        User user = userOpt.get();



        Optional<EmailVerificationToken> tokenOp = emailVerificationTokenRepository.findByUser_userId(user.getUserId());

        String emailTokenToSend = null;
        int tokenId = 0;

        if(!tokenOp.isPresent()) {

                // No token exists, generate a new one
                // Must be converted back to byte array in order to use for validation later
                // Generate token for email verification link
                String tokenPlain = EmailTokenGenerator.generateRandomToken();
                // Generate salt for email verification link
                String salt = EmailTokenGenerator.generateSalt();

                EmailVerificationToken emailToken = generateEmailToken(user, tokenPlain, salt);
                emailTokenToSend = emailToken.getPlainToken();
                tokenId = emailToken.getEmailTokenId();
                System.out.println("Token is not in db.. Generating new token..");

        }else {
            EmailVerificationToken token = tokenOp.get();

            // If still in cooldown throw an exception
            if(token.getCreatedAt().isAfter(now.minusMinutes(1))){
                // throw cooldown exception (user must wait for 1 minute to receive another email verification link)
                throw new CooldownException("Please wait before requesting another verification link. You can try again in 1 minute.");
            }

                if(token.getExpiryTime().isBefore(LocalDateTime.now()) ) {
                    // Delete old token
                    emailVerificationTokenRepository.deleteByUser_userId(user.getUserId());
                    // Must be converted back to byte array in order to use for validation later
                    // Generate token for email verification link
                    String tokenPlain = EmailTokenGenerator.generateRandomToken();
                    // Generate salt for email verification link
                    String salt = EmailTokenGenerator.generateSalt();

                    EmailVerificationToken emailToken = generateEmailToken(user, tokenPlain, salt);

                    emailTokenToSend = emailToken.getPlainToken();
                    tokenId = emailToken.getEmailTokenId();
                    System.out.println("Generating new token..");
                }else{
                    emailTokenToSend = token.getPlainToken();
                    tokenId = token.getEmailTokenId();
                    System.out.println("Reusing Token..");
                }
        }


        String message = emailService.resendSimpleEmailVerif(user, emailTokenToSend, tokenId);
        return new ApiResponse<>(message, "New verification link was sent successfully.");
    }




    private EmailVerificationToken generateEmailToken(User userData, String token, String salt) {
        // Generate the HashToken which will be included in the URL
        String hashedEmailToken = EmailTokenGenerator.hashToken(token, salt);

        EmailVerificationToken newToken = EmailVerificationToken.builder()
                .token(hashedEmailToken)
                .plainToken(token)
                .salt(salt)
                .expiryTime(LocalDateTime.now().plusMinutes(1))
                .createdAt(LocalDateTime.now())
                .used(false)
                .user(userData)
                .build();

        emailVerificationTokenRepository.save(newToken);

        return newToken;
    }
}






























