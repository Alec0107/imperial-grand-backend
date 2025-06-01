package com.imperialgrand.backend.auth;

import com.imperialgrand.backend.auth.dto.LoginRequest;
import com.imperialgrand.backend.auth.dto.RegisterRequest;
import com.imperialgrand.backend.common.globalexception.CooldownException;
import com.imperialgrand.backend.jwt.exception.InvalidJwtTokenException;
import com.imperialgrand.backend.resetpassword.dto.NewPasswordDto;
import com.imperialgrand.backend.dto_response.SignUpResponse;
import com.imperialgrand.backend.email.utils.EmailSenderService;
import com.imperialgrand.backend.email.model.EmailVerificationToken;
import com.imperialgrand.backend.email.repository.EmailVerificationTokenRepository;
import com.imperialgrand.backend.user.exception.EmailAlreadyUsedException;
import com.imperialgrand.backend.email.exception.EmailAlreadyVerifiedException;
import com.imperialgrand.backend.email.exception.EmailTokenException;
import com.imperialgrand.backend.email.exception.EmailTokenExpiredException;
import com.imperialgrand.backend.resetpassword.exception.InvalidResetPasswordTokenException;
import com.imperialgrand.backend.resetpassword.exception.TokenExpiredException;
import com.imperialgrand.backend.jwt.JwtService;
import com.imperialgrand.backend.jwt.model.JwtToken;
import com.imperialgrand.backend.jwt.repository.JwtTokenRepository;
import com.imperialgrand.backend.jwt.model.TokenType;
import com.imperialgrand.backend.resetpassword.model.ResetPasswordToken;
import com.imperialgrand.backend.resetpassword.repository.ResetPasswordTokenRepository;
import com.imperialgrand.backend.common.response.ApiResponse;
import com.imperialgrand.backend.user.exception.EmailNotFoundException;
import com.imperialgrand.backend.user.exception.EmailNotVerifiedException;
import com.imperialgrand.backend.user.model.Role;
import com.imperialgrand.backend.user.model.User;
import com.imperialgrand.backend.user.repository.UserRepository;
import com.imperialgrand.backend.email.utils.EmailTokenGenerator;
import com.imperialgrand.backend.common.utils.InputValidator;
import com.imperialgrand.backend.common.utils.MaskUserEmail;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;


import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtService jwtService;
    private final EmailSenderService emailService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtTokenRepository jwtTokenRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final ResetPasswordTokenRepository resetPasswordTokenRepository;

    // For registration
    public ApiResponse<SignUpResponse> register(RegisterRequest registerRequest) {

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
       EmailVerificationToken emailToken = generateEmailToken(userData, token, salt);

        // Send email verification link
        String message = emailService.sendSimpleEmailVerif(registerRequest, token, emailToken.getEmailTokenId());

        var signUpResponse = SignUpResponse.builder()
                .email(userData.getEmail())
                .message(message)
                .expiryTime(emailToken.getExpiryTime())
                .build();


        return new ApiResponse<>(signUpResponse, "Registration successful.");
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
        // wrap with entitynotfoundexception if getrefbyid is not found it throws an exception !!!
        try {
            // Might return a proxy — exception only thrown on access!
            EmailVerificationToken emailToken = emailVerificationTokenRepository.getReferenceById(tokenId);
            emailToken.getSalt(); // Force initialization to trigger exception early

            String salt = emailToken.getSalt();
            String hashedEmailToken = emailToken.getToken();
            String rawTokenHashed = EmailTokenGenerator.hashToken(rawToken, salt);

            if(emailToken.getUser().isEnabled()){
                throw EmailTokenException.builder().status("verified").build();
            }

            // sends this to user and let user decide to whether resend an email verification
            if(emailToken.getExpiryTime().isBefore(LocalDateTime.now())){
                System.out.println("Email token expired");
                throw EmailTokenExpiredException.builder().tokenId(tokenId).status("expired").build();
            }

            if(!hashedEmailToken.equals(rawTokenHashed)){
                System.out.println("Email token mismatched");
                throw EmailTokenException.builder().status("invalid").build();
            }

            emailToken.setUsed(true);
            User user = emailToken.getUser();
            user.setEnabled(true);

            userRepository.save(user);
            // emailVerificationTokenRepository.delete(emailToken);
        } catch (EntityNotFoundException ex) {
            throw EmailTokenException.builder().status("invalid").build();
        }


    }

    public ApiResponse<String> login(LoginRequest loginRequest) {
        String jwtToken = null;
        Optional<User> user = userRepository.findByEmail(loginRequest.getEmail());


        if(!user.isPresent()) {
            throw new EmailNotFoundException("Email not found");
        }

        if(user.get().isEnabled() == false) {
            throw new EmailNotVerifiedException("Email is not verified.");
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
            }else{
                jwtToken = jwt.get().getToken();
            }

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
    public ApiResponse<SignUpResponse> resendVerificationToken(String email) {

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiry;

        Optional<User> userOpt = userRepository.findByEmail(email);
        if(!userOpt.isPresent()) {
            throw new EmailNotFoundException("Email not found");
        }

        User user = userOpt.get();

        if(user.isEnabled()){
            throw new EmailAlreadyVerifiedException("Your email is already verified. Please log in.");
        }



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
                expiry = emailToken.getExpiryTime();

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
                    expiry = emailToken.getExpiryTime();
                    System.out.println("Generating new token..");
            }else{
                    emailTokenToSend = token.getPlainToken();
                    tokenId = token.getEmailTokenId();
                    expiry = token.getExpiryTime();
                    System.out.println("Reusing Token..");
            }
        }


        String message = emailService.resendSimpleEmailVerif(user, emailTokenToSend, tokenId);

        var signUpResponse = SignUpResponse.builder()
                .email(email)
                .message(message)
                .expiryTime(expiry)
                .build();

        return new ApiResponse<>(signUpResponse, "New verification link was sent successfully.");
    }

    // Another resend email verification link when user sends a request from inbox (gmail)
    // using tokenId to get the user object reference
    @Transactional
    public ApiResponse<SignUpResponse> resendVerificationToken(int tokenId){
       User user = null;
        try{
            EmailVerificationToken emailToken = emailVerificationTokenRepository.getReferenceById(tokenId);
            user = emailToken.getUser();
        }catch (EntityNotFoundException ex){
            System.out.println(ex.getMessage());
        }

        if(user == null){
            System.out.println("User not found");
        }

        // delete the previous/expired email verif token
        emailVerificationTokenRepository.deleteByUser_userId(user.getUserId());

        // generate a new one and send back to user's email inbox (link)
        String tokenPlain = EmailTokenGenerator.generateRandomToken();
        String salt = EmailTokenGenerator.generateSalt();

        EmailVerificationToken newEmailToken = generateEmailToken(user, tokenPlain, salt);
        String message = emailService.resendSimpleEmailVerif(user, newEmailToken.getPlainToken(), newEmailToken.getEmailTokenId());
        // mask user's email
        String maskedUserEmail = MaskUserEmail.maskUserEmail(user.getEmail());
        var signUpResponse = SignUpResponse.builder()
                .email(maskedUserEmail)
                .message(message)
                .expiryTime(newEmailToken.getExpiryTime())
                .build();

        return new ApiResponse<>(signUpResponse, "New verification link was sent successfully.");
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

    //
    public ApiResponse<String> sendTokenLinkPasswordReset(String email){

        User userObject = userRepository.findByEmail(email).orElse(null);
        String emailLinkMsg = null;

        if(userObject == null || !userObject.isEnabled()) {
            System.out.println("User not found");
            // if no user or email associated then just ignore. DO NOTHING.
            emailLinkMsg = "If an account exists for this email, a password reset link has been sent.";
        }else{
            //1. init or get the user object


                //2. generate a string token
                String plainToken = EmailTokenGenerator.generateRandomToken();

                //3. generate the salt
                String salt = EmailTokenGenerator.generateSalt();

                //4. generate a hashed token to compare later
                String hashedToken = EmailTokenGenerator.hashToken(plainToken, salt);

                //5. save the hashedToken and salt in db
                ResetPasswordToken resetPasswordToken = ResetPasswordToken.builder()
                        .token(hashedToken)
                        .plainToken(plainToken)
                        .salt(salt)
                        .expiryTime(LocalDateTime.now().plusMinutes(10))
                        .createdAt(LocalDateTime.now())
                        .used(false)
                        .user(userObject)
                        .build();

                resetPasswordTokenRepository.save(resetPasswordToken);
                // 4. send and a link to user's email with the token
                emailLinkMsg = emailService.sendResetPasswordEmail(email, userObject.getFirstName(), plainToken, resetPasswordToken.getResetTokenId());
            }

        // send a success response back to user
        return new ApiResponse<>(emailLinkMsg, "Reset password link was sent successfully.");
    }

    @Transactional
    public ApiResponse<String> resetPassword(NewPasswordDto resetPasswordRequest){
        /**
         * TODO: - invalid/missing token: Done
         *       - token expired: Done
         *       - reused token: Done
         *       - weak password:
         *       - confirm mismatch
         *in**/

        // 1. assign each attribute from resetPasswordRequest object
        String incomingToken = resetPasswordRequest.getToken();
        int tokenId = Integer.parseInt(resetPasswordRequest.getTokenId());
        String newPassword = resetPasswordRequest.getNewPassword();

        // 2. fetch the token using the tokenID
        ResetPasswordToken tokenEntry = resetPasswordTokenRepository.findById(tokenId)
                .orElseThrow(()-> new InvalidResetPasswordTokenException("Reset token not found."));

        // 3. check if token is expired
        if(tokenEntry.getExpiryTime().isBefore(LocalDateTime.now())){
            throw new TokenExpiredException("Reset password token has expired.");
        }

        // 4. check if token is already use
        if(tokenEntry.isUsed()){
            throw new InvalidResetPasswordTokenException("Reset password token is used.");
        }

        // 5. fetch the user using tokenEntry userId
        User user = tokenEntry.getUser();

        // 6. Hash the incoming token and compare
        String incomingHashedToken = EmailTokenGenerator.hashToken(incomingToken, tokenEntry.getSalt());
        if(!incomingHashedToken.equals(tokenEntry.getToken())){
            throw new InvalidResetPasswordTokenException("Invalid reset token.");
        }

        // 7. Validate Password
        InputValidator.validatePassword(newPassword);

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setUpdatedAt(LocalDateTime.now());
        tokenEntry.setUsed(true);

        userRepository.save(user);
        resetPasswordTokenRepository.save(tokenEntry);

        return new ApiResponse<>(null, "Password Reset Success.");
    }


}






























