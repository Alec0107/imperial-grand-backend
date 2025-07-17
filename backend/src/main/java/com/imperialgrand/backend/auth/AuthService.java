package com.imperialgrand.backend.auth;

import com.imperialgrand.backend.auth.dto.LoginRequest;
import com.imperialgrand.backend.auth.dto.RegisterRequest;
import com.imperialgrand.backend.auth.utils.FieldsNullChecker;
import com.imperialgrand.backend.common.globalexception.CooldownException;
import com.imperialgrand.backend.email.repository.EmailRepositoryService;

import com.imperialgrand.backend.jwt.JwtRepositoryService;
import com.imperialgrand.backend.jwt.exception.InvalidJwtTokenException;
import com.imperialgrand.backend.jwt.exception.MissingRefreshTokenException;
import com.imperialgrand.backend.jwt.exception.RefreshTokenExpiredException;
import com.imperialgrand.backend.jwt.exception.WrongTypeTokenException;
import com.imperialgrand.backend.jwt.model.JwtExpiration;
import com.imperialgrand.backend.resetpassword.dto.NewPasswordDto;
import com.imperialgrand.backend.dto_response.SignUpResponse;
import com.imperialgrand.backend.email.utils.EmailSenderService;
import com.imperialgrand.backend.email.model.EmailVerificationToken;
import com.imperialgrand.backend.email.repository.EmailVerificationTokenRepository;
import com.imperialgrand.backend.resetpassword.repository.ResetPasswordRepositoryService;
import com.imperialgrand.backend.user.UserRepositoryService;
import com.imperialgrand.backend.user.exception.EmailAlreadyUsedException;
import com.imperialgrand.backend.email.exception.EmailAlreadyVerifiedException;
import com.imperialgrand.backend.email.exception.EmailTokenException;
import com.imperialgrand.backend.email.exception.EmailTokenExpiredException;
import com.imperialgrand.backend.resetpassword.exception.InvalidResetPasswordTokenException;
import com.imperialgrand.backend.resetpassword.exception.TokenExpiredException;
import com.imperialgrand.backend.jwt.JwtGeneratorService;
import com.imperialgrand.backend.jwt.model.JwtToken;
import com.imperialgrand.backend.jwt.repository.JwtTokenRepository;
import com.imperialgrand.backend.resetpassword.model.ResetPasswordToken;
import com.imperialgrand.backend.resetpassword.repository.ResetPasswordTokenRepository;
import com.imperialgrand.backend.common.response.ApiResponse;
import com.imperialgrand.backend.user.exception.EmailNotFoundException;
import com.imperialgrand.backend.user.model.Role;
import com.imperialgrand.backend.user.model.User;
import com.imperialgrand.backend.user.repository.UserRepository;
import com.imperialgrand.backend.email.utils.HashTokenUtils;
import com.imperialgrand.backend.common.utils.InputValidator;
import com.imperialgrand.backend.common.utils.MaskUserEmail;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;


import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.logging.Logger;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtGeneratorService jwtGeneratorService;
    private final EmailSenderService emailService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    private final Logger logger = Logger.getLogger(AuthService.class.getName());

    private final JwtTokenRepository jwtTokenRepository;
    private final JwtRepositoryService jwtRepositoryService;

    private final UserRepository userRepositor;
    private final UserRepositoryService userRepositoryService;

    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final EmailRepositoryService emailRepositoryService;

    private final ResetPasswordTokenRepository resetPasswordTokenRepository;
    private final ResetPasswordRepositoryService resetPasswordRepositoryService;


    // For registration
    public ApiResponse<SignUpResponse> register(RegisterRequest registerRequest) {

        String userEmail = registerRequest.getEmail();

        // to check if user's email was not taken
        userRepositoryService.isEmailAvailable(userEmail);

        // If any fields are missing then throw an exception.
        if(FieldsNullChecker.missingFields(registerRequest)){
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

        userRepositoryService.saveUser(userData);

        // Must be converted back to byte array in order to use for validation later
        // Generate token for email verification link
        String plainToken = HashTokenUtils.generateRandomToken();
        // Generate salt for email verification link
        String salt = HashTokenUtils.generateSalt();
        String hashedToken = HashTokenUtils.hashToken(plainToken, salt);

        // hash the token and save in db
       EmailVerificationToken emailToken = emailRepositoryService.saveEmailVerifToken(userData, hashedToken, plainToken, salt);

        // Send email verification link
        String message = emailService.sendSimpleEmailVerif(registerRequest, plainToken, emailToken.getEmailTokenId());

        var signUpResponse = SignUpResponse.builder()
                .email(userData.getEmail())
                .message(message)
                .expiryTime(emailToken.getExpiryTime())
                .build();


        return new ApiResponse<>(signUpResponse, "Registration successful.");
    }

    // Verifying email verification token
    public void verifyEmailToken(String rawToken, int tokenId){
        // wrap with entitynotfoundexception if getrefbyid is not found it throws an exception !!!
        try {
            // Might return a proxy — exception only thrown on access!
            EmailVerificationToken emailToken = emailRepositoryService.getEmailVerificationToken(tokenId);
            String salt = emailToken.getSalt();
            String hashedEmailToken = emailToken.getToken();
            String rawHashedToken = HashTokenUtils.hashToken(rawToken, salt);

            if(emailToken.getUser().isEnabled()){
                throw EmailTokenException.builder().status("verified").build();
            }

            // sends this to user and let user decide to whether resend an email verification
            emailRepositoryService.isEmailTokenExpired(emailToken.getExpiryTime(), tokenId);

            if(!hashedEmailToken.equals(rawHashedToken)){
                System.out.println("Email token mismatched");
                throw EmailTokenException.builder().status("invalid").build();
            }

            emailToken.setUsed(true);
            User user = emailToken.getUser();
            user.setEnabled(true);

            userRepositoryService.saveUser(user);
        } catch (EntityNotFoundException ex) {
            throw EmailTokenException.builder().status("invalid").build();
        }


    }


    public Map<String, Object> login(LoginRequest loginRequest, String incomingDeviceId) {
        /**
         * TODO:
         *      - revoke and expired to true when log in so that if there are
         *      previous at and rt will be invalid to generate a new one
         * */

        logger.info("AUTHSERVICE: " + loginRequest.toString());
        String userEmail = loginRequest.getEmail();
        boolean rememberMe = loginRequest.isRememberMe();
        String accessToken = null;
        String refreshToken = null;
        String deviceId = null;

        // fetch the user form db and verify
        User user = userRepositoryService.getUserByEmail(userEmail);
        userRepositoryService.isUserEnabled(user);


        if(incomingDeviceId != null) {
            logger.info("DEVICE ID: " + incomingDeviceId);
            JwtToken previousRefreshToken = jwtRepositoryService.getTokenByUserIdAndDeviceId(user.getUserId(), incomingDeviceId);
            previousRefreshToken.setRevoked(true);
            jwtRepositoryService.saveOldToken(previousRefreshToken);
            deviceId = incomingDeviceId;
        }else{
            logger.info("DEVICE ID is empty. First Login with this device.");
            deviceId = UUID.randomUUID().toString();
        }


        try{
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
            );


            // generate refresh and access token
            refreshToken = jwtGeneratorService.generateRefreshToken(user, rememberMe);
            accessToken  = jwtGeneratorService.generateAccessToken(user);

            // hash the refresh token
            String salt = HashTokenUtils.generateSalt();
            String hashedRefreshToken = HashTokenUtils.hashRefreshToken(refreshToken, salt);

            // save salt and hashed refresh token
           jwtRepositoryService.saveNewToken(hashedRefreshToken, salt, user, deviceId, loginRequest.isRememberMe());

            System.out.println("LOGIN TIME: " + new Date());
            System.out.println("LOGIN: (Refresh-token): " + refreshToken);
            return helperResponseMap(user, accessToken, refreshToken, deviceId, loginRequest.isRememberMe());

        }catch (BadCredentialsException ex){
            throw new BadCredentialsException("Bad credentials" + ex.getMessage());
        }
    }

    private Map<String, Object> helperResponseMap(User user, String accessToken, String refreshToken, String deviceId, boolean rememberMe) {
        Map<String, Object> mapResponse = new HashMap<>();
        mapResponse.put("username", user.getUsername());
        mapResponse.put("role", user.getRole());
        mapResponse.put("access_token", accessToken);
        mapResponse.put("refresh_token", refreshToken);
        mapResponse.put("device_id", deviceId);
        mapResponse.put("remember_me", rememberMe);
        return mapResponse;
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
       jwtTokenRepository.save(jwtTokenObject);

       return new ApiResponse<>("" ,"Logout successful.");
    }

    @Transactional
    public ApiResponse<SignUpResponse> resendVerificationToken(String email) {

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiry;
        String emailTokenToSend = null;
        int tokenId = 0;

        User user = userRepositoryService.getUserByEmail(email);

        if(user.isEnabled()){
            throw new EmailAlreadyVerifiedException("Your email is already verified. Please log in.");
        }

        Optional<EmailVerificationToken> tokenOp = emailRepositoryService.getByUserId(user.getUserId());

        if(!tokenOp.isPresent()) {
                System.out.println("Token is not in db.. Generating new token..");
                // Must be converted back to byte array in order to use for validation later
                // Generate token for email verification link
                String plainToken = HashTokenUtils.generateRandomToken();
                emailTokenToSend = plainToken;
                // Generate salt for email verification link
                String salt = HashTokenUtils.generateSalt();
                String hashedToken = HashTokenUtils.hashToken(plainToken, salt);

                EmailVerificationToken emailToken = emailRepositoryService.saveEmailVerifToken(user, hashedToken, plainToken, salt);
                tokenId = emailToken.getEmailTokenId();
                expiry = emailToken.getExpiryTime();
        }else {
            EmailVerificationToken token = tokenOp.get();

            // If still in cooldown throw an exception
            if(token.getCreatedAt().isAfter(now.minusMinutes(1))){
                // throw cooldown exception (user must wait for 1 minute to receive another email verification link)
                throw new CooldownException("Please wait before requesting another verification link. You can try again in 1 minute.");
            }

            if(token.getExpiryTime().isBefore(LocalDateTime.now()) ) {
                      System.out.println("Old token is in db. Generating new token..");
                    // Delete old token
                    emailVerificationTokenRepository.deleteByUser_userId(user.getUserId());
                    // Must be converted back to byte array in order to use for validation later
                    // Generate token for email verification link
                    String plainToken = HashTokenUtils.generateRandomToken();
                    // Generate salt for email verification link
                    String salt = HashTokenUtils.generateSalt();
                    String hashedToken = HashTokenUtils.hashToken(plainToken, salt);

                    EmailVerificationToken emailToken = emailRepositoryService.saveEmailVerifToken(user, hashedToken ,plainToken, salt);

                    emailTokenToSend = emailToken.getPlainToken();
                    tokenId = emailToken.getEmailTokenId();
                    expiry = emailToken.getExpiryTime();

            }else{
                    System.out.println("Reusing Old token...");
                    emailTokenToSend = token.getPlainToken();
                    tokenId = token.getEmailTokenId();
                    expiry = token.getExpiryTime();
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
        /**
         * TODO:
         *       - reuse token if its not expired yet (THE FRONT END HAS TIME BUT FOR SECURITY PURPOSES)
         *       - throw cooldown exception if request is before 1min (remember for production set it to 5 mins)
         * */
       User user = null;
        try{
            EmailVerificationToken emailToken = emailVerificationTokenRepository.getReferenceById(tokenId);
            user = emailToken.getUser();
        }catch (EntityNotFoundException ex){
            System.out.println(ex.getMessage());
            /**
             * TODO:
             *       Maybe log or throw custom exception here
             *
             ***/
        }

        if(user == null){
            System.out.println("User not found");
        }

        // delete the previous/expired email verif token
        emailVerificationTokenRepository.deleteByUser_userId(user.getUserId());

        // generate a new one and send back to user's email inbox (link)
        String plainToken = HashTokenUtils.generateRandomToken();
        String salt = HashTokenUtils.generateSalt();
        String hashedToken = HashTokenUtils.hashToken(plainToken, salt);

        EmailVerificationToken newEmailToken = emailRepositoryService.saveEmailVerifToken(user, hashedToken, plainToken, salt);
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


    public ApiResponse<String> sendTokenLinkPasswordReset(String email){

        User userObject = userRepositoryService.getUserByEmailForPassReset(email);
        String emailLinkMsg = null;

        if(userObject == null || !userObject.isEnabled()) {
            System.out.println("User not found");
            // if no user or email associated then just ignore. DO NOTHING.
            emailLinkMsg = "If an account exists for this email, a password reset link has been sent.";
        }else{
            //1. init or get the user object

            /**
             *  TODO:
             *        -  reuse token email  if its not expired
             * **/

                //2. generate a string token
                String plainToken = HashTokenUtils.generateRandomToken();

                //3. generate the salt
                String salt = HashTokenUtils.generateSalt();

                //4. generate a hashed token to compare later
                String hashedToken = HashTokenUtils.hashToken(plainToken, salt);

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

                resetPasswordRepositoryService.saveResetPasswordToken(resetPasswordToken);
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
        ResetPasswordToken tokenEntry = resetPasswordRepositoryService.getResetPasswordTokenById(tokenId);
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
        String incomingHashedToken = HashTokenUtils.hashToken(incomingToken, tokenEntry.getSalt());
        if(!incomingHashedToken.equals(tokenEntry.getToken())){
            throw new InvalidResetPasswordTokenException("Invalid reset token.");
        }

        // 7. Validate Password
        InputValidator.validatePassword(newPassword);

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setUpdatedAt(LocalDateTime.now());
        tokenEntry.setUsed(true);

        userRepositoryService.saveUser(user);
        resetPasswordRepositoryService.saveResetPasswordToken(tokenEntry);

        return new ApiResponse<>(null, "Password Reset Success.");
    }

    /**
     * TODO:
     *       - Add a function that checks the status of the password reset token (expired / used)
     *       so it can show the correct modal when user clicks the email link from inbox
     * **/
    public ApiResponse<String> checkResetToken(String rawToken, int tokenId){
        ResetPasswordToken resetPasswordToken = resetPasswordRepositoryService.getResetPasswordTokenById(tokenId);

        String salt = resetPasswordToken.getSalt();
        String hashedResetToken = resetPasswordToken.getToken();
        String rawTokenHashed = HashTokenUtils.hashToken(rawToken, salt);

        if(resetPasswordToken.isUsed()){
            throw new InvalidResetPasswordTokenException("Reset password token is used.");
        }

        if(resetPasswordToken.getExpiryTime().isBefore(LocalDateTime.now())){
            throw new TokenExpiredException("Reset password token has expired.");
        }

        if(!hashedResetToken.equals(rawTokenHashed)){
            throw new InvalidResetPasswordTokenException("Invalid reset password token.");
        }

        return new ApiResponse<>(null, "Reset password token is valid.");
    }









    @Transactional
    public Map<String, Object> generateNewJwtToken(String incomingRefreshToken, String deviceId){
        logger.info("Processing refresh token generation request for user");
        logger.info("Refresh token: " + incomingRefreshToken);
        logger.info("Device ID: " + deviceId);
        User user = null;

        try{
            // check if token is present
            if(incomingRefreshToken == null || incomingRefreshToken.isEmpty()) {
                throw new MissingRefreshTokenException("Refresh token is empty");
            }

            // check if token is refresh and is not tampered
            Claims claims = jwtGeneratorService.extractAllClaims(incomingRefreshToken);
            if(!claims.get("type").equals("refresh-token")){
                throw new WrongTypeTokenException("Wrong type of jwt token.");
            }

            // fetch the user and matching token from DB early
            String userEmail = claims.getSubject();
            user = userRepositoryService.getUserByEmail(userEmail);
            JwtToken matchingToken = jwtRepositoryService.getTokenByUserIdAndDeviceId(user.getUserId(), deviceId);

            // DB expiration check should come before claims check
            if (matchingToken.getExpiresAt().isBefore(LocalDateTime.now())) {
//                matchingToken.setExpired(true);
//                jwtRepositoryService.saveOldToken(matchingToken); // Save change if you want
                throw new RefreshTokenExpiredException("Refresh token has expired (DB check). Please login again.");
            }

            // Optional: now check JWT claim expiration as secondary (for redundancy/logging)
            if (claims.getExpiration().before(new Date())) {
                throw new RefreshTokenExpiredException("Refresh token has expired (JWT claims). Please login again.");
            }

            /**
             * TODO:
             *        Alternative (more concise) make sure that only returns 1
             *        jwttoken from db or make it a lists and iterate
             * **/


            String salt = matchingToken.getSalt();
            String hashedRefreshTokenDb = matchingToken.getToken();
            String incomingHashedRefreshToken = HashTokenUtils.hashRefreshToken(incomingRefreshToken, salt);

            if(!incomingHashedRefreshToken.equals(hashedRefreshTokenDb)){
                throw new InvalidJwtTokenException("Refresh token not recognized");
            }

            // revoke the matched token
            matchingToken.setRevoked(true);
            jwtRepositoryService.saveOldToken(matchingToken);

            String newAccessToken = null;
            String newRefreshToken = null;
            String previousDeviceId = matchingToken.getDeviceId();

            newRefreshToken = jwtGeneratorService.generateRefreshToken(user, matchingToken.isRememberMe());
            newAccessToken = jwtGeneratorService.generateAccessToken(user);

            String newSalt = HashTokenUtils.generateSalt();
            String newHashedRefreshToken = HashTokenUtils.hashRefreshToken(newRefreshToken, newSalt);

            jwtRepositoryService.saveNewToken(newHashedRefreshToken, newSalt, user, previousDeviceId, matchingToken.isRememberMe());

            System.out.println("REFRESH TOKEN CREATED AT: " + new Date());
            System.out.println("REFRESH NEW: (Refresh-token): " + newRefreshToken);
            return helperResponseMap(user, newAccessToken, newRefreshToken, previousDeviceId, matchingToken.isRememberMe());
        }catch (JwtException e){
            throw new InvalidJwtTokenException("Invalid refresh token.");
        }
    }









    /// test endpoint


    public String getProfile(String token){
        String userEmail = jwtGeneratorService.getUserEmail(token);

        User user =  userRepositoryService.getUserByEmail(userEmail);

        String userFullName = user.getFirstName() + user.getLastName();

        return userFullName;
    }
}






























