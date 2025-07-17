package com.imperialgrand.backend.auth;

import com.imperialgrand.backend.resetpassword.dto.UserEmailDto;
import com.imperialgrand.backend.auth.dto.LoginRequest;
import com.imperialgrand.backend.auth.dto.RegisterRequest;
import com.imperialgrand.backend.resetpassword.dto.NewPasswordDto;
import com.imperialgrand.backend.dto_response.SignUpResponse;
import com.imperialgrand.backend.common.response.ApiResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.Response;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.time.Duration;
import java.util.*;
import java.util.logging.Logger;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final Logger logger = Logger.getLogger(AuthController.class.getName());

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<SignUpResponse>> register(@RequestBody RegisterRequest registerRequest) {
        logger.info("RESGISTER BODY: " + registerRequest.toString());
        ApiResponse<SignUpResponse> response = authService.register(registerRequest);
        return ResponseEntity.ok(response);
    }

    // To verify user's email when clicking the email verification link in user's email inbox
    @GetMapping("/verify")
    public RedirectView verify(@RequestParam("token") String rawToken,
                               @RequestParam("id") Integer tokenId) {
        authService.verifyEmailToken(rawToken, tokenId);
        // redirect the user to the front end html page
        return new RedirectView("http://127.0.0.1:5500/pages/user-inbox-email-response/email-success.html");
    }



    @PostMapping("/login")
    public ResponseEntity<ApiResponse<Map<String, Object>>> login(@RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        Duration accessMaxAge = Duration.ofMinutes(1); // 3 minutes for access token
        Duration refreshMaxAge = loginRequest.isRememberMe() ? Duration.ofMinutes(3) : Duration.ofMinutes(2);
        Map<String, Object> mapBody = new HashMap<>();

        String deviceIdHeader = request.getHeader("x-device-id");
        logger.info("DEVICE ID: " + deviceIdHeader);

        Map<String, Object> mapResponse = authService.login(loginRequest, deviceIdHeader);
        String accessToken = (String) mapResponse.get("access_token");
        String refreshToken = (String) mapResponse.get("refresh_token");
        String deviceId = (String) mapResponse.get("device_id");

        ResponseCookie refresh = ResponseCookie.from("refresh-token", refreshToken)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(refreshMaxAge)
                .build();

        ResponseCookie access = ResponseCookie.from("access-token", accessToken)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(accessMaxAge)
                .build();

        ResponseCookie device = ResponseCookie.from("device-id", deviceId)
                .httpOnly(false)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(refreshMaxAge)
                .build();


        mapBody.put("username", mapResponse.get("username"));
        mapBody.put("role", mapResponse.get("role"));

        ApiResponse<Map<String, Object>> apiResponse = new ApiResponse<>(mapBody, "Login Successful!");

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refresh.toString(), access.toString(), device.toString())
                .body(apiResponse);
    }


    private String getRefreshCookieToken(HttpServletRequest request) {
        String incomingRefreshToken = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("refresh-token")) {
                    incomingRefreshToken = cookie.getValue();
                    System.out.println("REFRESH TOKEN T: " + cookie.getValue());
                    break;
                }
            }
        }
        return incomingRefreshToken;
    }


    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<Map<String, Object>>> refresh(HttpServletRequest request) {

        logger.info("Refresh endpoint hit.");
        logger.info("Device-ID: " + request.getHeader("x-device-id"));
        logger.info("Cookies: " + Arrays.toString(request.getCookies()));


        Map<String, Object> mapBody = new HashMap<>();
        /**
         *  TODO:
         *       - add refresh rotation. If access token (AT) expired
         *       use the refresh token (RT) to issue a new AT and RT
         *
         * **/
        // get the cookie refresh token and device id string form header
        String deviceId = request.getHeader("x-device-id");
        String incomingRefreshToken = getRefreshCookieToken(request);

        Map<String, Object> mapResponse = authService.generateNewJwtToken(incomingRefreshToken, deviceId);
        String newAccessToken = (String) mapResponse.get("access_token");
        String newRefreshToken = (String) mapResponse.get("refresh_token");
        String deviceIdTest = (String)mapResponse.get("device_id");
        boolean rememberMe = (boolean) mapResponse.get("remember_me");

        System.out.println("NEW REFRESH TOKEN: " + newRefreshToken);

        int accessMaxAge =  1 * 60; // 3 minutes for access token
        int refreshMaxAge = rememberMe ? 5 * 60 : 3 * 60;

        ResponseCookie newRefresh = ResponseCookie.from("refresh-token", newRefreshToken)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(refreshMaxAge)
                .build();

        ResponseCookie newAccess = ResponseCookie.from("access-token", newAccessToken)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(accessMaxAge)
                .build();

        ResponseCookie device = ResponseCookie.from("device-id", deviceIdTest)
                .httpOnly(false)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(refreshMaxAge)
                .build();


        mapBody.put("username", mapResponse.get("username"));
        mapBody.put("role", mapResponse.get("role"));

        ApiResponse<Map<String, Object>> apiResponse = new ApiResponse<>(mapBody, "Refresh Successful!");

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, newRefresh.toString(), newAccess.toString(), device.toString())
                .body(apiResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(HttpServletRequest request) {
        ApiResponse<String> response = authService.logout(request); // body to send

        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<ApiResponse<SignUpResponse>> resendVerification(@RequestParam("email") String userEmail) {
        ApiResponse<SignUpResponse> response = authService.resendVerificationToken(userEmail);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/inbox-resend-verification")
    public ResponseEntity<ApiResponse<SignUpResponse>>inboxResend(@RequestParam("tokenId") int tokenId) {
        System.out.println(tokenId);
        ApiResponse<SignUpResponse> response = authService.resendVerificationToken(tokenId);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<String>> forgotPassword(@RequestBody UserEmailDto forgotPassword) {
        ApiResponse<String> response =  authService.sendTokenLinkPasswordReset(forgotPassword.getEmail());
        return ResponseEntity.ok(response);
    }


    @GetMapping("/reset-password/validate")
    public ResponseEntity<ApiResponse<String>> checkResetToken(@RequestParam("token") String token, @RequestParam("tokenId") int tokenId) {
        // validate the token & tokenId
        logger.info("Token: " + token + " " + tokenId);
        ApiResponse<String> response = authService.checkResetToken(token, tokenId);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<String>> resetPassword(@RequestBody NewPasswordDto resetPasswordRequest) {
      /**
       *  TODO: use to receive user's new password and
       *        the token generated by the server to compare
       *        for resetting the password
       * */
        System.out.println(resetPasswordRequest.toString());
        ApiResponse<String> response = authService.resetPassword(resetPasswordRequest);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/profile")
    public ResponseEntity<ApiResponse<String>> getProfile(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        String accessToken = null;
        for (Cookie cookie : cookies) {
            logger.info("PROFILE: " + cookie.getName() + " : " + cookie.getValue());
            if (cookie.getName().equals("access-token")) {
                accessToken = cookie.getValue();
            }
        }

        String fullName = authService.getProfile(accessToken);

        ApiResponse<String> apiResponse = new ApiResponse<>(fullName, "Profile");

        return ResponseEntity.ok(apiResponse);

        /**
         * TODO: just to send user's basic data such as; name, email, etc..
         *
         * **/
    }
}












    /**
     * TODO:
     *        - Add endpoint for checking the reset link token validity so whenever
     *        the user clicks the reset link it shows the appropriate modal
     * */

    // TEST ENDPOINT FOR RECEIVING THE COOKIE
//    @GetMapping("/detailsTest")
//    public ResponseEntity<String> getUserDetails(@CookieValue("jwt") String token) {
//        System.out.println("Received JWT: " + token);
//        return ResponseEntity.ok("Received token: " + token);
//    }



