package com.imperialgrand.backend.common.globalexception;

import com.imperialgrand.backend.email.exception.EmailAlreadyVerifiedException;
import com.imperialgrand.backend.email.exception.EmailTokenException;
import com.imperialgrand.backend.email.exception.EmailTokenExpiredException;
import com.imperialgrand.backend.resetpassword.exception.InvalidResetPasswordTokenException;
import com.imperialgrand.backend.resetpassword.exception.TokenExpiredException;
import com.imperialgrand.backend.common.response.ErrorResponse;
import com.imperialgrand.backend.user.exception.EmailAlreadyUsedException;
import com.imperialgrand.backend.user.exception.EmailNotFoundException;
import com.imperialgrand.backend.user.exception.EmailNotVerifiedException;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.view.RedirectView;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String CONFLICT_ERROR = "CONFLICT";
    private static final String BAD_REQUEST = "BAD_REQUEST";
    private static final String UNAUTHORIZED = "UNAUTHORIZED";
    private static final String NOT_FOUND= "NOT_FOUND";
    private static final String TOO_MANY_REQUEST = "Too many requests";


    @ExceptionHandler(EmailAlreadyUsedException.class)
    public ResponseEntity<ErrorResponse> handleEmailAlreadyUsedException(EmailAlreadyUsedException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                         ex.getMessage(),
                         CONFLICT_ERROR,
                         HttpStatus.CONFLICT.value());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                         ex.getMessage(),
                         BAD_REQUEST,
                         HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentialsException(BadCredentialsException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                "Invalid email or password", // keep it vague for security
                 UNAUTHORIZED,
                HttpStatus.UNAUTHORIZED.value()); // Use 401 Unauthorized
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }

//    @ExceptionHandler(EmailTokenException.class)
//    public ResponseEntity<ErrorResponse> handleEmailTokenNotFoundException(EmailTokenException ex) {
//        ErrorResponse errorResponse = new ErrorResponse(
//                         ex.getMessage(),
//                         BAD_REQUEST,
//                         HttpStatus.BAD_REQUEST.value());
//        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
//    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ErrorResponse> handleIllegalStateException(IllegalStateException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                        ex.getMessage(),
                        BAD_REQUEST,
                        HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    @ExceptionHandler(EmailNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleEmailNotFoundException(EmailNotFoundException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                ex.getMessage(),
                NOT_FOUND,
                HttpStatus.NOT_FOUND.value());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
    }

    @ExceptionHandler(EmailNotVerifiedException.class)
    public ResponseEntity<ErrorResponse> handleEmailNotVerifiedException(EmailNotVerifiedException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                ex.getMessage(),
                UNAUTHORIZED,
                HttpStatus.UNAUTHORIZED.value());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }


    @ExceptionHandler(CooldownException.class)
    public ResponseEntity<ErrorResponse> handleCooldownException(CooldownException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                ex.getMessage(),
                TOO_MANY_REQUEST,
                HttpStatus.TOO_MANY_REQUESTS.value());
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(errorResponse);
    }

    /** EXCEPTION FOR RESENDING EMAIL VERIFICATION **/
    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleEntityNotFound(EntityNotFoundException ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getMessage(),
                BAD_REQUEST, HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
    }

    @ExceptionHandler(EmailAlreadyVerifiedException.class)
    public ResponseEntity<ErrorResponse> handleEmailAlreadyVerifiedException(EmailAlreadyVerifiedException ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getMessage(),
                BAD_REQUEST,
                HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }



    /** EXCEPTION FOR VERIFYING EMAIL VERIFICATION TOKEN **/
    @ExceptionHandler(EmailTokenException.class)
    public RedirectView handleEmailTokenException(EmailTokenException ex) {
        String url = "http://127.0.0.1:5500/pages/user-inbox-email-response/email-error.html?status=" + ex.getStatus();
        System.out.println("URL: " + url);
        return new RedirectView(url);
    }

    @ExceptionHandler(EmailTokenExpiredException.class)
    public RedirectView handleEmailTokenException(EmailTokenExpiredException ex) {
        String url = "http://127.0.0.1:5500/pages/user-inbox-email-response/email-error.html?status=" + ex.getStatus() + "&tokenId=" + ex.getTokenId();
        System.out.println("URL: " + url);
        return new RedirectView(url);
    }


    /** EXCEPTION FOR RESETTING PASSWORD **/
    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<ErrorResponse> handleTokenExpiredException(TokenExpiredException ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getMessage(),
                BAD_REQUEST,
                HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    @ExceptionHandler(InvalidResetPasswordTokenException.class)
    public ResponseEntity<ErrorResponse> handleInvalidResetPasswordTokenException(InvalidResetPasswordTokenException ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getMessage(),
                BAD_REQUEST,
                HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }


}