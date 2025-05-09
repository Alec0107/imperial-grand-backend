package com.imperialgrand.backend.exception;

import com.imperialgrand.backend.dto.RegisterRequest;
import com.imperialgrand.backend.responseWrapper.ErrorResponse;
import org.aspectj.apache.bcel.generic.RET;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String CONFLICT_ERROR = "CONFLICT";
    private static final String BAD_REQUEST = "BAD_REQUEST";
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

    @ExceptionHandler(EmailTokenNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleEmailTokenNotFoundException(EmailTokenNotFoundException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                         ex.getMessage(),
                         BAD_REQUEST,
                         HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

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
                BAD_REQUEST,
                HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    @ExceptionHandler(EmailNotVerifiedException.class)
    public ResponseEntity<ErrorResponse> handleEmailNotVerifiedException(EmailNotVerifiedException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                ex.getMessage(),
                BAD_REQUEST,
                HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    @ExceptionHandler(CooldownException.class)
    public ResponseEntity<ErrorResponse> handleCooldownException(CooldownException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                ex.getMessage(),
                TOO_MANY_REQUEST,
                HttpStatus.TOO_MANY_REQUESTS.value());
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(errorResponse);
    }

}