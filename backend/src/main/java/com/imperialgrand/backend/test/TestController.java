package com.imperialgrand.backend.test;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/test")
public class TestController {

    @GetMapping("/secure")
    public ResponseEntity<String> secure() {
        return ResponseEntity.ok("You are authenticated");
    }


    @GetMapping("/publicHello")
    public ResponseEntity<String> publicHello() {
        return ResponseEntity.ok("Anyone can access this.");
    }
}
