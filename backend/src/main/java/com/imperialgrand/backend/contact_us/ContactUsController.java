package com.imperialgrand.backend.contact_us;


import com.imperialgrand.backend.contact_us.dto.ContactUs;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.logging.Logger;

@RestController
@RequestMapping("/api/v1/contact")
@RequiredArgsConstructor
public class ContactUsController {

    private final ContactUsService contactUsService;
    private final Logger logger = Logger.getLogger(ContactUsController.class.getName());

    @PostMapping
    public ResponseEntity<String> submitContact(@RequestBody ContactUs contactUsRequest, HttpServletRequest request){
        // 1. get the client's ip address
        String clientIp = "contactus:ip:" + getClientIp(request);
        contactUsService.checkRateLimiter(clientIp);



        contactUsService.validateContactUsRequest(contactUsRequest);
        return ResponseEntity.ok("Success");
    }

    private String getClientIp(HttpServletRequest request){
        String xfHeader = request.getHeader("X-Forwarded-For");
        String ip = (xfHeader != null) ? xfHeader.split(",")[0] : request.getRemoteAddr();

        // Normalize local loopback
        if ("0:0:0:0:0:0:0:1".equals(ip) || "::1".equals(ip)) {
            ip = "127.0.0.1";
        }

        return ip;
    }
}
