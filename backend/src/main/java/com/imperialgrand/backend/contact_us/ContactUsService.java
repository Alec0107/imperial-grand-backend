package com.imperialgrand.backend.contact_us;

import com.imperialgrand.backend.contact_us.dto.ContactUs;
import com.imperialgrand.backend.rate_limiter.RateLimitService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ContactUsService {

    private final RateLimitService rateLimitService;

    public void validateContactUsRequest(ContactUs contactUs){

    }

    public void checkRateLimiter(String clientIp){
        rateLimitService.isRequestAllowed(clientIp);
    }

}
