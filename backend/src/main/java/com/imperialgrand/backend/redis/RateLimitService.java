package com.imperialgrand.backend.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RateLimitService {

    /**
     *  RATE LIMITER TYPE: SLIDING WINDOW LOG
     * **/

    private final StringRedisTemplate redisTemplate;

    public boolean isRequestAllowed(String ip){
        String key = ip;
        long now = System.currentTimeMillis();
        long windowMillis = 2 * 60 * 1000;
        System.out.println(new Date());

        // 1. Remove entries older than 3 mins
        redisTemplate.opsForZSet().removeRangeByScore(key, 0, now - windowMillis);
        // 2. count how many request remain
        Long count = redisTemplate.opsForZSet().zCard(key);
        System.out.println("Current request count in window: " + count);

        if(count != null && count >= 3){
            System.out.println("Blocked");
            return false;
        }

        // 3. save new request timestamp
        String uuid = UUID.randomUUID().toString();
        redisTemplate.opsForZSet().add(key, uuid, now);
        System.out.println("Request accepted. Total now: " + (count + 1));

        // 4. auto-expire this key if user stops using it

        return true;
    }

}