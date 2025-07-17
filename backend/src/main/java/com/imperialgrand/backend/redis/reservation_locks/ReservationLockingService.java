package com.imperialgrand.backend.redis.reservation_locks;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.imperialgrand.backend.reservation.dto.ReservationDTO;
import com.imperialgrand.backend.reservation.dto.ReservationLockStatusDTO;
import com.imperialgrand.backend.reservation.exception.ReservationLockNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.Optional;
import java.util.logging.Logger;

@Service
@RequiredArgsConstructor
public class ReservationLockingService {

    private final StringRedisTemplate stringRedisTemplate;
    private final ObjectMapper objectMapper;

    private final Logger logger = Logger.getLogger(ReservationLockingService.class.getName());

    public boolean isTableLocked(int tableId, ReservationDTO reservationDTO) {
        // String key = buildLockKey(tableId, reservationDTO.getDate(), reservationDTO.getTime());
        // stringRedisTemplate.hasKey(...) returns a Boolean, which can be null in edge cases
        // (e.g. if Redis connection glitches or fails).
        // return Boolean.TRUE.equals(stringRedisTemplate.hasKey(key));

        LocalDate date = reservationDTO.getDate();
        LocalTime time = reservationDTO.getTime();


        /**
         * TODO: CHECK 30 MINS BEFORE AND 30 MINS AFTER THE USER PREFERRED TIME
         **/

        LocalTime timesToCheck[] = {
                time.minusMinutes(30),
                time,
                time.plusMinutes(30)};

        for(LocalTime t: timesToCheck){
            String key = buildLockKey(tableId, reservationDTO.getDate(), t);
            Boolean exists = stringRedisTemplate.hasKey(key);
            if(Boolean.TRUE.equals(exists)){
                logger.info("Table " + tableId + " is locked at " + t);
                return true;
            }
        }



//       return stringRedisTemplate.hasKey(key) ? true : false;
        return false;
    }

    public ReservationLockStatusDTO lockTable(int tableId, String tableName, ReservationDTO reservationDTO) {
        String key = buildLockKey(tableId, reservationDTO.getDate(), reservationDTO.getTime());

        ReservationLockStatusDTO lockStatus = ReservationLockStatusDTO.builder()
                .reservationDTO(reservationDTO)
                .tableId(tableId)
                .tableName(tableName)
                .expiresAt(LocalDateTime.now().plusMinutes(5))
                .build();

        try {
            String jsonValue = objectMapper.writeValueAsString(lockStatus);
            stringRedisTemplate.opsForValue().set(key, jsonValue);
            stringRedisTemplate.expire(key, Duration.ofMinutes(5));
            System.out.println("Tables saved " + tableName);
        } catch (JsonProcessingException e) {
            logger.warning("Failed to parse lock JSON: " + e.getMessage());
        }

        return lockStatus;
    }

    /**
     *  Called by frontend when user refreshes to rehydrate the timer.
     */
    public ReservationLockStatusDTO isLockValid(int tableId, LocalDate date, LocalTime time) {
        ReservationLockStatusDTO reservationLockStatusDTO = new ReservationLockStatusDTO();
        String key = buildLockKey(tableId, date, time);
        Optional<String> optionalRedisValue = Optional.ofNullable(stringRedisTemplate.opsForValue().get(key)); // wrapped by optional this might return a null

        String redisValueString = optionalRedisValue.orElseThrow(() -> new ReservationLockNotFoundException("Reservation lock not found for key: " + key));

        try{
          reservationLockStatusDTO = objectMapper.readValue(redisValueString, ReservationLockStatusDTO.class);
        }catch (JsonProcessingException e){
            logger.warning("Failed to parse lock JSON: " + e.getMessage());
        }
        return reservationLockStatusDTO;
    }

    private String buildLockKey(int tableId, LocalDate date, LocalTime time) {
        return "Reservation:lock:table:" + tableId + ":" + date + ":" + time;
    }

}
