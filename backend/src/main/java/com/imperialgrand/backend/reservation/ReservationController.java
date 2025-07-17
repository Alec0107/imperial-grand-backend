package com.imperialgrand.backend.reservation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.imperialgrand.backend.reservation.dto.FinalSubmissionDTO;
import com.imperialgrand.backend.reservation.dto.ReservationDTO;
import com.imperialgrand.backend.reservation.dto.ReservationLockStatusDTO;
import com.imperialgrand.backend.user.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.logging.Logger;

@Slf4j
@RestController
@RequestMapping("api/v1/reservation")
@RequiredArgsConstructor
public class ReservationController {

    private final ReservationService reservationService;
    private final Logger logger = Logger.getLogger(ReservationController.class.getName());

    private final ObjectMapper objectMapper; // for test

    @PostMapping("/availability")
    public ResponseEntity<ReservationLockStatusDTO> checkAvailability(@RequestBody ReservationDTO reservationDTO){
        ReservationLockStatusDTO reservationLockStatusDTO = reservationService.checkReservationAvailability(reservationDTO);
        return ResponseEntity.ok(reservationLockStatusDTO);
    }

    /** TODO: -check lock status (/lock-status) **/

    @GetMapping("/lock_status")
    public ResponseEntity<ReservationLockStatusDTO> checkLockStatus(
            @RequestParam("tableId") int tableId,
            @RequestParam("date") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date,
            @RequestParam("time") @DateTimeFormat(iso = DateTimeFormat.ISO.TIME) LocalTime time
    ){
        logger.info("TableId: " + tableId + " date: " + date + " time: " + time);
        ReservationLockStatusDTO reservationLockStatusDTO = reservationService.checkLockStatus(tableId, date, time);
        return ResponseEntity.ok(reservationLockStatusDTO);
    }


    @PostMapping("/submit")
    public ResponseEntity<String> submitReservation(@RequestBody FinalSubmissionDTO finalSubmissionDTO){
        System.out.println("Accessing submit reservation endpoint...");
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        User user = null;

        if(auth != null && auth.isAuthenticated()){
            user = (User) auth.getPrincipal();
        }

        reservationService.saveReservation(user, finalSubmissionDTO);


        return ResponseEntity.ok("Save successfully");
    }

}
