package com.imperialgrand.backend.reservation.Tests;

import com.imperialgrand.backend.reservation.ReservationService;
import com.imperialgrand.backend.reservation.dto.ReservationDTO;
import com.imperialgrand.backend.reservation.dto.ReservationLockStatusDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/test/reservation")
@RequiredArgsConstructor
public class TestController {

    private final ReservationService reservationService;

    @PostMapping("/availability")
    public ResponseEntity<ReservationLockStatusDTO> saveReservation(@RequestBody ReservationDTO reservationDTO) {
        ReservationLockStatusDTO reservationLockStatusDTO  = reservationService.checkReservationAvailability(reservationDTO);
        return ResponseEntity.ok(reservationLockStatusDTO);
    }



}
