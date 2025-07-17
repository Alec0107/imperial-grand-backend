package com.imperialgrand.backend.reservation.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalTime;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class FinalSubmissionDTO {
    private LocalDate date;
    private LocalTime time;
    private int guestCount;
    private int tableId;
    private String tableName;
    private String[] occasion;
    private String[] dietary;
    private String message;
}

//export const FinalReservationSubmission = {
//date: "",               // from reservationDTO.date
//time: "",               // from reservationDTO.time
//guestCount: 0,          // from reservationDTO.guestCount
//tableId: null,          // from Redis lock response
//tableName: "",          // optional: for frontend display
//occasion: [],           // from step 2
//dietary: [],            // from step 2
//message: "",            // from step 2
//        }