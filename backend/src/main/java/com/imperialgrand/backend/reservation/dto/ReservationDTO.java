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
public class ReservationDTO {
    private LocalDate date;
    private LocalTime time;
    private int guestCount;
}
