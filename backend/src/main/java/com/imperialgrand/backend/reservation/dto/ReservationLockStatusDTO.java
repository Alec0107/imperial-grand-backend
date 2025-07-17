package com.imperialgrand.backend.reservation.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;


@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ReservationLockStatusDTO {
    private ReservationDTO reservationDTO;
    private int tableId;
    private String tableName;
    private LocalDateTime expiresAt;
}
