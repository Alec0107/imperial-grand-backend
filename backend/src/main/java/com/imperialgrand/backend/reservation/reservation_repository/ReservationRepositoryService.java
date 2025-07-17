package com.imperialgrand.backend.reservation.reservation_repository;

import com.imperialgrand.backend.reservation.model.Reservation;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;

@RequiredArgsConstructor
@Service
public class ReservationRepositoryService {

    private final ReservationRepository reservationRepository;

    @Transactional
    public List<Integer> findBookedTablesId(LocalDate reservationDate, LocalTime time){
        LocalDate date = reservationDate;
        LocalTime startBuffer = time.minusMinutes(30);
        LocalTime endBuffer = time.plusMinutes(30);
        return reservationRepository.findBookedTableId(date, startBuffer, endBuffer);
    }

    public void saveReservationNative(Reservation reservation){
        reservationRepository.saveReservation(
                reservation.getDate(),
                reservation.getTime(),
                reservation.getGuestCount(),
                reservation.getName(),
                reservation.getEmail(),
                reservation.getPhone(),
                reservation.getSpecialRequest(),
                reservation.getStatus().name(),
                reservation.getSavedAt(),
                reservation.getTable().getTableId(),
                reservation.getUser().getUserId()
        );
    }

}
