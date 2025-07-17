package com.imperialgrand.backend.reservation.model;

import com.imperialgrand.backend.reservation.enums.ReservationStatus;
import com.imperialgrand.backend.user.model.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;

@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Data
@Table(name = "reservations")
public class Reservation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer reservationId;

    private LocalDate date;
    private LocalTime time;
    private int guestCount;

    @Column(nullable = true)
    private String name;

    @Column(nullable = true)
    private String email;

    @Column(nullable = true)
    private String phone;

    private String specialRequest;

    @Enumerated(EnumType.STRING)
    private ReservationStatus status;
    private LocalDateTime savedAt;

    @ManyToOne
    @JoinColumn(name = "table_id")
    private TableEntity table;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = true)
    private User user;

}
