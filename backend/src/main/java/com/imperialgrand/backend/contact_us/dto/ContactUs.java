package com.imperialgrand.backend.contact_us.dto;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "contact_us")
public class ContactUs {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer contactUsId;

    private String name;
    private String email;
    private String subject;

    @Lob // automatically map to a suitable large text type i so   @Column(columnDefinition = "TEXT") is optional
    @Column(columnDefinition = "TEXT")
    private String message;


}
