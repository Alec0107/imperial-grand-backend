package com.imperialgrand.backend.contact_us.repository;

import com.imperialgrand.backend.contact_us.dto.ContactUs;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ContactUsRepository extends JpaRepository<ContactUs, Integer> {
}
