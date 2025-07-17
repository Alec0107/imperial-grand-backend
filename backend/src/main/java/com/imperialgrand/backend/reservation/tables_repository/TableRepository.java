package com.imperialgrand.backend.reservation.tables_repository;

import com.imperialgrand.backend.reservation.model.TableEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TableRepository extends JpaRepository<TableEntity, Integer> {

    @Query(value = "SELECT * FROM tables WHERE table_id NOT IN (:excludedTableIds)", nativeQuery = true)
    List<TableEntity> findByTableIdNotIn(@Param("excludedTableIds") List<Integer> tableIds);

    @Query(value = "SELECT * FROM reservations WHERE table_id = :table_id", nativeQuery = true)
    Optional<TableEntity> findTableById(@Param("table_id") Integer tableId);

}
