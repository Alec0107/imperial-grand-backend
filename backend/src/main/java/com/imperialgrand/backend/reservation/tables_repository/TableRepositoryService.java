package com.imperialgrand.backend.reservation.tables_repository;

import com.imperialgrand.backend.reservation.model.TableEntity;
import jakarta.persistence.Table;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@RequiredArgsConstructor
@Service
public class TableRepositoryService {

    private final TableRepository tableRepository;

    public List<TableEntity> finAllTableEntities() {
        return tableRepository.findAll();
    }

    public List<TableEntity> fetchTablesExcludedTheIds(List<Integer> excludedTableIds) {
       return tableRepository.findByTableIdNotIn(excludedTableIds);
    }

    public TableEntity getTableEntityById(int id) {
        return tableRepository.findById(id).orElse(null);
    }


}
