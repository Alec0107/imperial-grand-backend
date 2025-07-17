package com.imperialgrand.backend.reservation;

import com.imperialgrand.backend.redis.reservation_locks.ReservationLockingService;
import com.imperialgrand.backend.reservation.dto.FinalSubmissionDTO;
import com.imperialgrand.backend.reservation.dto.ReservationDTO;
import com.imperialgrand.backend.reservation.dto.ReservationLockStatusDTO;
import com.imperialgrand.backend.reservation.enums.ReservationStatus;
import com.imperialgrand.backend.reservation.exception.NoAvailableTableException;
import com.imperialgrand.backend.reservation.model.Reservation;
import com.imperialgrand.backend.reservation.model.TableEntity;
import com.imperialgrand.backend.reservation.reservation_repository.ReservationRepositoryService;
import com.imperialgrand.backend.reservation.tables_repository.TableRepository;
import com.imperialgrand.backend.reservation.tables_repository.TableRepositoryService;
import com.imperialgrand.backend.user.model.User;
import jakarta.persistence.Table;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ReservationService {

    private final ReservationRepositoryService reservationRepositoryService;
    private final TableRepositoryService tableRepositoryService;
    private final ReservationLockingService reservationLockingService;

    private final Logger logger = Logger.getLogger(ReservationService.class.getName());

    public ReservationLockStatusDTO checkReservationAvailability(ReservationDTO reservation){
        //System.out.println(reservation.getTime().toString());
       List<TableEntity> availableTableEntity;
        // fetch all ids that are already booked based on the date and the time range before 30 mins and after 30mins of user's preferred time
       List<Integer> bookedTableIds = reservationRepositoryService.findBookedTablesId(reservation.getDate(), reservation.getTime());

       // if no tables are booked then fetch all tables entity so we can check the capacity f each table entity best is if exact or greater than the guest count (smallest possible)
       if(bookedTableIds.isEmpty()){
           availableTableEntity = sortTableCapacity(tableRepositoryService.finAllTableEntities(), reservation.getGuestCount());
       }else{
           availableTableEntity = sortTableCapacity(tableRepositoryService.fetchTablesExcludedTheIds(bookedTableIds), reservation.getGuestCount());
       }

        if (availableTableEntity.isEmpty()) {
            logger.warning("No suitable tables found. Guest count too high: " + reservation.getGuestCount());
            throw new NoAvailableTableException("No tables can handle " + reservation.getGuestCount() + " guests.");
        }

        TableEntity selectedTableEntity = null;

        // iterate the list and check redis whether the first index or other index tables are in redis or not
       for(TableEntity tableEntity : availableTableEntity){
           if(!reservationLockingService.isTableLocked(tableEntity.getTableId(), reservation)){
               logger.info("Table " + tableEntity.getTableId() + " is obtained");
               selectedTableEntity = tableEntity;
               break;
           }else{
               logger.info(tableEntity.getName() + " is assigned to " + reservation.getGuestCount() + " guests");
           }
       }

       if(selectedTableEntity == null){
           logger.warning("No available tables. Please change date, time or guest count.");
           throw new NoAvailableTableException("No available tables. Please change date, time or guest count.");
       }

        // lock the table and return the object;
        return reservationLockingService.lockTable(selectedTableEntity.getTableId(), selectedTableEntity.getName(), reservation);
    }

    //  ascending sorting and fetch the first index (0)
    private List<TableEntity> sortTableCapacity(List<TableEntity> tableEntities, int guestCount){
        List<TableEntity> suitable = tableEntities.stream()
                .filter(t -> t.getGuestCapacity() >= guestCount)
                .collect(Collectors.toList());

        suitable.sort(Comparator.comparingInt(TableEntity::getGuestCapacity));
        return suitable;
    }


    // a function use to check reservation lock status
    public ReservationLockStatusDTO checkLockStatus(int tableId, LocalDate date, LocalTime time){
        return reservationLockingService.isLockValid(tableId, date, time);
    }

    // function for saving reservation in the database
    public void saveReservation(User user, FinalSubmissionDTO dto){

        TableEntity table = tableRepositoryService.getTableEntityById(dto.getTableId());

        Reservation.ReservationBuilder builder = Reservation.builder()
                .date(dto.getDate())
                .time(dto.getTime())
                .guestCount(dto.getGuestCount())
                .specialRequest(dto.getMessage())
                .status(ReservationStatus.PENDING)
                .savedAt(LocalDateTime.now())
                .table(table);


        //Step 1:  Check if user is not null means user is logged in
        if(user != null){
            logger.info("User is logged in.");
            builder.user(user);
        }else{
        // Step 2: Check if user submit a reservation as a guest user
            builder.name(null)
                    .email(null)
                    .phone(null);
        }

        // Step 3: finalize the reservation pojono
        Reservation reservation = builder.build();
        reservationRepositoryService.saveReservationNative(reservation);
    }
}
