package com.company.incidentplatform.incident;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ResponseActionRepository extends JpaRepository<ResponseActionEntity, UUID> {
    long countByIncidentId(UUID incidentId);
    List<ResponseActionEntity> findByIncidentIdOrderByPerformedAtAsc(UUID incidentId);
}
