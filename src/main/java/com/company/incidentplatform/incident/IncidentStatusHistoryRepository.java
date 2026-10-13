package com.company.incidentplatform.incident;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IncidentStatusHistoryRepository extends JpaRepository<IncidentStatusHistoryEntity, UUID> {
    List<IncidentStatusHistoryEntity> findByIncidentIdOrderByChangedAtAsc(UUID incidentId);
}
