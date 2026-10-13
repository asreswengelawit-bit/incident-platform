package com.company.incidentplatform.incident;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * INCIDENT_COMMENT repository (FR-1.4, FR-2.8).
 */
@Repository
public interface IncidentCommentRepository extends JpaRepository<IncidentCommentEntity, UUID> {

    List<IncidentCommentEntity> findByIncidentIdOrderByCreatedAtAsc(UUID incidentId);
}
