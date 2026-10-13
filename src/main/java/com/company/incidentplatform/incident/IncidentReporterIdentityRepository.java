package com.company.incidentplatform.incident;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * FR-1.6 restricted repository. Only called by authorized service when
 * checking can_view_reporter_identity and audited.
 */
@Repository
public interface IncidentReporterIdentityRepository extends JpaRepository<IncidentReporterIdentityEntity, UUID> {
    Optional<IncidentReporterIdentityEntity> findByIncidentId(UUID incidentId);
}
