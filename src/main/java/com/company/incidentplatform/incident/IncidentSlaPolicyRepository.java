package com.company.incidentplatform.incident;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * INCIDENT_SLA_POLICY repository (Section 6.3, 12.3).
 */
@Repository
public interface IncidentSlaPolicyRepository extends JpaRepository<IncidentSlaPolicyEntity, UUID> {

    /** The most specific row: this category, this severity. */
    Optional<IncidentSlaPolicyEntity> findByCategoryIdAndSeverityAndIsActiveTrue(
            UUID categoryId, IncidentSeverity severity);

    /** The organisation-wide default for this severity. */
    Optional<IncidentSlaPolicyEntity> findByCategoryIdIsNullAndSeverityAndIsActiveTrue(
            IncidentSeverity severity);

    /** FR-6.2: the effective policy set an Admin is editing. */
    List<IncidentSlaPolicyEntity> findByIsActiveTrue();
}
