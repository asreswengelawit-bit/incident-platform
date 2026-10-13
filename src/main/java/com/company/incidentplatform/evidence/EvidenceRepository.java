package com.company.incidentplatform.evidence;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * Queries over {@code incident_evidence}.
 *
 * <p>Every method here is scoped to one incident. There is deliberately no
 * {@code findAll()} and no lookup by storage path alone: 7.6 makes the
 * authorization check the <em>only</em> route to a byte, and a repository method
 * that can fetch evidence without naming its parent incident is a method the
 * download endpoint will eventually be refactored to use, taking the object-level
 * check with it.
 */
public interface EvidenceRepository extends JpaRepository<EvidenceEntity, UUID> {

    /** Live evidence for an incident, newest first. Soft-deleted rows are excluded. */
    List<EvidenceEntity> findByIncidentIdAndDeletedAtIsNullOrderByUploadedAtDesc(UUID incidentId);

    /**
     * The 7.6 per-incident count limit.
     *
     * <p>Counted over live rows only, so that evidence removed by the 7.14
     * retention process frees a slot rather than permanently consuming one.
     * Quarantined rows are counted: they still occupy storage, and 7.6's limit
     * exists to bound storage consumption.
     */
    @Query("select count(e) from EvidenceEntity e where e.incident.id = :incidentId "
            + "and e.deletedAt is null")
    long countLiveByIncidentId(@Param("incidentId") UUID incidentId);

    /** Scoped by incident id so a caller cannot pair their incident with someone else's evidence id. */
    Optional<EvidenceEntity> findByIdAndIncidentId(UUID id, UUID incidentId);
}
