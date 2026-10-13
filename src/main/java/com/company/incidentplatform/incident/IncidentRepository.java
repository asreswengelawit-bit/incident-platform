package com.company.incidentplatform.incident;

import com.company.incidentplatform.identity.AppUserEntity;
import java.util.Optional;
import java.util.UUID;
import java.time.OffsetDateTime;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;

/**
 * INCIDENT repository (Section 5.5, 6.1, 7.10).
 */
@Repository
public interface IncidentRepository
        extends JpaRepository<IncidentEntity, UUID>, JpaSpecificationExecutor<IncidentEntity> {

    Optional<IncidentEntity> findByIdempotencyKey(String idempotencyKey);

    @EntityGraph(attributePaths = {"category", "reporter", "assignee"})
    @Query("SELECT i FROM IncidentEntity i WHERE i.id = :id")
    Optional<IncidentEntity> findNotificationSnapshot(@Param("id") UUID id);

    /**
     * The current status alone, as a scalar projection.
     *
     * <p>Exists so a write endpoint can work out <em>which</em> capability 8.2
     * requires for a target status before it loads the incident: reopening is
     * Analyst-permitted from RESOLVED and Lead-only from CLOSED, so the
     * function-level check genuinely depends on the source state, and the whole
     * point of checking function level first is that the incident record is not
     * read before the caller has proved they may act on it.
     *
     * <p>A projection rather than {@code findById} for that reason: it
     * materialises a single enum and never puts the reporter's description or the
     * anonymous-report linkage in the persistence context of a request that is
     * about to be refused. Empty for a missing incident, in which case the
     * object-level guard denies on a null snapshot and the caller gets the same
     * refusal as for one that exists but is not theirs -- 7.5 forbids the
     * difference.
     */
    @Query("SELECT i.status FROM IncidentEntity i WHERE i.id = :id")
    Optional<IncidentStatus> findStatusById(@Param("id") UUID id);

    @Query(value = """
            SELECT * FROM incident_platform.incident
            WHERE deleted_at IS NULL
              AND status IN ('NEW', 'ASSIGNED', 'TRIAGED')
              AND sla_response_due_at IS NOT NULL
              AND sla_response_due_at <= :now
            """, nativeQuery = true)
    List<IncidentEntity> findResponseSlaBreaches(@Param("now") OffsetDateTime now);

    @Query(value = """
            SELECT * FROM incident_platform.incident
            WHERE deleted_at IS NULL
              AND status NOT IN ('RESOLVED', 'CLOSED', 'REJECTED')
              AND sla_due_at IS NOT NULL
              AND sla_due_at <= :now
            """, nativeQuery = true)
    List<IncidentEntity> findResolutionSlaBreaches(@Param("now") OffsetDateTime now);

    /**
     * Section 7.10: Atomic assignment to prevent race conditions when two analysts
     * attempt to self-assign the same unassigned incident simultaneously.
     */
    @Modifying
    @Query("""
           UPDATE IncidentEntity i
              SET i.assignee = :newAssignee,
                  i.status = :newStatus
            WHERE i.id = :id
              AND i.assignee IS NULL
           """)
    int assignUnassignedAtomic(
            @Param("id") UUID id,
            @Param("newAssignee") AppUserEntity newAssignee,
            @Param("newStatus") IncidentStatus newStatus);

    /**
     * Section 7.10 / 8.2: Atomic reassignment by Security Lead or Admin.
     */
    @Modifying
    @Query("""
           UPDATE IncidentEntity i
              SET i.assignee = :newAssignee,
                  i.status = :newStatus
            WHERE i.id = :id
              AND (i.assignee = :currentAssignee OR i.assignee IS NULL)
           """)
    int reassignAtomic(
            @Param("id") UUID id,
            @Param("newAssignee") AppUserEntity newAssignee,
            @Param("currentAssignee") AppUserEntity currentAssignee,
            @Param("newStatus") IncidentStatus newStatus);
}
