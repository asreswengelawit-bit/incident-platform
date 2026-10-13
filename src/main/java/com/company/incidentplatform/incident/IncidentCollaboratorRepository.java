package com.company.incidentplatform.incident;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface IncidentCollaboratorRepository extends JpaRepository<IncidentCollaboratorEntity, UUID> {

    @Query("SELECT c FROM IncidentCollaboratorEntity c WHERE c.incident.id = :incidentId AND c.removedAt IS NULL")
    List<IncidentCollaboratorEntity> findActiveByIncidentId(@Param("incidentId") UUID incidentId);

    @Query("SELECT c FROM IncidentCollaboratorEntity c WHERE c.incident.id = :incidentId AND c.user.id = :userId AND c.removedAt IS NULL")
    Optional<IncidentCollaboratorEntity> findActiveByIncidentIdAndUserId(
            @Param("incidentId") UUID incidentId, @Param("userId") UUID userId);
}
