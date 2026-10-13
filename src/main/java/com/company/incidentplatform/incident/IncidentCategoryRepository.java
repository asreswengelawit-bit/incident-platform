package com.company.incidentplatform.incident;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IncidentCategoryRepository extends JpaRepository<IncidentCategoryEntity, UUID> {
    Optional<IncidentCategoryEntity> findByNameIgnoreCase(String name);
}
