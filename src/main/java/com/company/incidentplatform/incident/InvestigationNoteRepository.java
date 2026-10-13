package com.company.incidentplatform.incident;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * INVESTIGATION_NOTE repository (FR-2.4).
 */
@Repository
public interface InvestigationNoteRepository extends JpaRepository<InvestigationNoteEntity, UUID> {

    /**
     * Chronological, which is the order an investigation is read in and the order
     * a status timeline is assembled from. Sorted in the database rather than in
     * memory so pagination would be correct if the note list ever grows large
     * enough to need it.
     */
    List<InvestigationNoteEntity> findByIncidentIdOrderByCreatedAtAsc(UUID incidentId);
}
