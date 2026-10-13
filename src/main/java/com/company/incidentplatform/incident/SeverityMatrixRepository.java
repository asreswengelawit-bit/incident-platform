package com.company.incidentplatform.incident;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * SEVERITY_MATRIX_RULE repository (FR-2.2, 12.2).
 */
@Repository
public interface SeverityMatrixRepository extends JpaRepository<SeverityMatrixRuleEntity, UUID> {

    /**
     * The single cell that governs a classification. Filtered on {@code isActive}
     * so that an Admin deactivating a cell withdraws it, rather than leaving an
     * inactive row to be picked up and treated as authoritative.
     */
    Optional<SeverityMatrixRuleEntity> findByImpactAndLikelihoodAndIsActiveTrue(
            short impact, short likelihood);

    /** FR-6.2: the whole configured matrix, for the Admin configuration view. */
    List<SeverityMatrixRuleEntity> findByIsActiveTrueOrderByImpactAscLikelihoodAsc();
}
