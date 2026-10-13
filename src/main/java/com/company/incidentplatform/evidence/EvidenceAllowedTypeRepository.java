package com.company.incidentplatform.evidence;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Reads the per-category allow-list of {@code V3}. */
public interface EvidenceAllowedTypeRepository
        extends JpaRepository<EvidenceAllowedTypeEntity, EvidenceAllowedTypeEntity.Key> {

    /**
     * All allow-listed MIME types for one category.
     *
     * <p>Returns an empty list for a category with no configured types, which the
     * policy reads as "fall back to the platform default set" rather than as "this
     * category accepts nothing" -- see {@code EvidenceTypePolicy} for why, and
     * note that a category which genuinely must accept nothing is expressed by
     * deactivating it, not by an empty allow-list.
     */
    List<EvidenceAllowedTypeEntity> findByIdCategoryId(UUID categoryId);
}
