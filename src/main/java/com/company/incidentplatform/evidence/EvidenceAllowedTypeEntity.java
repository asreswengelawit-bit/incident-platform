package com.company.incidentplatform.evidence;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

/**
 * {@code incident_category_allowed_type} (Section 3/V3, 7.6, FR-1.2).
 *
 * <p>The per-category allow-list 7.6 asks for, and it is the reason a "which file
 * types may this category accept" question has an answer that an Admin can change
 * without a redeploy. The table carries both a MIME type and an optional
 * extension, and the column comment on {@code extension} in {@code V3} is the
 * instruction this class implements: the extension is stored as <em>additional
 * signal</em> and is never trusted on its own. Only {@link #getMimeType()} is
 * consulted for the accept/refuse decision, and it is matched against the
 * <em>sniffed</em> type.
 *
 * <p>Read-only in practice. There is no write path in the evidence module; rows
 * are maintained through category administration (FR-6.2), which is not built
 * yet.
 */
@Entity
@Table(name = "incident_category_allowed_type")
public class EvidenceAllowedTypeEntity {

    @EmbeddedId
    private Key id;

    /**
     * Present for display and for the admin UI's own affordance. Explicitly not
     * read by the decision path -- see the class comment.
     */
    @Column(name = "extension")
    private String extension;

    protected EvidenceAllowedTypeEntity() {
    }

    public EvidenceAllowedTypeEntity(UUID categoryId, String mimeType, String extension) {
        this.id = new Key(categoryId, mimeType);
        this.extension = extension;
    }

    public Key getId() {
        return id;
    }

    /**
     * Delegated to the composite key rather than held in a second field.
     * {@code mime_type} is part of {@link Key}, so mapping it again here duplicated
     * one column across two properties, which Hibernate rejects outright (it fails
     * SessionFactory construction, so it takes down every context that boots the
     * entity manager, not just this entity). Keeping a copy would also mean two
     * fields holding one value with nothing keeping them in step.
     */
    public String getMimeType() {
        return id.getMimeType();
    }

    public String getExtension() {
        return extension;
    }

    /** Composite key: one allow-list entry is (category, mime type). */
    @Embeddable
    public static class Key implements Serializable {

        @Column(name = "category_id", nullable = false)
        private UUID categoryId;

        @Column(name = "mime_type", nullable = false)
        private String mimeType;

        protected Key() {
        }

        public Key(UUID categoryId, String mimeType) {
            this.categoryId = categoryId;
            this.mimeType = mimeType;
        }

        public UUID getCategoryId() {
            return categoryId;
        }

        public String getMimeType() {
            return mimeType;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof Key key)) {
                return false;
            }
            return Objects.equals(categoryId, key.categoryId) && Objects.equals(mimeType, key.mimeType);
        }

        @Override
        public int hashCode() {
            return Objects.hash(categoryId, mimeType);
        }
    }
}
