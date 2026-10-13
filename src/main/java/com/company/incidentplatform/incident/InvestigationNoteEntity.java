package com.company.incidentplatform.incident;

import com.company.incidentplatform.identity.AppUserEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * INVESTIGATION_NOTE (Section 6.1, FR-2.4).
 *
 * <p>Analyst-only. This table is the 7.2 property-level example the document
 * names -- "a Reporter seeing internal-only fields on their own incident (e.g.
 * analyst-only investigation notes)" -- so it is never joined by a
 * Reporter-facing query and never serialised into a Reporter DTO. {@code V6}
 * records the same split from the other direction: notes are the internal
 * channel, {@code incident_comment} is the shared one.
 */
@Entity
@Table(name = "investigation_note")
public class InvestigationNoteEntity {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "incident_id", nullable = false)
    private IncidentEntity incident;

    /** FR-2.4: "timestamped and attributable to the author". */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "author_id", nullable = false)
    private AppUserEntity author;

    @Column(name = "note", nullable = false)
    private String note;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    /** 7.4: notes reach FR-5.3 exports, so PII is flagged for redaction. */
    @Column(name = "contains_pii", nullable = false)
    private boolean containsPii;

    protected InvestigationNoteEntity() {
    }

    public InvestigationNoteEntity(
            UUID id, IncidentEntity incident, AppUserEntity author, String note,
            OffsetDateTime createdAt, boolean containsPii) {
        this.id = id;
        this.incident = incident;
        this.author = author;
        this.note = note;
        this.createdAt = createdAt;
        this.containsPii = containsPii;
    }

    public UUID getId() {
        return id;
    }

    public IncidentEntity getIncident() {
        return incident;
    }

    public AppUserEntity getAuthor() {
        return author;
    }

    public String getNote() {
        return note;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public boolean isContainsPii() {
        return containsPii;
    }
}
