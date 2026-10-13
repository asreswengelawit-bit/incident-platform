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
 * INCIDENT_COMMENT (Section 6.1, FR-1.4, FR-2.8).
 *
 * <p>The shared channel: a Reporter follows up on their own report (FR-1.4) and
 * an Analyst requests more information from them (FR-2.8). Append-only, because
 * FR-1.4 forbids editing the original report after submission to preserve
 * evidentiary integrity -- a correction is a further comment, never an edit, so
 * what the Reporter said first remains on the record.
 */
@Entity
@Table(name = "incident_comment")
public class IncidentCommentEntity {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "incident_id", nullable = false)
    private IncidentEntity incident;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "author_id", nullable = false)
    private AppUserEntity author;

    @Column(name = "comment", nullable = false)
    private String comment;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    /**
     * 7.4: comments are reporter-facing and are the most likely place for
     * incidental PII -- names and third-party addresses in a phishing report --
     * so the flag drives the FR-5.3 redaction option.
     */
    @Column(name = "contains_pii", nullable = false)
    private boolean containsPii;

    protected IncidentCommentEntity() {
    }

    public IncidentCommentEntity(
            UUID id, IncidentEntity incident, AppUserEntity author, String comment,
            OffsetDateTime createdAt, boolean containsPii) {
        this.id = id;
        this.incident = incident;
        this.author = author;
        this.comment = comment;
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

    public String getComment() {
        return comment;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public boolean isContainsPii() {
        return containsPii;
    }
}
