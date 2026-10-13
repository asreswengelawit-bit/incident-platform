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
 * INCIDENT_COLLABORATOR (Section 6.1, FR-2.3, 7.2.1).
 */
@Entity
@Table(name = "incident_collaborator")
public class IncidentCollaboratorEntity {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "incident_id", nullable = false)
    private IncidentEntity incident;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private AppUserEntity user;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "added_by", nullable = false)
    private AppUserEntity addedBy;

    @Column(name = "added_at", nullable = false)
    private OffsetDateTime addedAt;

    @Column(name = "removed_at")
    private OffsetDateTime removedAt;

    protected IncidentCollaboratorEntity() {
    }

    public IncidentCollaboratorEntity(
            UUID id, IncidentEntity incident, AppUserEntity user,
            AppUserEntity addedBy, OffsetDateTime addedAt) {
        this.id = id;
        this.incident = incident;
        this.user = user;
        this.addedBy = addedBy;
        this.addedAt = addedAt;
    }

    public UUID getId() {
        return id;
    }

    public IncidentEntity getIncident() {
        return incident;
    }

    public AppUserEntity getUser() {
        return user;
    }

    public AppUserEntity getAddedBy() {
        return addedBy;
    }

    public OffsetDateTime getAddedAt() {
        return addedAt;
    }

    public OffsetDateTime getRemovedAt() {
        return removedAt;
    }

    public void setRemovedAt(OffsetDateTime removedAt) {
        this.removedAt = removedAt;
    }
}
