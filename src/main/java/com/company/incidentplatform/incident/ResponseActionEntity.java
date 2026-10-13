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
 * RESPONSE_ACTION (Section 6.1, FR-2.5, 3.3, 5.5 Command pattern).
 */
@Entity
@Table(name = "response_action")
public class ResponseActionEntity {

    @Id
    private UUID id;

    @Column(name = "incident_id", nullable = false)
    private UUID incidentId;

    @Column(name = "action_type", nullable = false)
    private String actionType;

    @Column(name = "description")
    private String description;

    @Column(name = "outcome", nullable = false)
    private String outcome;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "performed_by", nullable = false)
    private AppUserEntity performedBy;

    @Column(name = "performed_at", nullable = false)
    private OffsetDateTime performedAt;

    protected ResponseActionEntity() {
    }

    public ResponseActionEntity(
            UUID id, UUID incidentId, String actionType, String description,
            String outcome, AppUserEntity performedBy, OffsetDateTime performedAt) {
        this.id = id;
        this.incidentId = incidentId;
        this.actionType = actionType;
        this.description = description;
        this.outcome = outcome;
        this.performedBy = performedBy;
        this.performedAt = performedAt;
    }

    public UUID getId() {
        return id;
    }

    public UUID getIncidentId() {
        return incidentId;
    }

    public String getActionType() {
        return actionType;
    }

    public String getDescription() {
        return description;
    }

    public String getOutcome() {
        return outcome;
    }

    public AppUserEntity getPerformedBy() {
        return performedBy;
    }

    public OffsetDateTime getPerformedAt() {
        return performedAt;
    }
}
