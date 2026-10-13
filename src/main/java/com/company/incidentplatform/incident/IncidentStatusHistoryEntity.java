package com.company.incidentplatform.incident;

import com.company.incidentplatform.identity.AppUserEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * INCIDENT_STATUS_HISTORY (FR-1.3, FR-5.1, 7.10).
 */
@Entity
@Table(name = "incident_status_history")
public class IncidentStatusHistoryEntity {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "incident_id", nullable = false)
    private IncidentEntity incident;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.NAMED_ENUM)
    @Column(name = "from_status")
    private IncidentStatus fromStatus;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.NAMED_ENUM)
    @Column(name = "to_status", nullable = false)
    private IncidentStatus toStatus;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "changed_by")
    private AppUserEntity changedBy;

    @Column(name = "changed_at", nullable = false)
    private OffsetDateTime changedAt;

    @Column(name = "reason")
    private String reason;

    @Column(name = "request_id")
    private UUID requestId;

    protected IncidentStatusHistoryEntity() {
    }

    public IncidentStatusHistoryEntity(
            UUID id, IncidentEntity incident, IncidentStatus fromStatus,
            IncidentStatus toStatus, AppUserEntity changedBy, OffsetDateTime changedAt,
            String reason, UUID requestId) {
        this.id = id;
        this.incident = incident;
        this.fromStatus = fromStatus;
        this.toStatus = toStatus;
        this.changedBy = changedBy;
        this.changedAt = changedAt;
        this.reason = reason;
        this.requestId = requestId;
    }

    public UUID getId() {
        return id;
    }

    public IncidentEntity getIncident() {
        return incident;
    }

    public IncidentStatus getFromStatus() {
        return fromStatus;
    }

    public IncidentStatus getToStatus() {
        return toStatus;
    }

    public AppUserEntity getChangedBy() {
        return changedBy;
    }

    public OffsetDateTime getChangedAt() {
        return changedAt;
    }

    public String getReason() {
        return reason;
    }

    public UUID getRequestId() {
        return requestId;
    }
}
