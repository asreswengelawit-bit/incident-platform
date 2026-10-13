package com.company.incidentplatform.incident;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * INCIDENT_REPORTER_IDENTITY (Section 6.1, FR-1.6 restricted anonymous store).
 */
@Entity
@Table(name = "incident_reporter_identity")
public class IncidentReporterIdentityEntity {

    @Id
    @Column(name = "incident_id")
    private UUID incidentId;

    @Column(name = "reporter_id")
    private UUID reporterId;

    @Column(name = "reporter_email")
    private String reporterEmail;

    @Column(name = "reporter_ip", columnDefinition = "inet")
    private String reporterIp;

    @Column(name = "reporter_user_agent")
    private String reporterUserAgent;

    @Enumerated(EnumType.STRING)
    @Column(name = "source_channel", nullable = false)
    private IncidentSource sourceChannel;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "identity_accessed_at")
    private OffsetDateTime identityAccessedAt;

    @Column(name = "identity_accessed_by")
    private UUID identityAccessedBy;

    protected IncidentReporterIdentityEntity() {
    }

    public IncidentReporterIdentityEntity(
            UUID incidentId, UUID reporterId, String reporterEmail,
            String reporterIp, String reporterUserAgent, IncidentSource sourceChannel,
            OffsetDateTime createdAt) {
        this.incidentId = incidentId;
        this.reporterId = reporterId;
        this.reporterEmail = reporterEmail;
        this.reporterIp = reporterIp;
        this.reporterUserAgent = reporterUserAgent;
        this.sourceChannel = sourceChannel;
        this.createdAt = createdAt;
    }

    public UUID getIncidentId() {
        return incidentId;
    }

    public UUID getReporterId() {
        return reporterId;
    }

    public String getReporterEmail() {
        return reporterEmail;
    }

    public String getReporterIp() {
        return reporterIp;
    }

    public String getReporterUserAgent() {
        return reporterUserAgent;
    }

    public IncidentSource getSourceChannel() {
        return sourceChannel;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public OffsetDateTime getIdentityAccessedAt() {
        return identityAccessedAt;
    }

    public void setIdentityAccessedAt(OffsetDateTime identityAccessedAt) {
        this.identityAccessedAt = identityAccessedAt;
    }

    public UUID getIdentityAccessedBy() {
        return identityAccessedBy;
    }

    public void setIdentityAccessedBy(UUID identityAccessedBy) {
        this.identityAccessedBy = identityAccessedBy;
    }
}
