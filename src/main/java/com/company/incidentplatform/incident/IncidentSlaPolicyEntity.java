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
 * INCIDENT_SLA_POLICY (FR-6.2, Section 12.3, 6.3).
 *
 * <p>One row per (category-or-organisation default, severity). A NULL
 * {@code categoryId} is the organisation-wide default for that severity, which
 * lets an Admin retune a noisy category without restating the other three
 * severities. The database enforces at most one active row per scope
 * ({@code uq_incident_sla_policy_scope} in V3).
 */
@Entity
@Table(name = "incident_sla_policy")
public class IncidentSlaPolicyEntity {

    @Id
    private UUID id;

    @Column(name = "category_id")
    private UUID categoryId;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false)
    private IncidentSeverity severity;

    @Column(name = "response_sla_minutes", nullable = false)
    private int responseSlaMinutes;

    /**
     * Nullable, and deliberately so. Section 12.3 defines a resolution target,
     * and V11 seeds it, but a deployment that has not confirmed those numbers
     * leaves this NULL rather than inheriting a deadline nobody agreed to --
     * {@code incident.sla_due_at} simply stays unset.
     */
    @Column(name = "resolution_sla_minutes")
    private Integer resolutionSlaMinutes;

    @Column(name = "business_hours_only", nullable = false)
    private boolean businessHoursOnly;

    @Column(name = "is_active", nullable = false)
    private boolean isActive;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    protected IncidentSlaPolicyEntity() {
    }

    /**
     * Full constructor, matching the other configuration entities.
     *
     * <p>A {@code null} {@code categoryId} is the organisation-wide default for the
     * severity; that null is the whole distinction {@link SlaDeadlineService}
     * resolves, so it is expressed here rather than by a separate factory that
     * would only hide which of the two row kinds is being built.
     */
    public IncidentSlaPolicyEntity(
            UUID id,
            UUID categoryId,
            IncidentSeverity severity,
            int responseSlaMinutes,
            Integer resolutionSlaMinutes,
            boolean businessHoursOnly,
            boolean active,
            OffsetDateTime createdAt,
            OffsetDateTime updatedAt) {
        this.id = id;
        this.categoryId = categoryId;
        this.severity = severity;
        this.responseSlaMinutes = responseSlaMinutes;
        this.resolutionSlaMinutes = resolutionSlaMinutes;
        this.businessHoursOnly = businessHoursOnly;
        this.isActive = active;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public UUID getId() {
        return id;
    }

    /** NULL means the organisation-wide default row for this severity. */
    public UUID getCategoryId() {
        return categoryId;
    }

    public IncidentSeverity getSeverity() {
        return severity;
    }

    public int getResponseSlaMinutes() {
        return responseSlaMinutes;
    }

    public Integer getResolutionSlaMinutes() {
        return resolutionSlaMinutes;
    }

    public boolean isBusinessHoursOnly() {
        return businessHoursOnly;
    }

    public boolean isActive() {
        return isActive;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public OffsetDateTime getUpdatedAt() {
        return updatedAt;
    }
}
