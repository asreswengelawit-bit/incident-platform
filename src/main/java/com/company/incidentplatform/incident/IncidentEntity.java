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
import jakarta.persistence.Version;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * INCIDENT -- the core incident aggregate (Section 6.1, FR-1.1, FR-2.7, 8.1).
 *
 * <p>Section 8.1 / FR-2.7: {@code escalated}, {@code escalatedAt}, and
 * {@code escalationReason} are ATTRIBUTES on the incident, NOT a lifecycle status.
 *
 * <p>Section 7.10: {@code version} provides optimistic locking.
 */
@Entity
@Table(name = "incident")
public class IncidentEntity {

    @Id
    private UUID id;

    @Column(name = "title", nullable = false)
    private String title;

    @Column(name = "description", nullable = false)
    private String description;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "category_id", nullable = false)
    private IncidentCategoryEntity category;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.NAMED_ENUM)
    @Column(name = "severity")
    private IncidentSeverity severity;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.NAMED_ENUM)
    @Column(name = "status", nullable = false)
    private IncidentStatus status;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "reporter_id", nullable = false)
    private AppUserEntity reporter;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "assignee_id")
    private AppUserEntity assignee;

    @Column(name = "occurred_at", nullable = false)
    private OffsetDateTime occurredAt;

    @Column(name = "reported_at", nullable = false)
    private OffsetDateTime reportedAt;

    @Column(name = "resolved_at")
    private OffsetDateTime resolvedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "group_id")
    private IncidentGroupEntity group;

    @Column(name = "escalated", nullable = false)
    private boolean escalated;

    @Column(name = "escalated_at")
    private OffsetDateTime escalatedAt;

    @Column(name = "escalation_reason")
    private String escalationReason;

    @Column(name = "idempotency_key")
    private String idempotencyKey;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.NAMED_ENUM)
    @Column(name = "source", nullable = false)
    private IncidentSource source;

    @Column(name = "anonymous", nullable = false)
    private boolean anonymous;

    @Column(name = "contains_pii", nullable = false)
    private boolean containsPii;

    @Column(name = "affected_system")
    private String affectedSystem;

    @Column(name = "affected_department")
    private String affectedDepartment;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "severity_overridden_by")
    private AppUserEntity severityOverriddenBy;

    @Column(name = "severity_override_reason")
    private String severityOverrideReason;

    @Column(name = "resolution_summary")
    private String resolutionSummary;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "resolved_by")
    private AppUserEntity resolvedBy;

    @Column(name = "rejected_reason")
    private String rejectedReason;

    @Column(name = "closed_at")
    private OffsetDateTime closedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "closed_by")
    private AppUserEntity closedBy;

    @Column(name = "sla_response_due_at")
    private OffsetDateTime slaResponseDueAt;

    @Column(name = "sla_due_at")
    private OffsetDateTime slaDueAt;

    @Column(name = "sla_cycle", nullable = false)
    private int slaCycle;

    @Column(name = "legal_hold", nullable = false)
    private boolean legalHold;

    @Column(name = "legal_hold_reason")
    private String legalHoldReason;

    @Column(name = "legal_hold_set_at")
    private OffsetDateTime legalHoldSetAt;

    @Column(name = "deleted_at")
    private OffsetDateTime deletedAt;

    @Version
    @Column(name = "version", nullable = false)
    private Integer version;

    protected IncidentEntity() {
    }

    public IncidentEntity(
            UUID id, String title, String description, IncidentCategoryEntity category,
            IncidentSeverity severity, AppUserEntity reporter, OffsetDateTime occurredAt,
            OffsetDateTime reportedAt, String affectedSystem, String affectedDepartment,
            boolean anonymous, boolean containsPii, IncidentSource source, String idempotencyKey) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.category = category;
        this.severity = severity;
        this.status = IncidentStatus.NEW;
        this.reporter = reporter;
        this.occurredAt = occurredAt;
        this.reportedAt = reportedAt;
        this.affectedSystem = affectedSystem;
        this.affectedDepartment = affectedDepartment;
        this.anonymous = anonymous;
        this.containsPii = containsPii;
        this.source = source != null ? source : IncidentSource.WEB_UI;
        this.idempotencyKey = idempotencyKey;
        this.escalated = false;
        this.legalHold = false;
        this.version = 0;
    }

    public UUID getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public IncidentCategoryEntity getCategory() {
        return category;
    }

    public void setCategory(IncidentCategoryEntity category) {
        this.category = category;
    }

    public IncidentSeverity getSeverity() {
        return severity;
    }

    public void setSeverity(IncidentSeverity severity) {
        this.severity = severity;
    }

    public IncidentStatus getStatus() {
        return status;
    }

    public void setStatus(IncidentStatus status) {
        this.status = status;
    }

    public AppUserEntity getReporter() {
        return reporter;
    }

    public AppUserEntity getAssignee() {
        return assignee;
    }

    public void setAssignee(AppUserEntity assignee) {
        this.assignee = assignee;
    }

    public OffsetDateTime getOccurredAt() {
        return occurredAt;
    }

    public OffsetDateTime getReportedAt() {
        return reportedAt;
    }

    public OffsetDateTime getResolvedAt() {
        return resolvedAt;
    }

    public void setResolvedAt(OffsetDateTime resolvedAt) {
        this.resolvedAt = resolvedAt;
    }

    public IncidentGroupEntity getGroup() {
        return group;
    }

    public void setGroup(IncidentGroupEntity group) {
        this.group = group;
    }

    public boolean isEscalated() {
        return escalated;
    }

    public void setEscalated(boolean escalated) {
        this.escalated = escalated;
    }

    public OffsetDateTime getEscalatedAt() {
        return escalatedAt;
    }

    public void setEscalatedAt(OffsetDateTime escalatedAt) {
        this.escalatedAt = escalatedAt;
    }

    public String getEscalationReason() {
        return escalationReason;
    }

    public void setEscalationReason(String escalationReason) {
        this.escalationReason = escalationReason;
    }

    public String getIdempotencyKey() {
        return idempotencyKey;
    }

    public IncidentSource getSource() {
        return source;
    }

    public boolean isAnonymous() {
        return anonymous;
    }

    public boolean isContainsPii() {
        return containsPii;
    }

    public void setContainsPii(boolean containsPii) {
        this.containsPii = containsPii;
    }

    public String getAffectedSystem() {
        return affectedSystem;
    }

    public void setAffectedSystem(String affectedSystem) {
        this.affectedSystem = affectedSystem;
    }

    public String getAffectedDepartment() {
        return affectedDepartment;
    }

    public void setAffectedDepartment(String affectedDepartment) {
        this.affectedDepartment = affectedDepartment;
    }

    public String effectiveDepartment() {
        if (affectedDepartment != null && !affectedDepartment.isBlank()) {
            return affectedDepartment.trim();
        }
        return reporter != null ? reporter.getDepartment() : null;
    }

    public AppUserEntity getSeverityOverriddenBy() {
        return severityOverriddenBy;
    }

    public void setSeverityOverriddenBy(AppUserEntity severityOverriddenBy) {
        this.severityOverriddenBy = severityOverriddenBy;
    }

    public String getSeverityOverrideReason() {
        return severityOverrideReason;
    }

    public void setSeverityOverrideReason(String severityOverrideReason) {
        this.severityOverrideReason = severityOverrideReason;
    }

    public String getResolutionSummary() {
        return resolutionSummary;
    }

    public void setResolutionSummary(String resolutionSummary) {
        this.resolutionSummary = resolutionSummary;
    }

    public AppUserEntity getResolvedBy() {
        return resolvedBy;
    }

    public void setResolvedBy(AppUserEntity resolvedBy) {
        this.resolvedBy = resolvedBy;
    }

    public String getRejectedReason() {
        return rejectedReason;
    }

    public void setRejectedReason(String rejectedReason) {
        this.rejectedReason = rejectedReason;
    }

    public OffsetDateTime getClosedAt() {
        return closedAt;
    }

    public void setClosedAt(OffsetDateTime closedAt) {
        this.closedAt = closedAt;
    }

    public AppUserEntity getClosedBy() {
        return closedBy;
    }

    public void setClosedBy(AppUserEntity closedBy) {
        this.closedBy = closedBy;
    }

    public OffsetDateTime getSlaResponseDueAt() {
        return slaResponseDueAt;
    }

    public void setSlaResponseDueAt(OffsetDateTime slaResponseDueAt) {
        this.slaResponseDueAt = slaResponseDueAt;
    }

    public OffsetDateTime getSlaDueAt() {
        return slaDueAt;
    }

    public int getSlaCycle() {
        return slaCycle;
    }

    public void incrementSlaCycle() {
        slaCycle++;
    }

    public void setSlaDueAt(OffsetDateTime slaDueAt) {
        this.slaDueAt = slaDueAt;
    }

    public boolean isLegalHold() {
        return legalHold;
    }

    public void setLegalHold(boolean legalHold) {
        this.legalHold = legalHold;
    }

    public String getLegalHoldReason() {
        return legalHoldReason;
    }

    public void setLegalHoldReason(String legalHoldReason) {
        this.legalHoldReason = legalHoldReason;
    }

    public OffsetDateTime getLegalHoldSetAt() {
        return legalHoldSetAt;
    }

    public void setLegalHoldSetAt(OffsetDateTime legalHoldSetAt) {
        this.legalHoldSetAt = legalHoldSetAt;
    }

    public OffsetDateTime getDeletedAt() {
        return deletedAt;
    }

    public boolean isDeleted() {
        return deletedAt != null;
    }

    public void setDeletedAt(OffsetDateTime deletedAt) {
        this.deletedAt = deletedAt;
    }

    public Integer getVersion() {
        return version;
    }
}
