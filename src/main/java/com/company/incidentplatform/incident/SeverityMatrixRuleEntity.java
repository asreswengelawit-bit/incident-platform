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
 * SEVERITY_MATRIX_RULE (Section 6.1, FR-2.2, 12.2).
 *
 * <p>Section 5.5's Strategy pattern made concrete: the impact x likelihood ->
 * severity mapping is a row, not an {@code if} chain, so FR-6.2's
 * Admin-configurable matrix needs no code change. The 16 cells are seeded by
 * {@code V11} and remain editable.
 */
@Entity
@Table(name = "severity_matrix_rule")
public class SeverityMatrixRuleEntity {

    @Id
    private UUID id;

    /** Section 12.1 rank, 1..4 (1 = Severe). */
    @Column(name = "impact", nullable = false)
    private short impact;

    /** Section 12.1 rank, 1..4 (1 = Confirmed). */
    @Column(name = "likelihood", nullable = false)
    private short likelihood;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false)
    private IncidentSeverity severity;

    /**
     * Why this cell maps as it does. Retained because 7.11 requires the audit
     * trail to record the Impact/Likelihood inputs rather than only the resulting
     * severity, and because a matrix an Admin has edited is only reviewable if
     * the reasoning behind each cell survives.
     */
    @Column(name = "justification")
    private String justification;

    @Column(name = "is_active", nullable = false)
    private boolean isActive;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    protected SeverityMatrixRuleEntity() {
    }

    /**
     * Full constructor, matching the shape of the other configuration entities.
     *
     * <p>Exists for the same reason {@code IncidentCategoryEntity} has one: the
     * matrix is seeded by migration today, but FR-6.2 makes it Admin-editable
     * through the API, and seeding a cell through a repository and building one in
     * a test should not need two different mechanisms.
     */
    public SeverityMatrixRuleEntity(
            UUID id,
            short impact,
            short likelihood,
            IncidentSeverity severity,
            String justification,
            boolean active,
            OffsetDateTime createdAt,
            OffsetDateTime updatedAt) {
        this.id = id;
        this.impact = impact;
        this.likelihood = likelihood;
        this.severity = severity;
        this.justification = justification;
        this.isActive = active;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public UUID getId() {
        return id;
    }

    public short getImpact() {
        return impact;
    }

    public short getLikelihood() {
        return likelihood;
    }

    public IncidentSeverity getSeverity() {
        return severity;
    }

    public String getJustification() {
        return justification;
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
