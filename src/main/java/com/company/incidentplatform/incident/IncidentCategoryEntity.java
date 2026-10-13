package com.company.incidentplatform.incident;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * INCIDENT_CATEGORY (Section 6.1, FR-6.2).
 */
@Entity
@Table(name = "incident_category")
public class IncidentCategoryEntity {

    @Id
    private UUID id;

    @Column(name = "name", nullable = false, unique = true)
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "default_sla_hours", nullable = false)
    private int defaultSlaHours;

    @Column(name = "retention_months", nullable = false)
    private int retentionMonths;

    @Column(name = "max_evidence_size_bytes", nullable = false)
    private long maxEvidenceSizeBytes;

    @Column(name = "max_evidence_files", nullable = false)
    private int maxEvidenceFiles;

    @Column(name = "is_active", nullable = false)
    private boolean isActive;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    @Column(name = "deleted_at")
    private OffsetDateTime deletedAt;

    @Version
    @Column(name = "version", nullable = false)
    private Integer version;

    protected IncidentCategoryEntity() {
    }

    public IncidentCategoryEntity(
            UUID id, String name, String description, int defaultSlaHours,
            int retentionMonths, long maxEvidenceSizeBytes, int maxEvidenceFiles,
            boolean isActive, OffsetDateTime createdAt, OffsetDateTime updatedAt) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.defaultSlaHours = defaultSlaHours;
        this.retentionMonths = retentionMonths;
        this.maxEvidenceSizeBytes = maxEvidenceSizeBytes;
        this.maxEvidenceFiles = maxEvidenceFiles;
        this.isActive = isActive;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.version = 0;
    }

    public UUID getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public int getDefaultSlaHours() {
        return defaultSlaHours;
    }

    public int getRetentionMonths() {
        return retentionMonths;
    }

    public long getMaxEvidenceSizeBytes() {
        return maxEvidenceSizeBytes;
    }

    public int getMaxEvidenceFiles() {
        return maxEvidenceFiles;
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

    public OffsetDateTime getDeletedAt() {
        return deletedAt;
    }

    public Integer getVersion() {
        return version;
    }
}
