package com.company.incidentplatform.notification;

import com.company.incidentplatform.incident.IncidentSeverity;
import com.company.incidentplatform.security.PlatformRole;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.OffsetDateTime;
import java.util.UUID;
import java.util.Objects;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "notification_rule")
public class NotificationRuleEntity {

    @Id
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 40)
    private IncidentLifecycleEventType eventType;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.NAMED_ENUM)
    @Column(name = "min_severity")
    private IncidentSeverity minSeverity;

    @Column(name = "category_id")
    private UUID categoryId;

    @Column(name = "created_by")
    private UUID createdBy;

    @Column(name = "updated_by")
    private UUID updatedBy;

    @Column(name = "deleted_by")
    private UUID deletedBy;

    @Enumerated(EnumType.STRING)
    @Column(name = "channel", nullable = false, length = 16)
    private NotificationChannel channel;

    @Enumerated(EnumType.STRING)
    @Column(name = "recipient_role", nullable = false, length = 32)
    private PlatformRole recipientRole;

    @Column(name = "enabled", nullable = false)
    private boolean enabled;

    @Column(name = "deleted_at")
    private OffsetDateTime deletedAt;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    @Version
    @Column(name = "version", nullable = false)
    private Integer version;

    protected NotificationRuleEntity() {
    }

    public NotificationRuleEntity(
            UUID id,
            IncidentLifecycleEventType eventType,
            IncidentSeverity minSeverity,
            UUID categoryId,
            NotificationChannel channel,
            PlatformRole recipientRole,
            boolean enabled,
            UUID actorId,
            OffsetDateTime now) {
        if (recipientRole != PlatformRole.SECURITY_LEAD && recipientRole != PlatformRole.SECURITY_ADMIN) {
            throw new IllegalArgumentException("Notification recipient role must be SECURITY_LEAD or SECURITY_ADMIN");
        }
        this.id = Objects.requireNonNull(id);
        this.eventType = Objects.requireNonNull(eventType);
        validateSeverity(eventType, minSeverity);
        this.minSeverity = minSeverity;
        this.categoryId = categoryId;
        this.createdBy = Objects.requireNonNull(actorId);
        this.updatedBy = actorId;
        this.channel = Objects.requireNonNull(channel);
        this.recipientRole = recipientRole;
        this.enabled = enabled;
        this.createdAt = Objects.requireNonNull(now);
        this.updatedAt = now;
    }

    public UUID getId() {
        return id;
    }

    public IncidentLifecycleEventType getEventType() {
        return eventType;
    }

    public IncidentSeverity getMinSeverity() {
        return minSeverity;
    }

    public UUID getCategoryId() {
        return categoryId;
    }

    public NotificationChannel getChannel() {
        return channel;
    }

    public PlatformRole getRecipientRole() {
        return recipientRole;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public OffsetDateTime getUpdatedAt() {
        return updatedAt;
    }

    public Integer getVersion() {
        return version;
    }

    public UUID getCreatedBy() {
        return createdBy;
    }

    public UUID getUpdatedBy() {
        return updatedBy;
    }

    public UUID getDeletedBy() {
        return deletedBy;
    }

    public OffsetDateTime getDeletedAt() {
        return deletedAt;
    }

    public void update(
            IncidentLifecycleEventType eventType,
            IncidentSeverity minSeverity,
            UUID categoryId,
            NotificationChannel channel,
            PlatformRole recipientRole,
            boolean enabled,
            UUID actorId,
            OffsetDateTime now) {
        if (deletedAt != null) {
            throw new IllegalStateException("A deleted notification rule cannot be updated");
        }
        if (recipientRole != PlatformRole.SECURITY_LEAD && recipientRole != PlatformRole.SECURITY_ADMIN) {
            throw new IllegalArgumentException("Notification recipient role must be SECURITY_LEAD or SECURITY_ADMIN");
        }
        validateSeverity(eventType, minSeverity);
        this.eventType = Objects.requireNonNull(eventType);
        this.minSeverity = minSeverity;
        this.categoryId = categoryId;
        this.channel = Objects.requireNonNull(channel);
        this.recipientRole = recipientRole;
        this.enabled = enabled;
        this.updatedBy = Objects.requireNonNull(actorId);
        this.updatedAt = Objects.requireNonNull(now);
    }

    public void softDelete(UUID actorId, OffsetDateTime now) {
        if (deletedAt != null) {
            throw new IllegalStateException("Notification rule is already deleted");
        }
        this.enabled = false;
        this.deletedAt = Objects.requireNonNull(now);
        this.deletedBy = Objects.requireNonNull(actorId);
        this.updatedBy = actorId;
        this.updatedAt = now;
    }

    private static void validateSeverity(
            IncidentLifecycleEventType eventType, IncidentSeverity minSeverity) {
        if (eventType == IncidentLifecycleEventType.SEVERITY_CHANGED && minSeverity == null) {
            throw new IllegalArgumentException("minSeverity is required for SEVERITY_CHANGED rules");
        }
    }
}
