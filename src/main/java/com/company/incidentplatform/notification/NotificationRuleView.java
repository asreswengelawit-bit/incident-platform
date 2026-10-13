package com.company.incidentplatform.notification;

import com.company.incidentplatform.incident.IncidentSeverity;
import com.company.incidentplatform.security.PlatformRole;
import java.time.OffsetDateTime;
import java.util.UUID;

public record NotificationRuleView(
        UUID id,
        IncidentLifecycleEventType eventType,
        IncidentSeverity minSeverity,
        UUID categoryId,
        NotificationChannel channel,
        PlatformRole recipientRole,
        boolean enabled,
        OffsetDateTime createdAt,
        UUID createdBy,
        OffsetDateTime updatedAt,
        UUID updatedBy,
        OffsetDateTime deletedAt,
        UUID deletedBy,
        Integer version) {

    public static NotificationRuleView from(NotificationRuleEntity entity) {
        return new NotificationRuleView(
                entity.getId(),
                entity.getEventType(),
                entity.getMinSeverity(),
                entity.getCategoryId(),
                entity.getChannel(),
                entity.getRecipientRole(),
                entity.isEnabled(),
                entity.getCreatedAt(),
                entity.getCreatedBy(),
                entity.getUpdatedAt(),
                entity.getUpdatedBy(),
                entity.getDeletedAt(),
                entity.getDeletedBy(),
                entity.getVersion());
    }
}
