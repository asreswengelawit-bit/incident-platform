package com.company.incidentplatform.notification;

import java.time.OffsetDateTime;
import java.util.UUID;

public record NotificationView(
        UUID id,
        UUID incidentId,
        IncidentLifecycleEventType eventType,
        NotificationDeliveryStatus status,
        String message,
        OffsetDateTime createdAt,
        OffsetDateTime readAt) {

    static NotificationView from(NotificationEntity entity) {
        return new NotificationView(
                entity.getId(),
                entity.getIncidentId(),
                entity.getEventType(),
                entity.getDeliveryStatus(),
                entity.getMessage(),
                entity.getCreatedAt(),
                entity.getReadAt());
    }
}
