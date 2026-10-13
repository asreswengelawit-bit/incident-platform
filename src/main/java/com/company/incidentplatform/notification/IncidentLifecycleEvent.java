package com.company.incidentplatform.notification;

import com.company.incidentplatform.incident.IncidentSeverity;
import com.company.incidentplatform.incident.IncidentStatus;
import java.util.Objects;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Minimal lifecycle event. It deliberately contains no reporter, reporter
 * identity, incident title, description, or free-form reason.
 */
public record IncidentLifecycleEvent(
        UUID eventId,
        UUID incidentId,
        IncidentLifecycleEventType eventType,
        IncidentStatus previousStatus,
        IncidentStatus status,
        IncidentSeverity previousSeverity,
        IncidentSeverity newSeverity,
        UUID categoryId,
        String departmentKey,
        UUID reporterUserId,
        UUID assigneeUserId,
        UUID recipientUserId,
        SlaType slaType,
        String idempotencyKey,
        OffsetDateTime occurredAt) {

    public IncidentLifecycleEvent(
            UUID eventId,
            UUID incidentId,
            IncidentLifecycleEventType eventType,
            IncidentStatus previousStatus,
            IncidentStatus status,
            IncidentSeverity severity,
            UUID recipientUserId,
            OffsetDateTime occurredAt) {
        this(eventId, incidentId, eventType, previousStatus, status, null, severity,
                null, null, null, recipientUserId, recipientUserId, null,
                eventId.toString(), occurredAt);
    }

    public IncidentSeverity severity() {
        return newSeverity;
    }

    public IncidentLifecycleEvent {
        Objects.requireNonNull(eventId);
        Objects.requireNonNull(incidentId);
        Objects.requireNonNull(eventType);
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            idempotencyKey = "event:" + eventId;
        }
        Objects.requireNonNull(occurredAt);
    }
}
