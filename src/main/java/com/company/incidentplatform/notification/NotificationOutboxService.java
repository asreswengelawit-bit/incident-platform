package com.company.incidentplatform.notification;

import com.company.incidentplatform.authorization.DepartmentKey;
import com.company.incidentplatform.incident.IncidentEntity;
import com.company.incidentplatform.incident.IncidentSeverity;
import com.company.incidentplatform.incident.IncidentStatus;
import com.company.incidentplatform.identity.AppUserEntity;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class NotificationOutboxService {

    private final NotificationOutboxRepository repository;
    private final ObjectMapper objectMapper;

    public NotificationOutboxService(NotificationOutboxRepository repository, ObjectMapper objectMapper) {
        this.repository = repository;
        this.objectMapper = objectMapper;
    }

    public UUID enqueue(
            IncidentLifecycleEventType eventType,
            IncidentEntity incident,
            IncidentStatus previousStatus,
            IncidentStatus status,
            AppUserEntity recipient) {
        return persist(createEvent(eventType, incident, previousStatus, status,
                null, incident.getSeverity(), recipient, null, null));
    }

    public UUID enqueueSeverityChanged(
            IncidentEntity incident, IncidentSeverity previousSeverity, IncidentSeverity newSeverity) {
        if (previousSeverity == newSeverity) {
            return null;
        }
        return persist(createEvent(
                IncidentLifecycleEventType.SEVERITY_CHANGED,
                incident,
                incident.getStatus(),
                incident.getStatus(),
                previousSeverity,
                newSeverity,
                null,
                null,
                null));
    }

    public UUID enqueueSlaBreach(IncidentEntity incident, SlaType slaType) {
        String key = "sla:" + incident.getId() + ":" + slaType + ":" + incident.getSlaCycle();
        if (repository.existsByIdempotencyKey(key)) {
            return UUID.nameUUIDFromBytes(key.getBytes(StandardCharsets.UTF_8));
        }
        return persist(createEvent(
                IncidentLifecycleEventType.SLA_BREACHED,
                incident,
                incident.getStatus(),
                incident.getStatus(),
                incident.getSeverity(),
                incident.getSeverity(),
                null,
                slaType,
                key));
    }

    private IncidentLifecycleEvent createEvent(
            IncidentLifecycleEventType eventType,
            IncidentEntity incident,
            IncidentStatus previousStatus,
            IncidentStatus status,
            IncidentSeverity previousSeverity,
            IncidentSeverity newSeverity,
            AppUserEntity recipient,
            SlaType slaType,
            String idempotencyKey) {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        String key = idempotencyKey == null
                ? "event:" + UUID.randomUUID()
                : idempotencyKey;
        UUID eventId = UUID.nameUUIDFromBytes(key.getBytes(StandardCharsets.UTF_8));
        IncidentLifecycleEvent event = new IncidentLifecycleEvent(
                eventId,
                incident.getId(),
                eventType,
                previousStatus,
                status,
                previousSeverity,
                newSeverity,
                incident.getCategory().getId(),
                DepartmentKey.normalize(incident.effectiveDepartment()),
                incident.getReporter() == null ? null : incident.getReporter().getId(),
                incident.getAssignee() == null ? null : incident.getAssignee().getId(),
                recipient == null ? null : recipient.getId(),
                slaType,
                key,
                now);
        return event;
    }

    private UUID persist(IncidentLifecycleEvent event) {
        try {
            repository.save(new NotificationOutboxEntity(
                    event.eventId(),
                    event.eventType(),
                    event.incidentId(),
                    objectMapper.writeValueAsString(event),
                    event.idempotencyKey(),
                    event.occurredAt()));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not serialize incident lifecycle event", e);
        }
        return event.eventId();
    }
}
