package com.company.incidentplatform.notification;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "notification_outbox")
public class NotificationOutboxEntity {

    @Id
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 40)
    private IncidentLifecycleEventType eventType;

    @Column(name = "incident_id", nullable = false)
    private UUID incidentId;

    @Column(name = "payload", nullable = false, columnDefinition = "text")
    private String payload;

    @Column(name = "idempotency_key", nullable = false, length = 240)
    private String idempotencyKey;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 24)
    private NotificationOutboxStatus status;

    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "available_at", nullable = false)
    private OffsetDateTime availableAt;

    @Column(name = "published_at")
    private OffsetDateTime publishedAt;

    @Column(name = "dead_lettered_at")
    private OffsetDateTime deadLetteredAt;

    @Column(name = "last_error", length = 1000)
    private String lastError;

    protected NotificationOutboxEntity() {
    }

    public NotificationOutboxEntity(
            UUID id,
            IncidentLifecycleEventType eventType,
            UUID incidentId,
            String payload,
            OffsetDateTime createdAt) {
        this(id, eventType, incidentId, payload, "event:" + id, createdAt);
    }

    public NotificationOutboxEntity(
            UUID id,
            IncidentLifecycleEventType eventType,
            UUID incidentId,
            String payload,
            String idempotencyKey,
            OffsetDateTime createdAt) {
        this.id = id;
        this.eventType = eventType;
        this.incidentId = incidentId;
        this.payload = payload;
        this.idempotencyKey = idempotencyKey;
        this.status = NotificationOutboxStatus.PENDING;
        this.createdAt = createdAt;
        this.availableAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public IncidentLifecycleEventType getEventType() {
        return eventType;
    }

    public UUID getIncidentId() {
        return incidentId;
    }

    public String getPayload() {
        return payload;
    }

    public String getIdempotencyKey() {
        return idempotencyKey;
    }

    public NotificationOutboxStatus getStatus() {
        return status;
    }

    public int getAttempts() {
        return attempts;
    }

    public OffsetDateTime getAvailableAt() {
        return availableAt;
    }

    public void markPublished(OffsetDateTime now) {
        status = NotificationOutboxStatus.PUBLISHED;
        publishedAt = now;
        lastError = null;
    }

    public void recordFailure(String error, OffsetDateTime retryAt, OffsetDateTime failedAt, int maxAttempts) {
        attempts++;
        lastError = error == null ? "Kafka publish failed" : error.substring(0, Math.min(error.length(), 1000));
        if (attempts >= maxAttempts) {
            status = NotificationOutboxStatus.DEAD_LETTERED;
            deadLetteredAt = failedAt;
        } else {
            availableAt = retryAt;
        }
    }

    public void markDeadLettered(String error, OffsetDateTime now) {
        status = NotificationOutboxStatus.DEAD_LETTERED;
        deadLetteredAt = now;
        lastError = error == null ? "Notification consumer exhausted retries"
                : error.substring(0, Math.min(error.length(), 1000));
    }
}
