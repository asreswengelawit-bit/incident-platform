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
@Table(name = "notification")
public class NotificationEntity {

    @Id
    private UUID id;

    @Column(name = "event_id", nullable = false)
    private UUID eventId;

    @Column(name = "incident_id", nullable = false)
    private UUID incidentId;

    @Column(name = "recipient_user_id", nullable = false)
    private UUID recipientUserId;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 40)
    private IncidentLifecycleEventType eventType;

    @Enumerated(EnumType.STRING)
    @Column(name = "channel", nullable = false, length = 16)
    private NotificationChannel channel;

    @Enumerated(EnumType.STRING)
    @Column(name = "delivery_status", nullable = false, length = 16)
    private NotificationDeliveryStatus deliveryStatus;

    @Column(name = "message", nullable = false, length = 500)
    private String message;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "read_at")
    private OffsetDateTime readAt;

    protected NotificationEntity() {
    }

    public NotificationEntity(
            UUID id,
            UUID eventId,
            UUID incidentId,
            UUID recipientUserId,
            IncidentLifecycleEventType eventType,
            NotificationChannel channel,
            NotificationDeliveryStatus deliveryStatus,
            String message,
            OffsetDateTime createdAt) {
        this.id = id;
        this.eventId = eventId;
        this.incidentId = incidentId;
        this.recipientUserId = recipientUserId;
        this.eventType = eventType;
        this.channel = channel;
        this.deliveryStatus = deliveryStatus;
        this.message = message;
        this.createdAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public UUID getEventId() {
        return eventId;
    }

    public UUID getIncidentId() {
        return incidentId;
    }

    public UUID getRecipientUserId() {
        return recipientUserId;
    }

    public IncidentLifecycleEventType getEventType() {
        return eventType;
    }

    public NotificationChannel getChannel() {
        return channel;
    }

    public NotificationDeliveryStatus getDeliveryStatus() {
        return deliveryStatus;
    }

    public String getMessage() {
        return message;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public OffsetDateTime getReadAt() {
        return readAt;
    }

    public void markRead(OffsetDateTime now) {
        if (channel == NotificationChannel.IN_APP && deliveryStatus == NotificationDeliveryStatus.UNREAD) {
            deliveryStatus = NotificationDeliveryStatus.READ;
            readAt = now;
        }
    }

    public void markSent() {
        if (channel != NotificationChannel.EMAIL || deliveryStatus != NotificationDeliveryStatus.QUEUED) {
            throw new IllegalStateException("Only a queued email notification can be marked sent");
        }
        deliveryStatus = NotificationDeliveryStatus.SENT;
    }

    public void markDisabled() {
        if (channel != NotificationChannel.EMAIL || deliveryStatus != NotificationDeliveryStatus.QUEUED) {
            throw new IllegalStateException("Only a queued email notification can be disabled");
        }
        deliveryStatus = NotificationDeliveryStatus.DISABLED;
    }
}
