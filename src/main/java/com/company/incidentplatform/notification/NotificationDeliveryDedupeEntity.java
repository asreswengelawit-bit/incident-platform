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
@Table(name = "notification_delivery_dedupe")
public class NotificationDeliveryDedupeEntity {

    @Id
    private UUID id;

    @Column(name = "idempotency_key", nullable = false, length = 240)
    private String idempotencyKey;

    @Column(name = "recipient_user_id", nullable = false)
    private UUID recipientUserId;

    @Enumerated(EnumType.STRING)
    @Column(name = "channel", nullable = false, length = 16)
    private NotificationChannel channel;

    @Enumerated(EnumType.STRING)
    @Column(name = "delivery_status", nullable = false, length = 16)
    private DeliveryDedupeStatus deliveryStatus;

    @Column(name = "message_id", nullable = false, length = 255)
    private String messageId;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    protected NotificationDeliveryDedupeEntity() {
    }

    public NotificationDeliveryDedupeEntity(
            UUID id, String idempotencyKey, UUID recipientUserId, NotificationChannel channel,
            DeliveryDedupeStatus deliveryStatus, String messageId, OffsetDateTime now) {
        this.id = id;
        this.idempotencyKey = idempotencyKey;
        this.recipientUserId = recipientUserId;
        this.channel = channel;
        this.deliveryStatus = deliveryStatus;
        this.messageId = messageId;
        this.createdAt = now;
        this.updatedAt = now;
    }

    public DeliveryDedupeStatus getDeliveryStatus() {
        return deliveryStatus;
    }

    public String getMessageId() {
        return messageId;
    }

    public void markSent(OffsetDateTime now) {
        deliveryStatus = DeliveryDedupeStatus.SENT;
        updatedAt = now;
    }
}
