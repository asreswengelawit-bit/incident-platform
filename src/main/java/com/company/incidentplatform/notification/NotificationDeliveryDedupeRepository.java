package com.company.incidentplatform.notification;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import jakarta.persistence.LockModeType;

public interface NotificationDeliveryDedupeRepository
        extends JpaRepository<NotificationDeliveryDedupeEntity, UUID> {

    Optional<NotificationDeliveryDedupeEntity> findByIdempotencyKeyAndRecipientUserIdAndChannel(
            String idempotencyKey, UUID recipientUserId, NotificationChannel channel);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select d from NotificationDeliveryDedupeEntity d
            where d.idempotencyKey = :key and d.recipientUserId = :recipient
              and d.channel = :channel
            """)
    Optional<NotificationDeliveryDedupeEntity> lockDelivery(
            @Param("key") String key,
            @Param("recipient") UUID recipient,
            @Param("channel") NotificationChannel channel);
}
