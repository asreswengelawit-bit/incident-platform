package com.company.incidentplatform.notification;

import java.util.UUID;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NotificationRepository extends JpaRepository<NotificationEntity, UUID> {
    boolean existsByEventIdAndRecipientUserIdAndChannel(
            UUID eventId, UUID recipientUserId, NotificationChannel channel);

    Optional<NotificationEntity> findByEventIdAndRecipientUserIdAndChannel(
            UUID eventId, UUID recipientUserId, NotificationChannel channel);

    Page<NotificationEntity> findByRecipientUserIdAndChannelOrderByCreatedAtDesc(
            UUID recipientUserId, NotificationChannel channel, Pageable pageable);

    Optional<NotificationEntity> findByIdAndRecipientUserIdAndChannel(
            UUID id, UUID recipientUserId, NotificationChannel channel);
}
