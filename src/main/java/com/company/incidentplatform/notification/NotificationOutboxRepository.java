package com.company.incidentplatform.notification;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface NotificationOutboxRepository extends JpaRepository<NotificationOutboxEntity, UUID> {
    boolean existsByIdempotencyKey(String idempotencyKey);

    @Query(value = """
            SELECT * FROM incident_platform.notification_outbox
            WHERE status = 'PENDING' AND available_at <= :now
            ORDER BY created_at
            LIMIT 1
            FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    Optional<NotificationOutboxEntity> lockNextReady(@Param("now") OffsetDateTime now);
}
