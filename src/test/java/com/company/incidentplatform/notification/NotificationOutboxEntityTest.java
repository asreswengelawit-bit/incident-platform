package com.company.incidentplatform.notification;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class NotificationOutboxEntityTest {

    @Test
    void backsOffAndMovesPermanentlyFailedPublishToDeadLetterState() {
        OffsetDateTime createdAt = OffsetDateTime.now();
        NotificationOutboxEntity outbox = new NotificationOutboxEntity(
                UUID.randomUUID(),
                IncidentLifecycleEventType.ESCALATED,
                UUID.randomUUID(),
                "{}",
                createdAt);

        outbox.recordFailure("broker unavailable", createdAt.plusSeconds(1), createdAt, 2);
        assertThat(outbox.getStatus()).isEqualTo(NotificationOutboxStatus.PENDING);
        assertThat(outbox.getAttempts()).isEqualTo(1);
        assertThat(outbox.getAvailableAt()).isEqualTo(createdAt.plusSeconds(1));

        outbox.recordFailure("broker unavailable", createdAt.plusSeconds(3), createdAt.plusSeconds(2), 2);
        assertThat(outbox.getStatus()).isEqualTo(NotificationOutboxStatus.DEAD_LETTERED);
    }
}
