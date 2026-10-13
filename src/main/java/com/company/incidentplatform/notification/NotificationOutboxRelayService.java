package com.company.incidentplatform.notification;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@ConditionalOnProperty(
        prefix = "incident-platform.notifications.kafka",
        name = "enabled",
        havingValue = "true")
public class NotificationOutboxRelayService {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationOutboxRelayService.class);

    private final NotificationOutboxRepository repository;
    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final ObjectMapper objectMapper;
    private final String topic;
    private final int maxAttempts;

    public NotificationOutboxRelayService(
            NotificationOutboxRepository repository,
            KafkaTemplate<String, Object> kafkaTemplate,
            ObjectMapper objectMapper,
            @Value("${incident-platform.notifications.kafka.topic:incident.lifecycle.events}") String topic,
            @Value("${incident-platform.notifications.kafka.max-publish-attempts:8}") int maxAttempts) {
        this.repository = repository;
        this.kafkaTemplate = kafkaTemplate;
        this.objectMapper = objectMapper;
        this.topic = topic;
        this.maxAttempts = Math.max(1, maxAttempts);
    }

    @Transactional
    public boolean publishNext() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        var row = repository.lockNextReady(now);
        if (row.isEmpty()) {
            return false;
        }

        NotificationOutboxEntity outbox = row.get();
        try {
            IncidentLifecycleEvent event = objectMapper.readValue(
                    outbox.getPayload(), IncidentLifecycleEvent.class);
            kafkaTemplate.send(topic, event.eventId().toString(), event).get(5, TimeUnit.SECONDS);
            outbox.markPublished(OffsetDateTime.now(ZoneOffset.UTC));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            recordFailure(outbox, e);
        } catch (ExecutionException | RuntimeException | TimeoutException e) {
            recordFailure(outbox, e);
        } catch (Exception e) {
            recordFailure(outbox, e);
        }
        return true;
    }

    private void recordFailure(NotificationOutboxEntity outbox, Exception error) {
        long delaySeconds = Math.min(300, 1L << Math.min(outbox.getAttempts(), 8));
        OffsetDateTime failedAt = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime retryAt = failedAt.plusSeconds(delaySeconds);
        outbox.recordFailure(error.getMessage(), retryAt, failedAt, maxAttempts);
        LOGGER.warn(
                "Could not publish notification outbox event {}; attempt {}",
                outbox.getId(),
                outbox.getAttempts());
    }
}
