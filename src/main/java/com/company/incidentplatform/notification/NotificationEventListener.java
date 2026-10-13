package com.company.incidentplatform.notification;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.annotation.DltHandler;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.annotation.RetryableTopic;
import org.springframework.retry.annotation.Backoff;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(
        prefix = "incident-platform.notifications.kafka",
        name = "enabled",
        havingValue = "true")
public class NotificationEventListener {

    private final NotificationProcessingService processingService;

    public NotificationEventListener(NotificationProcessingService processingService) {
        this.processingService = processingService;
    }

    @RetryableTopic(
            attempts = "${incident-platform.notifications.kafka.attempts:4}",
            backoff = @Backoff(delayExpression = "${incident-platform.notifications.kafka.retry-delay-ms:1000}"),
            dltTopicSuffix = ".DLT")
    @KafkaListener(
            topics = "${incident-platform.notifications.kafka.topic:incident.lifecycle.events}",
            containerFactory = "notificationKafkaListenerContainerFactory")
    public void onEvent(IncidentLifecycleEvent event) {
        processingService.process(event);
    }

    @DltHandler
    public void onDeadLetter(IncidentLifecycleEvent event) {
        processingService.markDeadLettered(event.eventId(), "Kafka notification consumer exhausted retries");
    }
}
