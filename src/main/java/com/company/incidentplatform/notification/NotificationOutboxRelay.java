package com.company.incidentplatform.notification;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@EnableScheduling
@ConditionalOnProperty(
        prefix = "incident-platform.notifications.kafka",
        name = "enabled",
        havingValue = "true")
public class NotificationOutboxRelay {

    private final NotificationOutboxRelayService relayService;

    public NotificationOutboxRelay(NotificationOutboxRelayService relayService) {
        this.relayService = relayService;
    }

    @Scheduled(fixedDelayString = "${incident-platform.notifications.kafka.poll-interval-ms:1000}")
    public void publishPendingEvents() {
        for (int i = 0; i < 50 && relayService.publishNext(); i++) {
            // Drain a bounded batch; the delay gives database and broker resources room to recover.
        }
    }
}
