package com.company.incidentplatform.notification;

import com.company.incidentplatform.incident.IncidentRepository;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@ConditionalOnProperty(
        prefix = "incident-platform.notifications.kafka",
        name = "enabled",
        havingValue = "true")
public class IncidentSlaBreachScheduler {

    private final IncidentRepository incidents;
    private final NotificationOutboxService outbox;

    public IncidentSlaBreachScheduler(IncidentRepository incidents, NotificationOutboxService outbox) {
        this.incidents = incidents;
        this.outbox = outbox;
    }

    @Scheduled(fixedDelayString = "${incident-platform.notifications.sla.poll-interval-ms:30000}")
    @Transactional
    public void emitBreaches() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        incidents.findResponseSlaBreaches(now)
                .forEach(incident -> outbox.enqueueSlaBreach(incident, SlaType.RESPONSE));
        incidents.findResolutionSlaBreaches(now)
                .forEach(incident -> outbox.enqueueSlaBreach(incident, SlaType.RESOLUTION));
    }
}
