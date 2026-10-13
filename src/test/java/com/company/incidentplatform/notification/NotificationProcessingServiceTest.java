package com.company.incidentplatform.notification;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.company.incidentplatform.authorization.IncidentResponsibilityResolver;
import com.company.incidentplatform.incident.IncidentSeverity;
import com.company.incidentplatform.incident.IncidentStatus;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class NotificationProcessingServiceTest {

    private final NotificationOutboxRepository outbox = mock(NotificationOutboxRepository.class);
    private final NotificationRuleRepository rules = mock(NotificationRuleRepository.class);
    private final IncidentResponsibilityResolver resolver = mock(IncidentResponsibilityResolver.class);
    private final NotificationDeliveryService delivery = mock(NotificationDeliveryService.class);

    @Test
    void hardcodedBaseRecipientsAreDispatchedIndependentlyOfRules() {
        UUID reporter = UUID.randomUUID();
        UUID assignee = UUID.randomUUID();
        IncidentLifecycleEvent event = event(reporter, assignee);
        when(rules.findByEnabledTrueAndDeletedAtIsNull()).thenReturn(List.of());
        when(delivery.prepareEmailIfMissing(event, reporter)).thenReturn(true);
        when(delivery.prepareEmailIfMissing(event, assignee)).thenReturn(true);

        service().process(event);

        verify(delivery).createInAppIfMissing(event, reporter);
        verify(delivery).createInAppIfMissing(event, assignee);
        verify(delivery).sendPendingEmail(event, reporter);
        verify(delivery).sendPendingEmail(event, assignee);
    }

    @Test
    void doesNotAttemptEmailWhenDeliveryIsAlreadySent() {
        UUID reporter = UUID.randomUUID();
        IncidentLifecycleEvent event = event(reporter, null);
        when(rules.findByEnabledTrueAndDeletedAtIsNull()).thenReturn(List.of());
        when(delivery.prepareEmailIfMissing(event, reporter)).thenReturn(false);

        service().process(event);

        verify(delivery).createInAppIfMissing(event, reporter);
        verify(delivery, never()).sendPendingEmail(event, reporter);
    }

    private NotificationProcessingService service() {
        return new NotificationProcessingService(outbox, rules, resolver, delivery);
    }

    private IncidentLifecycleEvent event(UUID reporterId, UUID assigneeId) {
        UUID eventId = UUID.randomUUID();
        return new IncidentLifecycleEvent(
                eventId,
                UUID.randomUUID(),
                IncidentLifecycleEventType.STATUS_CHANGED,
                IncidentStatus.TRIAGED,
                IncidentStatus.ASSIGNED,
                IncidentSeverity.HIGH,
                IncidentSeverity.HIGH,
                UUID.randomUUID(),
                "finance",
                reporterId,
                assigneeId,
                null,
                null,
                "event:" + eventId,
                OffsetDateTime.now());
    }
}
