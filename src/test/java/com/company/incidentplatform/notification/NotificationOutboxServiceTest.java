package com.company.incidentplatform.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.company.incidentplatform.incident.IncidentEntity;
import com.company.incidentplatform.incident.IncidentCategoryEntity;
import com.company.incidentplatform.incident.IncidentSeverity;
import com.company.incidentplatform.incident.IncidentStatus;
import com.company.incidentplatform.identity.AppUserEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class NotificationOutboxServiceTest {

    private final NotificationOutboxRepository repository = mock(NotificationOutboxRepository.class);
    private final NotificationOutboxService service =
            new NotificationOutboxService(repository, new ObjectMapper().findAndRegisterModules());

    @Test
    void enqueuesMinimalEventWithoutReporterOrIncidentText() throws Exception {
        UUID incidentId = UUID.randomUUID();
        UUID assignedUserId = UUID.randomUUID();
        IncidentEntity incident = mock(IncidentEntity.class);
        AppUserEntity assignee = mock(AppUserEntity.class);
        IncidentCategoryEntity category = mock(IncidentCategoryEntity.class);
        when(incident.getId()).thenReturn(incidentId);
        when(incident.getSeverity()).thenReturn(IncidentSeverity.HIGH);
        when(incident.getCategory()).thenReturn(category);
        when(category.getId()).thenReturn(UUID.randomUUID());
        when(assignee.getId()).thenReturn(assignedUserId);

        UUID eventId = service.enqueue(
                IncidentLifecycleEventType.STATUS_CHANGED,
                incident,
                IncidentStatus.TRIAGED,
                IncidentStatus.ASSIGNED,
                assignee);

        ArgumentCaptor<NotificationOutboxEntity> captor =
                ArgumentCaptor.forClass(NotificationOutboxEntity.class);
        verify(repository).save(captor.capture());
        NotificationOutboxEntity outbox = captor.getValue();
        IncidentLifecycleEvent event = new ObjectMapper().findAndRegisterModules()
                .readValue(outbox.getPayload(), IncidentLifecycleEvent.class);
        assertThat(event.eventId()).isEqualTo(eventId);
        assertThat(event.incidentId()).isEqualTo(incidentId);
        assertThat(event.recipientUserId()).isEqualTo(assignedUserId);
        assertThat(event.severity()).isEqualTo(IncidentSeverity.HIGH);
        assertThat(outbox.getPayload()).doesNotContain("identity", "full_name", "title", "description", "email");
    }
}
