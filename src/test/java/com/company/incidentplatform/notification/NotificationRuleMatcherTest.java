package com.company.incidentplatform.notification;

import static org.assertj.core.api.Assertions.assertThat;

import com.company.incidentplatform.incident.IncidentSeverity;
import com.company.incidentplatform.incident.IncidentStatus;
import com.company.incidentplatform.security.PlatformRole;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class NotificationRuleMatcherTest {

    @Test
    void severityChangedMatchesOnlyThresholdsCrossedOnThisTransition() {
        UUID categoryId = UUID.randomUUID();
        IncidentLifecycleEvent event = new IncidentLifecycleEvent(
                UUID.randomUUID(),
                UUID.randomUUID(),
                IncidentLifecycleEventType.SEVERITY_CHANGED,
                IncidentStatus.TRIAGED,
                IncidentStatus.TRIAGED,
                IncidentSeverity.HIGH,
                IncidentSeverity.CRITICAL,
                categoryId,
                "finance",
                UUID.randomUUID(),
                UUID.randomUUID(),
                null,
                null,
                "severity-change",
                OffsetDateTime.now());
        NotificationRuleEntity critical = rule(IncidentSeverity.CRITICAL, categoryId);
        NotificationRuleEntity high = rule(IncidentSeverity.HIGH, categoryId);

        assertThat(NotificationRuleMatcher.matching(List.of(critical, high), event))
                .containsExactly(critical);
    }

    @Test
    void severityChangedFromUnclassifiedToCriticalCrossesCriticalThreshold() {
        UUID categoryId = UUID.randomUUID();
        IncidentLifecycleEvent event = new IncidentLifecycleEvent(
                UUID.randomUUID(),
                UUID.randomUUID(),
                IncidentLifecycleEventType.SEVERITY_CHANGED,
                IncidentStatus.TRIAGED,
                IncidentStatus.TRIAGED,
                null,
                IncidentSeverity.CRITICAL,
                categoryId,
                "finance",
                UUID.randomUUID(),
                UUID.randomUUID(),
                null,
                null,
                "unclassified-to-critical",
                OffsetDateTime.now());
        NotificationRuleEntity critical = rule(IncidentSeverity.CRITICAL, categoryId);

        assertThat(NotificationRuleMatcher.matching(List.of(critical), event))
                .containsExactly(critical);
    }

    @Test
    void disabledAndDeletedRulesNeverMatch() {
        UUID categoryId = UUID.randomUUID();
        IncidentLifecycleEvent event = new IncidentLifecycleEvent(
                UUID.randomUUID(),
                UUID.randomUUID(),
                IncidentLifecycleEventType.INCIDENT_CREATED,
                IncidentStatus.NEW,
                IncidentStatus.NEW,
                IncidentSeverity.CRITICAL,
                IncidentSeverity.CRITICAL,
                categoryId,
                "finance",
                UUID.randomUUID(),
                null,
                null,
                null,
                "incident-created",
                OffsetDateTime.now());
        NotificationRuleEntity disabled = rule(IncidentSeverity.CRITICAL, categoryId);
        disabled.update(
                IncidentLifecycleEventType.SEVERITY_CHANGED,
                IncidentSeverity.CRITICAL,
                categoryId,
                NotificationChannel.EMAIL,
                PlatformRole.SECURITY_ADMIN,
                false,
                UUID.randomUUID(),
                OffsetDateTime.now());
        NotificationRuleEntity deleted = rule(IncidentSeverity.CRITICAL, categoryId);
        deleted.softDelete(UUID.randomUUID(), OffsetDateTime.now());

        assertThat(NotificationRuleMatcher.matching(List.of(disabled, deleted), event)).isEmpty();
    }

    private NotificationRuleEntity rule(IncidentSeverity threshold, UUID categoryId) {
        return new NotificationRuleEntity(
                UUID.randomUUID(),
                IncidentLifecycleEventType.SEVERITY_CHANGED,
                threshold,
                categoryId,
                NotificationChannel.EMAIL,
                PlatformRole.SECURITY_ADMIN,
                true,
                UUID.randomUUID(),
                OffsetDateTime.now());
    }
}
