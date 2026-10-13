package com.company.incidentplatform.notification;

import com.company.incidentplatform.incident.IncidentSeverity;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

final class NotificationRuleMatcher {

    private NotificationRuleMatcher() {
    }

    static List<NotificationRuleEntity> matching(
            List<NotificationRuleEntity> rules, IncidentLifecycleEvent event) {
        Set<IncidentSeverity> crossed = crossedSeverityThresholds(event);
        return rules.stream()
                .filter(rule -> rule.isEnabled() && rule.getDeletedAt() == null)
                .filter(rule -> rule.getEventType() == event.eventType())
                .filter(rule -> rule.getCategoryId() == null
                        || rule.getCategoryId().equals(event.categoryId()))
                .filter(rule -> rule.getMinSeverity() == null
                        || (event.eventType() == IncidentLifecycleEventType.SEVERITY_CHANGED
                                ? crossed.contains(rule.getMinSeverity())
                                : atLeast(event.newSeverity(), rule.getMinSeverity())))
                .toList();
    }

    private static Set<IncidentSeverity> crossedSeverityThresholds(IncidentLifecycleEvent event) {
        EnumSet<IncidentSeverity> crossed = EnumSet.noneOf(IncidentSeverity.class);
        if (event.eventType() != IncidentLifecycleEventType.SEVERITY_CHANGED || event.newSeverity() == null) {
            return crossed;
        }
        for (IncidentSeverity threshold : IncidentSeverity.values()) {
            boolean crossedUp = (event.previousSeverity() == null
                            || event.previousSeverity().ordinal() < threshold.ordinal())
                    && event.newSeverity().ordinal() >= threshold.ordinal();
            if (crossedUp) {
                crossed.add(threshold);
            }
        }
        return crossed;
    }

    private static boolean atLeast(IncidentSeverity severity, IncidentSeverity threshold) {
        return severity != null && severity.ordinal() >= threshold.ordinal();
    }
}
