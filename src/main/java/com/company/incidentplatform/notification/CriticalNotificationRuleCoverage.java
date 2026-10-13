package com.company.incidentplatform.notification;

import com.company.incidentplatform.incident.IncidentSeverity;
import org.springframework.stereotype.Service;

@Service
public class CriticalNotificationRuleCoverage {

    public static final String WARNING = "No enabled notification rule covers Critical incident events";

    private final NotificationRuleRepository rules;

    public CriticalNotificationRuleCoverage(NotificationRuleRepository rules) {
        this.rules = rules;
    }

    public boolean isCovered() {
        return rules.findByEnabledTrueAndDeletedAtIsNull().stream().anyMatch(this::coversCritical);
    }

    public String warningIfUncovered() {
        return isCovered() ? null : WARNING;
    }

    private boolean coversCritical(NotificationRuleEntity rule) {
        return switch (rule.getEventType()) {
            case INCIDENT_CREATED -> rule.getMinSeverity() == null
                    || rule.getMinSeverity().ordinal() <= IncidentSeverity.CRITICAL.ordinal();
            case SEVERITY_CHANGED -> rule.getMinSeverity() == IncidentSeverity.CRITICAL;
            default -> false;
        };
    }
}
