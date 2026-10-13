package com.company.incidentplatform.notification;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

@Component("notificationRules")
public class NotificationRuleHealthIndicator implements HealthIndicator {

    private final CriticalNotificationRuleCoverage coverage;

    public NotificationRuleHealthIndicator(CriticalNotificationRuleCoverage coverage) {
        this.coverage = coverage;
    }

    @Override
    public Health health() {
        if (coverage.isCovered()) {
            return Health.up().withDetail("criticalEventRule", "covered").build();
        }
        return Health.down()
                .withDetail("criticalEventRule", CriticalNotificationRuleCoverage.WARNING)
                .build();
    }
}
