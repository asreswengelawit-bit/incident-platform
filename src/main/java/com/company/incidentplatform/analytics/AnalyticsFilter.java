package com.company.incidentplatform.analytics;

import com.company.incidentplatform.incident.IncidentSeverity;
import com.company.incidentplatform.incident.IncidentStatus;
import java.time.Instant;
import java.util.UUID;

/** Narrow, validated filters shared by dashboard and export endpoints. */
public record AnalyticsFilter(
        IncidentStatus status,
        IncidentSeverity severity,
        UUID categoryId,
        String department,
        Instant from,
        Instant to) {

    public AnalyticsFilter {
        if (from != null && to != null && from.isAfter(to)) {
            throw new IllegalArgumentException("'from' must not be after 'to'");
        }
        if (department != null) {
            department = department.trim();
            if (department.isEmpty()) {
                department = null;
            } else if (department.length() > 100) {
                throw new IllegalArgumentException("department must be at most 100 characters");
            }
        }
    }
}
