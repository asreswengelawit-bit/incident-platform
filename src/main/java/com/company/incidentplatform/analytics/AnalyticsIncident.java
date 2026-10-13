package com.company.incidentplatform.analytics;

import com.company.incidentplatform.incident.IncidentSeverity;
import com.company.incidentplatform.incident.IncidentStatus;
import java.time.OffsetDateTime;
import java.util.UUID;

/** Export-safe incident projection. It intentionally has no reporter identity fields. */
public record AnalyticsIncident(
        UUID id,
        String title,
        String description,
        String category,
        IncidentSeverity severity,
        IncidentStatus status,
        OffsetDateTime reportedAt,
        OffsetDateTime occurredAt,
        OffsetDateTime resolvedAt,
        String affectedSystem,
        String department,
        boolean escalated,
        boolean anonymous) {
}
