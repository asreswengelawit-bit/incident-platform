package com.company.incidentplatform.analytics;

import java.util.Map;

/** Counts are computed only from incidents visible to the requesting user. */
public record AnalyticsSummary(
        long totalIncidents,
        long escalatedIncidents,
        Map<String, Long> byStatus,
        Map<String, Long> bySeverity) {
}
