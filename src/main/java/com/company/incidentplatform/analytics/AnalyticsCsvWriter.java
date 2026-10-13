package com.company.incidentplatform.analytics;

import java.nio.charset.StandardCharsets;
import java.util.List;

/** RFC-4180-style CSV writer for the export's deliberately restricted field set. */
final class AnalyticsCsvWriter {

    private static final String HEADER =
            "id,title,description,category,severity,status,reported_at,occurred_at,resolved_at,affected_system,department,escalated\r\n";

    private AnalyticsCsvWriter() {
    }

    static byte[] write(List<AnalyticsIncident> incidents) {
        StringBuilder csv = new StringBuilder(HEADER);
        for (AnalyticsIncident incident : incidents) {
            csv.append(row(
                    incident.id(),
                    incident.title(),
                    incident.description(),
                    incident.category(),
                    incident.severity(),
                    incident.status(),
                    incident.reportedAt(),
                    incident.occurredAt(),
                    incident.resolvedAt(),
                    incident.affectedSystem(),
                    incident.anonymous() ? "" : incident.department(),
                    incident.escalated()));
        }
        return csv.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String row(Object... fields) {
        StringBuilder row = new StringBuilder();
        for (int i = 0; i < fields.length; i++) {
            if (i > 0) {
                row.append(',');
            }
            row.append(escape(fields[i] == null ? "" : fields[i].toString()));
        }
        return row.append("\r\n").toString();
    }

    private static String escape(String value) {
        // Prevent exported text from being interpreted as a spreadsheet formula.
        String safe = value.matches("^[\\s]*[=+\\-@].*") ? "'" + value : value;
        return "\"" + safe.replace("\"", "\"\"").replace("\r", " ").replace("\n", " ") + "\"";
    }
}
