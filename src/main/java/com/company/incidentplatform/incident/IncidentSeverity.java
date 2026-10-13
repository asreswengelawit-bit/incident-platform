package com.company.incidentplatform.incident;

/**
 * Section 12 -- severity vocabulary matching incident_severity PostgreSQL enum.
 */
public enum IncidentSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    public boolean isMediumOrHigher() {
        return this == MEDIUM || this == HIGH || this == CRITICAL;
    }

    /**
     * FR-2.7: Escalation raises severity.
     */
    public IncidentSeverity nextHigher() {
        return switch (this) {
            case LOW -> MEDIUM;
            case MEDIUM -> HIGH;
            case HIGH, CRITICAL -> CRITICAL;
        };
    }
}
