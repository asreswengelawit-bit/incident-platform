package com.company.incidentplatform.incident;

/**
 * Section 8.1 / FR-3.1 -- incident status lifecycle values.
 *
 * <p>ESCALATED is intentionally NOT a status -- per FR-2.7 and Section 8.1,
 * escalation is a boolean/timestamped attribute, not a lifecycle state.
 */
public enum IncidentStatus {
    NEW,
    TRIAGED,
    ASSIGNED,
    INVESTIGATING,
    CONTAINED,
    RESOLVED,
    CLOSED,
    REOPENED,
    REJECTED;

    public boolean isActive() {
        return this != CLOSED && this != REJECTED;
    }

    public boolean isTerminal() {
        return this == CLOSED || this == REJECTED;
    }

    /**
     * Section 8.1: Escalation can occur while status is INVESTIGATING
     * (or less commonly ASSIGNED or CONTAINED).
     */
    public boolean canBeEscalated() {
        return this == INVESTIGATING || this == ASSIGNED || this == CONTAINED;
    }
}
