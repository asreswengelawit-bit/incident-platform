package com.company.incidentplatform.security;

/**
 * Section 7.2.1 -- department-scoped visibility, encoded as data rather than as
 * branching logic.
 *
 * <p>Confirmed Phase-1 decision: implemented exactly as 7.2.1 is written. An
 * Analyst is <em>not</em> granted organisation-wide visibility; cross-department
 * reach requires an explicit share, a group, or a Lead/Admin action.
 */
public enum VisibilityScope {

    /** Reporter: own submitted incidents only. */
    OWN_INCIDENTS,

    /**
     * Analyst: incidents assigned to them, plus <em>unassigned</em> incidents
     * within their own department. Assigned work is reachable regardless of
     * department, because 7.2.1 grants the Analyst their own assignments and
     * restricting those by department would strand an incident whose department
     * changed mid-investigation.
     */
    ASSIGNED_AND_OWN_DEPARTMENT_UNASSIGNED,

    /** Security Lead: all incidents within the department(s) they lead. */
    LED_DEPARTMENTS,

    /** Admin: organisation-wide, all departments. */
    ORGANIZATION,

    /** Service account: no read access at all; ingestion only. */
    NONE;

    public static VisibilityScope fromKey(String key) {
        if (key == null) {
            return NONE;
        }
        for (VisibilityScope scope : values()) {
            if (scope.name().equals(key)) {
                return scope;
            }
        }
        // Fail closed. An unrecognised scope must never widen access; NONE is
        // the only safe default, and the missing key is a configuration bug
        // worth surfacing rather than absorbing.
        return NONE;
    }
}
