package com.company.incidentplatform.authorization;

/**
 * How 7.2.1's "explicitly shared/grouped" clause is satisfied.
 *
 * <p>7.2.1 states that cross-department visibility "requires either the incident
 * being explicitly shared/grouped, or a Lead/Admin action". The word "grouped" is
 * ambiguous in the document: it can mean that placing incidents into an
 * Incident Group (FR-2.6) makes the whole campaign mutually visible, or only
 * that grouping is one of the ways an incident comes to be shared.
 *
 * <p>Rather than resolve that ambiguity silently in either direction, it is a
 * policy value. {@link #EXPLICIT_COLLABORATION_ONLY} is the default because
 * granting visibility transitively through campaign membership is the reading
 * that can over-expose: linking a phishing wave across three departments would
 * hand every participant visibility of every other incident in the campaign,
 * which is a materially larger grant than 7.2.1's department table implies.
 *
 * <p>FLAGGED FOR REVIEW -- see the Phase 2 summary. If the intended behaviour
 * is that campaign membership confers visibility, set
 * {@code incident.authorization.group-visibility-policy=GROUP_MEMBERSHIP}; no
 * code change is needed.
 */
public enum GroupVisibilityPolicy {

    /**
     * Default. Cross-department reach comes only from an explicit
     * {@code incident_collaborator} row, or from a Lead/Admin action. Incident
     * Groups are a linking and analytics construct (FR-2.6) and confer no
     * visibility of their own.
     */
    EXPLICIT_COLLABORATION_ONLY,

    /**
     * Alternative reading. A caller who can see any incident in a group can see
     * every incident in that group, implementing "explicitly grouped" as
     * transitive visibility. Materially broader -- see the enum javadoc.
     */
    GROUP_MEMBERSHIP
}
