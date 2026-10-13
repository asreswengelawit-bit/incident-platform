package com.company.incidentplatform.security;

/**
 * Section 7.2 -- which of the three authorization layers was actually evaluated.
 *
 * <p>7.11 requires the audit entry to record "the specific authorization check
 * that permitted it". That makes this value a compliance artefact, not
 * debug information: it is how a reviewer can prove that a given write was
 * gated at the object level rather than merely having a role check pass over it.
 *
 * <p>Mirrors the {@code authorization_check_type} enum in
 * {@code V1__baseline_schema_and_vocabularies.sql}.
 */
public enum AuthorizationCheckType {

    /** No authorization decision was involved (e.g. a health probe). */
    NONE,

    /** 7.2: role/scope check at the controller/method level. Prevents BFLA. */
    FUNCTION_LEVEL,

    /**
     * 7.2: re-validation that the caller is the reporter/assignee/collaborator or
     * holds a covering role. Prevents BOLA/IDOR.
     */
    OBJECT_LEVEL,

    /**
     * 7.2: the response is a role-appropriate <em>view</em> rather than the full
     * entity with fields hidden client-side.
     */
    PROPERTY_LEVEL;

    public String dbValue() {
        return name();
    }
}
