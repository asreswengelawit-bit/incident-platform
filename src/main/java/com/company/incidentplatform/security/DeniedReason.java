package com.company.incidentplatform.security;

/**
 * Section 7.11 denial classifications.
 *
 * <p>7.11 requires every denied-authorization event to carry a reason/category,
 * and explains why: it is what makes IDOR/BOLA probing -- repeated denied
 * attempts against sequential IDs -- detectable, and what feeds the anomaly
 * alerting in 7.12. A 403 with no classification is indistinguishable from
 * ordinary client error and simply vanishes.
 *
 * <p>The {@code CROSS_USER_OBJECT_ACCESS} and {@code INSUFFICIENT_ROLE} values
 * correspond directly to the two failure modes named in the Section 10
 * authorization test matrix: BOLA/IDOR and BFLA respectively.
 */
public enum DeniedReason {

    /** 7.2 object level: caller is not the reporter/assignee/collaborator and holds no covering role. */
    CROSS_USER_OBJECT_ACCESS,

    /** 7.2 function level: the role may not call this endpoint at all. */
    INSUFFICIENT_ROLE,

    /**
     * 7.2 property level: the caller may see the record but was refused a field
     * or a whole view (e.g. analyst-only investigation notes, or the identity
     * behind an anonymous report under FR-1.6).
     */
    PROPERTY_SUPPRESSION,

    /** 7.1: account deactivated -- by deprovisioning, dormancy, or manual disable. */
    ACCOUNT_DISABLED,

    /** 7.1/7.9: the account is not yet provisioned in the application, so no role can be established. */
    USER_UNKNOWN,

    /**
     * 7.9: the token asserts a coarse role that no longer matches current state
     * -- the user was demoted or promoted in Keycloak after this token was
     * issued. Denying is what makes a role change take effect immediately rather
     * than waiting for the access token to expire.
     */
    ROLE_CHANGED_SINCE_TOKEN_ISSUED,

    /** 7.1: privileged role without a second factor. */
    MFA_REQUIRED,

    /** 7.9: absolute or idle session timeout reached. */
    SESSION_TIMEOUT,

    /** Token failed signature, issuer, audience, or expiry validation. */
    TOKEN_INVALID,

    /** 8.2: the specific (current status, next status) pair is not permitted for this role. */
    TRANSITION_NOT_PERMITTED,

    /**
     * 7.6: an evidence upload was refused by the type allow-list, a size or count
     * limit, or the malware scan.
     *
     * <p>Its own category rather than a reuse of {@link #INSUFFICIENT_ROLE}, because
     * that one is 7.12's BFLA signal and a caller who legitimately may upload but
     * sent a {@code .exe} is not a broken-function-level caller. Folding the two
     * together would make a burst of rejected uploads look like an authorization
     * anomaly and dilute the signal that value exists to carry. The reason code is
     * free text in the schema precisely so this distinction is expressible.
     */
    EVIDENCE_CONTENT_REJECTED,

    /** 9.1: pageSize above the hard maximum, or a sort field outside the allow-list. */
    PAGINATION_LIMIT_EXCEEDED,

    /** 7.5: request rejected by rate limiting (7.7). */
    RATE_LIMIT_EXCEEDED
}
