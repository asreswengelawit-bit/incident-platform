package com.company.incidentplatform.security;

/**
 * Section 6.2.1 -- the coarse role vocabulary.
 *
 * <p>These names are deliberately identical to the Keycloak realm role names, so
 * the mapping from the token's role claim to a platform role is a provable 1:1
 * correspondence rather than a translation table that can drift. The enum
 * constants also match the {@code platform_coarse_role} PostgreSQL enum created
 * in {@code V1__baseline_schema_and_vocabularies.sql}; the shared name is the
 * contract, and {@link #fromKeycloakRole} fails closed on anything unrecognised
 * so a role added in the IdP without a corresponding Platform decision cannot
 * silently become an authorization grant.
 *
 * <p>Section 6.2.2: Spring Security reads the role from the validated token and
 * maps it here. It does not re-derive the coarse role from the application
 * database -- that would create a second source of truth competing with
 * Keycloak. See {@code CurrentUserStateService} for how 7.1/7.9 revocation is
 * satisfied without doing that.
 */
public enum PlatformRole {

    REPORTER,
    ANALYST,
    SECURITY_LEAD,
    SECURITY_ADMIN,
    AUDITOR,
    SERVICE_ACCOUNT;

    /**
     * Resolves a realm role name from the token. Fails closed: an unknown role
     * is an error, never a default-to-Reporter fallback, because a silent
     * downgrade would hide a misconfigured IdP and a silent upgrade would be a
     * privilege escalation.
     */
    public static PlatformRole fromKeycloakRole(String realmRole) {
        if (realmRole == null) {
            throw new IllegalArgumentException("No role claim present in token");
        }
        for (PlatformRole role : values()) {
            if (role.name().equals(realmRole)) {
                return role;
            }
        }
        throw new IllegalArgumentException(
                "Unrecognised Keycloak realm role '" + realmRole + "'. It must match a PlatformRole "
                        + "exactly (Section 6.2.1); granting access for an unmapped role would be an "
                        + "unreviewed authorization change.");
    }

    /** Section 7.1: MFA is required for every role that can read or change incident data. */
    public boolean requiresMfa() {
        return this == ANALYST
                || this == SECURITY_LEAD
                || this == SECURITY_ADMIN
                || this == AUDITOR;
    }

    /**
     * Section 7.1: Reporters are "strongly recommended (configurable to
     * required) for Reporters". The threshold is a deployment decision, so it
     * is expressed as a capability rather than hard-coded -- see
     * {@code mfa.reporter-required} in configuration.
     */
    public boolean mfaRecommended() {
        return this == REPORTER;
    }
}
