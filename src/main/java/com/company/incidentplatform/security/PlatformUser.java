package com.company.incidentplatform.security;

import java.util.UUID;

/**
 * The authorization principal for the current request -- the end of the
 * Section 6.2 chain:
 *
 * <pre>
 * Keycloak role claim
 *   -&gt; Spring Security authentication
 *     -&gt; Platform role + department (from the synced USER/ROLE projection)
 *       -&gt; object/property-level authorization (Section 7.2)
 *         -&gt; resource decision
 * </pre>
 *
 * <p>Every field is resolved from <em>current</em> state at request time, not
 * from the token's claims. Section 7.1 is explicit: authorization is always
 * evaluated against a user's current role and department, never their historical
 * ones, so a demotion or a department move takes effect on the next request
 * rather than at token expiry. Section 7.9 requires the same thing from the
 * token-lifecycle side.
 *
 * <p>Immutable.
 */
public record PlatformUser(
        UUID id,
        String keycloakSubject,
        String email,
        String fullName,
        String department,
        PlatformRole role,
        RolePermissions permissions,
        boolean active,
        boolean mfaVerified) {

    public PlatformUser {
        if (id == null) {
            throw new IllegalArgumentException("PlatformUser requires an id");
        }
        if (keycloakSubject == null || keycloakSubject.isBlank()) {
            throw new IllegalArgumentException("PlatformUser requires a Keycloak subject");
        }
        if (role == null) {
            throw new IllegalArgumentException("PlatformUser requires a role");
        }
        if (permissions == null) {
            throw new IllegalArgumentException("PlatformUser requires permissions");
        }
    }

    /** True when the token proves a second factor was presented (Section 7.1). */
    public boolean hasMfa() {
        return mfaVerified;
    }

    public boolean is(PlatformRole expected) {
        return role == expected;
    }

    /**
     * Returns a copy carrying the token's MFA evidence. Used once per request
     * after 7.1 verification, so that downstream code can see the authentication
     * strength without re-reading the token.
     */
    public PlatformUser withMfaVerified(boolean verified) {
        if (verified == this.mfaVerified) {
            return this;
        }
        return new PlatformUser(
                id, keycloakSubject, email, fullName, department, role, permissions, active, verified);
    }
}
