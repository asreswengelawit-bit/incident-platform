package com.company.incidentplatform.authorization;

import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.DeniedReason;
import com.company.incidentplatform.security.PlatformUser;

/**
 * Thrown when an authorization check refuses the request.
 *
 * <p>Extends Spring Security's {@code AccessDeniedException} deliberately. That
 * is what routes the refusal through the configured {@code AccessDeniedHandler},
 * which is the single place a 7.11 audit entry is written for denials. A plain
 * {@code RuntimeException} would propagate to the container and become a 500 with
 * no audit trail -- the precise failure 7.11 exists to prevent.
 *
 * <p>Carries the {@link AuthorizationDecision} rather than a bare message so the
 * handler can write a complete 7.11 entry -- including the reason code and the
 * specific rule that failed -- without re-deriving anything.
 *
 * <p>The message deliberately contains no detail about the resource. A 7.5
 * "secure error handling" rule: a rejection body must not tell an attacker
 * whether an incident ID exists, or which department owns it, because that
 * difference is exactly what an IDOR enumeration needs. The detail goes to the
 * audit log, where the legitimate operator can see it and the caller cannot.
 */
public class AuthorizationDeniedException extends org.springframework.security.access.AccessDeniedException {

    private static final long serialVersionUID = 1L;

    private final transient AuthorizationDecision decision;
    private final transient String resourceType;
    private final transient java.util.UUID resourceId;

    public AuthorizationDeniedException(
            AuthorizationDecision decision, String resourceType, java.util.UUID resourceId) {
        super("Access denied: " + decision.rule());
        this.decision = decision;
        this.resourceType = resourceType;
        this.resourceId = resourceId;
    }

    public AuthorizationDecision decision() {
        return decision;
    }

    public String resourceType() {
        return resourceType;
    }

    public java.util.UUID resourceId() {
        return resourceId;
    }

    /** Builds the function-level refusal for a capability the role does not hold. */
    public static AuthorizationDeniedException forMissingCapability(
            Capability capability, String resourceType, java.util.UUID resourceId) {
        return new AuthorizationDeniedException(
                AuthorizationDecision.deny(
                        AuthorizationCheckType.FUNCTION_LEVEL,
                        capability.rule(),
                        DeniedReason.INSUFFICIENT_ROLE),
                resourceType,
                resourceId);
    }

    /**
     * Builds the function-level refusal for a read-only role attempting a write.
     *
     * <p>Shared rather than inlined at each site because the rule string is what
     * 7.11 records and what an administrator reviewing the log will match
     * against. Two spellings of the same rule means a search for one of them
     * silently misses the other half of the denials.
     */
    public static AuthorizationDeniedException forReadOnlyRole(
            String resourceType, java.util.UUID resourceId) {
        return new AuthorizationDeniedException(
                AuthorizationDecision.deny(
                        AuthorizationCheckType.FUNCTION_LEVEL,
                        "capability.write_blocked_read_only",
                        DeniedReason.INSUFFICIENT_ROLE),
                resourceType,
                resourceId);
    }
}
