package com.company.incidentplatform.security;

/**
 * Carries a {@link DeniedReason} alongside an authentication failure.
 *
 * <p>{@code BadCredentialsException} carries only a message, and a 7.11 audit
 * entry needs a classification. Wrapping the reason rather than string-matching
 * on the message keeps the audit category a structured value: a message is a
 * human-readable string that gets reworded, and a rewrite would silently degrade
 * every MFA failure into a generic token failure.
 */
public class AuthorizationContextRefused extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final transient DeniedReason reason;
    private final transient String rule;

    public AuthorizationContextRefused(DeniedReason reason, String rule) {
        super(reason + ": " + rule);
        this.reason = reason;
        this.rule = rule;
    }

    public DeniedReason reason() {
        return reason;
    }

    public String rule() {
        return rule;
    }
}
