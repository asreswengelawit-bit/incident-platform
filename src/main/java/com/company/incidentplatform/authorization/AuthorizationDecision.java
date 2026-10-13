package com.company.incidentplatform.authorization;

import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.DeniedReason;

/**
 * The outcome of an authorization check, carrying everything Section 7.11 needs
 * to write an audit entry: which layer was evaluated, whether it passed, and --
 * when it did not -- the classification that makes the denial detectable.
 *
 * <p>A denial is a first-class result, not an exception. Throwing on every
 * refusal would make "denied" an error path that callers forget to log, which is
 * precisely the failure mode 7.11 was written to prevent.
 */
public record AuthorizationDecision(
        boolean allowed,
        AuthorizationCheckType checkType,
        String rule,
        DeniedReason deniedReason) {

    public static AuthorizationDecision allow(AuthorizationCheckType checkType, String rule) {
        return new AuthorizationDecision(true, checkType, rule, null);
    }

    public static AuthorizationDecision deny(
            AuthorizationCheckType checkType, String rule, DeniedReason reason) {
        return new AuthorizationDecision(false, checkType, rule, reason);
    }

    public boolean denied() {
        return !allowed;
    }
}
