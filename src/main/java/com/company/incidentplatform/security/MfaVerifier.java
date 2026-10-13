package com.company.incidentplatform.security;

import java.util.List;
import java.util.Locale;

/**
 * Section 7.1 -- MFA enforcement.
 *
 * <p>Keycloak's evidence that a second factor was presented arrives in the token
 * as the {@code amr} (Authentication Methods References) array and the
 * {@code acr} (Authentication Context Class Reference) value. The API cannot
 * ask the IdP whether MFA happened; the token assertion is the only available
 * evidence, and trusting anything looser would let a user satisfy an MFA
 * requirement with a bare username/password login.
 *
 * <p>The two properties are ORed deliberately. {@code amr} is precise but its
 * contents depend on the authenticator that was used; {@code acr} is a
 * coarse, ordered statement about the level achieved. Requiring both would
 * break with any custom authenticator that populates only one, and requiring
 * only {@code acr} would accept a realm whose {@code acr} configuration is
 * loose. Together they mean: either the realm asserted a strong enough
 * authentication context, or a recognised multi-factor method is present.
 */
public final class MfaVerifier {

    /** {@code amr} values that evidence a genuine second factor. */
    private static final List<String> MULTI_FACTOR_METHODS =
            List.of("mfa", "otp", "totp", "hotp", "sms", "webauthn", "hwk", "piv", "skid", "u2f", "fido2");

    private final String requiredAcr;

    public MfaVerifier(String requiredAcr) {
        this.requiredAcr = requiredAcr;
    }

    /**
     * @param amr the token's {@code amr} claim, possibly null
     * @param acr the token's {@code acr} claim, possibly null
     */
    public boolean isMfaSatisfied(List<String> amr, String acr) {
        if (isMultiFactorMethodPresent(amr)) {
            return true;
        }
        return requiredAcr != null
                && !requiredAcr.isBlank()
                && acr != null
                && acr.equalsIgnoreCase(requiredAcr);
    }

    private static boolean isMultiFactorMethodPresent(List<String> amr) {
        if (amr == null) {
            return false;
        }
        return amr.stream()
                .filter(java.util.Objects::nonNull)
                .map(s -> s.toLowerCase(Locale.ROOT))
                .anyMatch(MULTI_FACTOR_METHODS::contains);
    }

    /**
     * Full decision: does <em>this</em> user, holding <em>this</em> verified
     * token, satisfy the MFA policy?
     *
     * <p>A role with no MFA requirement passes regardless of token contents. A
     * role with a requirement fails when the token does not evidence a second
     * factor. Reporters are configurable per 7.1 ("strongly recommended
     * (configurable to required)").
     */
    public AuthorizationCheck requireMfa(PlatformUser user, List<String> amr, String acr, boolean reporterMfaRequired) {
        boolean required = user.role().requiresMfa()
                || (user.role().mfaRecommended() && reporterMfaRequired);

        if (!required) {
            return AuthorizationCheck.pass("mfa.not_required");
        }
        if (isMfaSatisfied(amr, acr)) {
            return AuthorizationCheck.pass("mfa.satisfied");
        }
        return AuthorizationCheck.fail("mfa.required_not_present");
    }

    /** Result of a single non-resource authorization check, carrying a 7.11 reason on failure. */
    public record AuthorizationCheck(boolean passed, String rule, DeniedReason deniedReason) {

        static AuthorizationCheck pass(String rule) {
            return new AuthorizationCheck(true, rule, null);
        }

        static AuthorizationCheck fail(String rule) {
            return new AuthorizationCheck(false, rule, DeniedReason.MFA_REQUIRED);
        }
    }
}
