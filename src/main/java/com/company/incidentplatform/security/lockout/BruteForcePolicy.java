package com.company.incidentplatform.security.lockout;

/**
 * Section 7.1 -- the realm's brute-force parameters, as read back from Keycloak.
 *
 * <p>Read from the live realm rather than restated from {@code application.yml}.
 * The failure mode this avoids is the important one: a locally configured copy of
 * these numbers can drift from the realm they claim to describe, and the drift is
 * invisible because both files are internally consistent. If Keycloak locks an
 * account on the fifth failure and this code believes the factor is three, the
 * monitor either pages early and trains the on-call to ignore it, or misses
 * lockouts entirely -- and "misses lockouts" is a security monitoring control
 * silently not working, which is precisely what 7.12's requirements are for.
 *
 * @param failureFactor       consecutive failures tolerated before any wait applies
 * @param waitIncrementSeconds seconds added to the wait per failure past the factor;
 *                            zero is the flat-window configuration 7.1 rejects
 * @param maxFailureWaitSeconds ceiling the incremental wait is capped at
 * @param maxDeltaTimeSeconds window after which a failure counter decays to zero
 * @param bruteForceProtected  whether protection is switched on at all
 */
public record BruteForcePolicy(
        int failureFactor,
        long waitIncrementSeconds,
        long maxFailureWaitSeconds,
        long maxDeltaTimeSeconds,
        boolean bruteForceProtected) {

    /**
     * Mirrors Keycloak's own wait calculation, so that "the account is locked" in
     * the monitor means the same thing as "the account is locked" in Keycloak.
     *
     * <p>Keycloak waits {@code (failures - failureFactor + 1) * waitIncrement},
     * capped at {@code maxFailureWaitSeconds}. Below the factor there is no wait
     * at all. A non-positive factor is normalised to 1 because a zero or negative
     * value would make the arithmetic below lock an account on zero failures.
     */
    public long waitSecondsFor(int consecutiveFailures) {
        if (consecutiveFailures <= 0) {
            return 0L;
        }
        int factor = Math.max(1, failureFactor);
        if (consecutiveFailures < factor) {
            return 0L;
        }
        if (waitIncrementSeconds <= 0L) {
            // The flat-window configuration 7.1 explicitly rejects. Reported
            // faithfully rather than corrected, because the monitor's job is to
            // describe what Keycloak actually did; a realm-config regression test
            // is what enforces 7.1's incremental requirement.
            return maxFailureWaitSeconds;
        }
        long raw = (long) (consecutiveFailures - factor + 1) * waitIncrementSeconds;
        return Math.min(raw, maxFailureWaitSeconds);
    }

    /** Whether the given failure count has reached the point of lockout. */
    public boolean isLocked(int consecutiveFailures) {
        return bruteForceProtected && waitSecondsFor(consecutiveFailures) > 0L;
    }
}
