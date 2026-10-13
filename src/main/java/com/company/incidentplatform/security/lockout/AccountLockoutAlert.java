package com.company.incidentplatform.security.lockout;

import com.company.incidentplatform.security.PlatformRole;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/**
 * Section 7.1 -- a reconstructed account lockout, as raised to the Notification
 * Service (5.4) and written to the audit log (7.11).
 *
 * <p>Carries the reconstructed wait rather than only a boolean, because the value
 * distinguishes an account under active attack (a rising wait) from one that
 * simply tripped once, and an on-call reading three of these in a row is looking
 * at a credential-stuffing pattern rather than three unrelated typos.
 *
 * <p>{@code pagedAdmin} is carried on the payload rather than being used to decide
 * whether to send. Audit and paging are different destinations with different
 * retention and different audiences: a Reporter lockout is recorded and
 * deliberately not paged, and a consumer that filtered on {@code pagedAdmin}
 * before writing its audit entry would lose exactly the record 7.1 requires.
 *
 * @param detectedAt      when the monitor observed the threshold crossing, which
 *                        is at most one poll interval after the actual lock
 * @param consecutiveFailures failure count at that point
 * @param waitSeconds     Keycloak's incremental wait for that count
 * @param roles           recognised coarse roles held by the account
 * @param pageAdmin       whether 7.1 requires an Admin page for this account
 * @param firstLockout    whether this is the first crossing of the current
 *                        episode, so repeated failures do not re-page
 */
public record AccountLockoutAlert(
        UUID userId,
        String username,
        Instant detectedAt,
        int consecutiveFailures,
        long waitSeconds,
        Set<PlatformRole> roles,
        boolean pageAdmin,
        boolean firstLockout) {

    /** 7.1/7.12: a stable action name for the audit trail and the Kafka message key. */
    public static final String AUDIT_ACTION = "account_lockout";

    public String summary() {
        return "Account " + username + " locked after " + consecutiveFailures
                + " consecutive failed logins (wait " + waitSeconds + "s"
                + (pageAdmin ? ", paging Admin per 7.1" : ", audit-only per 7.1")
                + ")";
    }
}
