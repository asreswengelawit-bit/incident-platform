package com.company.incidentplatform.security.lockout;

import static org.assertj.core.api.Assertions.assertThat;

import com.company.incidentplatform.security.PlatformRole;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Section 7.1 -- lockout detection and, specifically, who it pages.
 *
 * <p><strong>Why the paging rule is tested so heavily.</strong> The whole control
 * is a trade-off between two documented failure modes. Page every lockout and
 * routine forgotten-password lockouts train the on-call to ignore pages -- 7.1
 * names this when it carves Reporters out. Page nothing, or page on role alone,
 * and a credential-stuffing run against a Lead goes unattended -- 7.12's
 * monitoring requirement. Both halves are cheap to implement and easy to get
 * subtly wrong, and neither shows up in a smoke test, because the code "works"
 * in both directions until the day it matters.
 *
 * <p>The tests are therefore split by the property each one defends: the wait
 * math must be incremental, the threshold must not fire early, paging must follow
 * the role set in 7.1 exactly, the alert must not repeat within one episode, and
 * unlocking must clear the episode so a later attack alerts again.
 */
@DisplayName("7.1 account lockout detection and Admin paging")
class BruteForceLockoutDetectorTest {

    /** The realm's shipped values, as asserted independently by RealmSecurityConfigTest. */
    private static final int FAILURE_FACTOR = 5;
    private static final long WAIT_INCREMENT_SECONDS = 60;
    private static final long MAX_WAIT_SECONDS = 900;
    private static final long MAX_DELTA_SECONDS = 43_200;

    private static final Instant T0 = Instant.parse("2026-09-30T09:00:00Z");

    private static BruteForceLockoutDetector detector() {
        BruteForceLockoutDetector detector = new BruteForceLockoutDetector();
        detector.setPolicy(new BruteForcePolicy(
                FAILURE_FACTOR, WAIT_INCREMENT_SECONDS, MAX_WAIT_SECONDS,
                MAX_DELTA_SECONDS, true));
        return detector;
    }

    private static BruteForceLockoutDetector detectorWith(BruteForcePolicy policy) {
        BruteForceLockoutDetector detector = new BruteForceLockoutDetector();
        detector.setPolicy(policy);
        return detector;
    }

    private static Instant at(long secondsAfterT0) {
        return T0.plusSeconds(secondsAfterT0);
    }

    @Nested
    @DisplayName("7.1 the wait is incremental, not a flat window")
    class IncrementalWait {

        @ParameterizedTest(name = "{0} consecutive failures -> {1}s wait")
        @CsvSource({
                "0,  0",
                "1,  0",
                "4,  0",
                "5,  60",
                "6,  120",
                "7,  180",
                "20, 900",
                "99, 900"
        })
        @DisplayName("grows by one increment per failure past the threshold, then caps")
        void waitIsIncrementalAndCapped(int failures, long expectedWaitSeconds) {
            BruteForcePolicy policy = new BruteForcePolicy(
                    FAILURE_FACTOR, WAIT_INCREMENT_SECONDS, MAX_WAIT_SECONDS, MAX_DELTA_SECONDS, true);

            assertThat(policy.waitSecondsFor(failures)).isEqualTo(expectedWaitSeconds);
        }

        @Test
        @DisplayName("two accounts locked the same way are held for different lengths of time")
        void differentFailureCountsProduceDifferentWaits() {
            BruteForcePolicy policy = new BruteForcePolicy(
                    FAILURE_FACTOR, WAIT_INCREMENT_SECONDS, MAX_WAIT_SECONDS, MAX_DELTA_SECONDS, true);

            assertThat(policy.waitSecondsFor(5))
                    .as("A fixed 900s window would make these equal, and that is precisely the "
                            + "configuration 7.1 rejects: it cannot distinguish a user fumbling a "
                            + "password from a scripted attack that has failed many times")
                    .isNotEqualTo(policy.waitSecondsFor(9));
        }

        @Test
        @DisplayName("the wait never exceeds the configured maximum")
        void waitIsBounded() {
            BruteForcePolicy policy = new BruteForcePolicy(
                    FAILURE_FACTOR, WAIT_INCREMENT_SECONDS, MAX_WAIT_SECONDS, MAX_DELTA_SECONDS, true);

            for (int failures = 1; failures <= 50; failures++) {
                assertThat(policy.waitSecondsFor(failures))
                        .as("An uncapped wait would eventually lock an account out for months")
                        .isLessThanOrEqualTo(MAX_WAIT_SECONDS);
            }
        }

        @Test
        @DisplayName("a flat-window realm is reported faithfully rather than silently corrected")
        void flatWindowIsReportedNotCorrected() {
            // waitIncrementSeconds = 0 is the misconfiguration. The monitor's job is to
            // describe what Keycloak actually did, so it reports the flat max rather
            // than inventing an increment; RealmSecurityConfigTest is what prevents the
            // realm from being configured that way in the first place.
            BruteForcePolicy flat = new BruteForcePolicy(
                    FAILURE_FACTOR, 0, MAX_WAIT_SECONDS, MAX_DELTA_SECONDS, true);

            assertThat(flat.waitSecondsFor(5))
                    .as("With no increment, Keycloak applies the flat maximum")
                    .isEqualTo(MAX_WAIT_SECONDS);
        }

        @Test
        @DisplayName("brute-force protection switched off locks nobody")
        void unprotectedRealmLocksNobody() {
            BruteForcePolicy off = new BruteForcePolicy(
                    FAILURE_FACTOR, WAIT_INCREMENT_SECONDS, MAX_WAIT_SECONDS, MAX_DELTA_SECONDS, false);

            assertThat(off.isLocked(50))
                    .as("isLocked must report the realm's setting, not assume protection is on")
                    .isFalse();
        }
    }

    @Nested
    @DisplayName("7.1 lockout fires at the threshold, not before")
    class Threshold {

        @Test
        @DisplayName("nothing is held below the failure factor")
        void noLockoutBelowThreshold() {
            BruteForceLockoutDetector detector = detector();
            UUID user = UUID.randomUUID();

            for (int attempt = 1; attempt < FAILURE_FACTOR; attempt++) {
                assertThat(detector.recordFailure(user, "analyst", at(attempt), List.of("ANALYST")))
                        .as("Attempt %d of %d is below the threshold; locking here would mean one "
                                + "typo costs an analyst their session", attempt, FAILURE_FACTOR)
                        .isEmpty();
            }
        }

        @Test
        @DisplayName("the attempt that crosses the threshold raises an alert")
        void alertAtThreshold() {
            BruteForceLockoutDetector detector = detector();
            UUID user = UUID.randomUUID();

            for (int attempt = 1; attempt < FAILURE_FACTOR; attempt++) {
                detector.recordFailure(user, "analyst", at(attempt), List.of("ANALYST"));
            }

            Optional<AccountLockoutAlert> alert =
                    detector.recordFailure(user, "analyst", at(FAILURE_FACTOR), List.of("ANALYST"));

            assertThat(alert).isPresent();
            assertThat(alert.orElseThrow().consecutiveFailures()).isEqualTo(FAILURE_FACTOR);
            assertThat(alert.orElseThrow().waitSeconds()).isEqualTo(WAIT_INCREMENT_SECONDS);
            assertThat(alert.orElseThrow().firstLockout())
                    .as("This is the episode's first crossing, so it is the one that pages")
                    .isTrue();
        }

        @Test
        @DisplayName("failures decay, so years-old typos do not accumulate into a lockout")
        void failuresDecay() {
            BruteForceLockoutDetector detector = detector();
            UUID user = UUID.randomUUID();

            // Four failures, the last one well beyond maxDeltaTimeSeconds.
            detector.recordFailure(user, "analyst", at(0), List.of("ANALYST"));
            detector.recordFailure(user, "analyst", at(10), List.of("ANALYST"));
            detector.recordFailure(user, "analyst", at(20), List.of("ANALYST"));
            detector.recordFailure(user, "analyst", at(MAX_DELTA_SECONDS + 100), List.of("ANALYST"));

            assertThat(detector.recordFailure(user, "analyst", at(MAX_DELTA_SECONDS + 110), List.of("ANALYST")))
                    .as("After decay the count restarts, so the fifth attempt is not a lockout")
                    .isEmpty();
        }

        @Test
        @DisplayName("an unconfigured policy raises nothing rather than throwing")
        void missingPolicyIsSafe() {
            BruteForceLockoutDetector detector = new BruteForceLockoutDetector();

            assertThat(detector.recordFailure(UUID.randomUUID(), "analyst", T0, List.of("ANALYST")))
                    .as("The monitor must survive the realm admin API being unreachable -- 7.1's "
                            + "alerting degrades, it does not throw inside the scheduler")
                    .isEmpty();
        }
    }

    @Nested
    @DisplayName("7.1 only privileged roles page the Admin")
    class AdminPaging {

        @Test
        @DisplayName("an Analyst lockout pages the Admin")
        void analystPages() {
            assertThat(pageFor("ANALYST")).isTrue();
        }

        @Test
        @DisplayName("a Security Lead lockout pages the Admin")
        void leadPages() {
            assertThat(pageFor("SECURITY_LEAD")).isTrue();
        }

        @Test
        @DisplayName("a Security Admin lockout pages the Admin")
        void adminPages() {
            assertThat(pageFor("SECURITY_ADMIN")).isTrue();
        }

        @Test
        @DisplayName("an Auditor lockout pages the Admin")
        void auditorPages() {
            assertThat(pageFor("AUDITOR")).isTrue();
        }

        @Test
        @DisplayName("a Reporter lockout does NOT page the Admin")
        void reporterDoesNotPage() {
            assertThat(pageFor("REPORTER"))
                    .as("7.1: 'Reporter lockouts are audited but need not page an Admin by default, "
                            + "to avoid alert fatigue from routine forgotten-password lockouts'")
                    .isFalse();
        }

        @Test
        @DisplayName("a Reporter lockout is still detected and still audited")
        void reporterLockoutIsStillDetected() {
            BruteForceLockoutDetector detector = detector();
            UUID user = UUID.randomUUID();

            Optional<AccountLockoutAlert> alert = Optional.empty();
            for (int attempt = 1; attempt <= FAILURE_FACTOR; attempt++) {
                alert = detector.recordFailure(user, "reporter", at(attempt), List.of("REPORTER"));
            }

            assertThat(alert)
                    .as("Not paging is a routing decision, not a detection decision -- 7.11 requires "
                            + "the audit record for every lockout regardless of role")
                    .isPresent();
            assertThat(alert.orElseThrow().pageAdmin()).isFalse();
            assertThat(alert.orElseThrow().summary())
                    .as("The audit row must make the routing decision visible to whoever reads it")
                    .contains("audit-only");
        }

        @Test
        @DisplayName("a user with no recognisable role is audited but not paged")
        void unknownRoleFailsSafe() {
            BruteForceLockoutDetector detector = detector();
            UUID user = UUID.randomUUID();

            Optional<AccountLockoutAlert> alert = Optional.empty();
            for (int attempt = 1; attempt <= FAILURE_FACTOR; attempt++) {
                alert = detector.recordFailure(
                        user, "someone", at(attempt), List.of("SOME_NEW_ROLE_FROM_THE_IDP"));
            }

            assertThat(alert).isPresent();
            assertThat(alert.orElseThrow().pageAdmin())
                    .as("An unrecognised role is treated as non-privileged so a typo in an IdP role "
                            + "name cannot flood the on-call with pages")
                    .isFalse();
            assertThat(alert.orElseThrow().roles())
                    .as("An unknown role name is ignored, not guessed at")
                    .isEmpty();
        }

        @Test
        @DisplayName("a Reporter holding an additional privileged role still pages")
        void multiRoleAccountPages() {
            BruteForceLockoutDetector detector = detector();
            UUID user = UUID.randomUUID();

            Optional<AccountLockoutAlert> alert = Optional.empty();
            for (int attempt = 1; attempt <= FAILURE_FACTOR; attempt++) {
                alert = detector.recordFailure(
                        user, "lead-who-also-reports", at(attempt), List.of("REPORTER", "SECURITY_LEAD"));
            }

            assertThat(alert.orElseThrow().pageAdmin())
                    .as("7.1 names the privileged set; an account holding any of it is privileged. "
                            + "Keycloak roles are additive, so this is a real configuration.")
                    .isTrue();
        }

        @Test
        @DisplayName("the paging set is exactly the four privileged roles")
        void pagingSetIsExactlyThePrivilegedRoles() {
            assertThat(Set.of(PlatformRole.ANALYST, PlatformRole.SECURITY_LEAD,
                            PlatformRole.SECURITY_ADMIN, PlatformRole.AUDITOR))
                    .allMatch(BruteForceLockoutDetector::pagesAdmin);

            assertThat(BruteForceLockoutDetector.pagesAdmin(PlatformRole.REPORTER)).isFalse();
            assertThat(BruteForceLockoutDetector.pagesAdmin(PlatformRole.SERVICE_ACCOUNT))
                    .as("A service account cannot log in interactively, so there is no human to page "
                            + "about; 7.1's privileged list does not include it")
                    .isFalse();
            assertThat(BruteForceLockoutDetector.pagesAdmin(null)).isFalse();
        }

        private static boolean pageFor(String realmRole) {
            BruteForceLockoutDetector detector = detector();
            UUID user = UUID.randomUUID();

            Optional<AccountLockoutAlert> alert = Optional.empty();
            for (int attempt = 1; attempt <= FAILURE_FACTOR; attempt++) {
                alert = detector.recordFailure(user, "user", at(attempt), List.of(realmRole));
            }
            return alert.orElseThrow().pageAdmin();
        }
    }

    @Nested
    @DisplayName("7.1 one page per episode, and unlocking resets it")
    class EpisodeHandling {

        @Test
        @DisplayName("continued failures after lockout do not re-page")
        void repeatedFailuresDoNotRepage() {
            BruteForceLockoutDetector detector = detector();
            UUID user = UUID.randomUUID();

            for (int attempt = 1; attempt < FAILURE_FACTOR; attempt++) {
                detector.recordFailure(user, "analyst", at(attempt), List.of("ANALYST"));
            }

            AccountLockoutAlert first = detector
                    .recordFailure(user, "analyst", at(FAILURE_FACTOR), List.of("ANALYST"))
                    .orElseThrow();
            assertThat(first.firstLockout()).isTrue();

            for (int attempt = FAILURE_FACTOR + 1; attempt <= FAILURE_FACTOR + 10; attempt++) {
                AccountLockoutAlert later = detector
                        .recordFailure(user, "analyst", at(attempt), List.of("ANALYST"))
                        .orElseThrow();
                assertThat(later.firstLockout())
                        .as("Page %d in the same episode must not page again -- a user under attack "
                                + "generates failures indefinitely, and paging on each one is how an "
                                + "on-call learns to ignore the channel", attempt)
                        .isFalse();
            }
        }

        @Test
        @DisplayName("a successful login clears the counter and the already-paged flag")
        void successResetsTheEpisode() {
            BruteForceLockoutDetector detector = detector();
            UUID user = UUID.randomUUID();

            for (int attempt = 1; attempt <= FAILURE_FACTOR; attempt++) {
                detector.recordFailure(user, "analyst", at(attempt), List.of("ANALYST"));
            }
            assertThat(detector.wasLocked(user))
                    .as("7.1: 'Lockout and unlock events are audited' -- the monitor has to know the "
                            + "account was locked in order to record the unlock")
                    .isTrue();

            detector.recordSuccess(user);

            assertThat(detector.wasLocked(user))
                    .as("After a successful login the account is no longer considered locked")
                    .isFalse();

            // A new attack on the same account must alert again rather than being
            // suppressed as 'already paged'.
            Optional<AccountLockoutAlert> secondEpisode = Optional.empty();
            for (int attempt = 1; attempt <= FAILURE_FACTOR; attempt++) {
                secondEpisode = detector.recordFailure(
                        user, "analyst", at(FAILURE_FACTOR + 100 + attempt), List.of("ANALYST"));
            }

            assertThat(secondEpisode.orElseThrow().firstLockout())
                    .as("An unlock is the start of a new episode; a later lockout is a new event and "
                            + "must page")
                    .isTrue();
        }

        @Test
        @DisplayName("an account that never locked does not report itself as locked on login")
        void ordinaryLoginIsNotAnUnlockEvent() {
            BruteForceLockoutDetector detector = detector();
            UUID user = UUID.randomUUID();

            assertThat(detector.wasLocked(user))
                    .as("An ordinary first-time login is not a lockout event; auditing it as one "
                            + "would fill the audit log with noise that hides real unlocks")
                    .isFalse();
        }

        @Test
        @DisplayName("nulls and blank input do not throw")
        void malformedEventsAreTolerated() {
            BruteForceLockoutDetector detector = detector();

            assertThat(detector.recordFailure(null, "nobody", T0, List.of("ANALYST"))).isEmpty();
            assertThat(detector.recordFailure(UUID.randomUUID(), "nobody", null, List.of("ANALYST")))
                    .isEmpty();
            assertThat(detector.recordFailure(UUID.randomUUID(), "nobody", T0, null)).isEmpty();
            detector.recordSuccess(null);
        }
    }

    @Nested
    @DisplayName("the alert payload carries what the on-call needs")
    class AlertPayload {

        @Test
        @DisplayName("a privileged lockout states that it is paging the Admin")
        void summaryStatesPaging() {
            BruteForceLockoutDetector detector = detector();
            UUID user = UUID.randomUUID();

            AccountLockoutAlert alert = null;
            for (int attempt = 1; attempt <= FAILURE_FACTOR; attempt++) {
                alert = detector.recordFailure(user, "a.lead", at(attempt), List.of("SECURITY_LEAD"))
                        .orElse(null);
            }

            assertThat(alert).isNotNull();
            assertThat(alert.summary())
                    .contains("a.lead")
                    .contains("paging Admin");
            assertThat(alert.roles()).contains(PlatformRole.SECURITY_LEAD);
        }

        @Test
        @DisplayName("the wait is carried, so a rising wait is visible to the on-call")
        void alertCarriesTheWait() {
            BruteForceLockoutDetector detector = detector();
            UUID user = UUID.randomUUID();

            AccountLockoutAlert alert = null;
            for (int attempt = 1; attempt <= FAILURE_FACTOR + 3; attempt++) {
                alert = detector.recordFailure(user, "a.lead", at(attempt), List.of("SECURITY_LEAD"))
                        .orElse(null);
            }

            assertThat(alert).isNotNull();
            assertThat(alert.waitSeconds())
                    .as("The value distinguishes an account under sustained attack from one that "
                            + "simply tripped once; three of these in a row is credential stuffing")
                    .isEqualTo((long) (FAILURE_FACTOR + 3 - FAILURE_FACTOR + 1) * WAIT_INCREMENT_SECONDS);
            assertThat(AccountLockoutAlert.AUDIT_ACTION)
                    .as("7.11 needs a stable action name for the audit row and the Kafka key")
                    .isEqualTo("account_lockout");
        }

        @Test
        @DisplayName("detecting a lockout takes no measurable time")
        void detectionIsNotABlockingHotPath() {
            BruteForceLockoutDetector detector = detector();
            UUID user = UUID.randomUUID();
            for (int attempt = 1; attempt <= FAILURE_FACTOR; attempt++) {
                detector.recordFailure(user, "analyst", at(attempt), List.of("ANALYST"));
            }

            var before = System.nanoTime();
            for (int attempt = 0; attempt < 10_000; attempt++) {
                detector.recordFailure(user, "analyst", at(1000 + attempt), List.of("ANALYST"));
            }
            Duration elapsed = Duration.ofNanos(System.nanoTime() - before);

            assertThat(elapsed.toMillis())
                    .as("This runs on the poll loop for every event in the feed batch")
                    .isLessThan(2_000);
        }
    }
}
