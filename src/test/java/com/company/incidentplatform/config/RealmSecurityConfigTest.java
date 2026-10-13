package com.company.incidentplatform.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.company.incidentplatform.security.lockout.BruteForcePolicy;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Section 7.1 / 7.9 -- the realm file is a security control, so it gets tested
 * like one.
 *
 * <p><strong>Why this exists.</strong> Two separate parts of the implementation
 * already made a promise this test keeps:
 *
 * <ul>
 *   <li>{@code BruteForcePolicy.waitSecondsFor} says, of a flat
 *       {@code waitIncrementSeconds = 0}: "a realm-config regression test is what
 *       enforces 7.1's incremental requirement".</li>
 *   <li>The realm file's own {@code _comment_password_policy} says "Do not lower
 *       passwordHistory below 10", and {@code _comment_brute_force} says "Do not
 *       set waitIncrementSeconds to 0".</li>
 * </ul>
 *
 * <p>Before this test, both instructions were enforced by a comment in a JSON
 * file. That is the weakest possible form of enforcement: an operator applying a
 * realm change is editing exactly this file, and a diff that lowers
 * {@code passwordHistory} to 5 or zeroes {@code waitIncrementSeconds} is
 * perfectly plausible during a routine "sync the realm with staging" -- and
 * nothing in the build would flag it. 7.1's actual complaint is that a password
 * history of 5 is a silent weakening, which is exactly what a comment cannot
 * prevent.
 *
 * <p><strong>Why the deferral block is asserted too.</strong> 7.1 permits
 * deferring the breached-password check "but the deferral itself must be flagged
 * back for sign-off, not silently dropped". A {@code _deferred_security_controls}
 * entry is that flag, so its absence is a spec violation and not a tidy-up. This
 * test is the thing that makes "explicitly deferred" mechanically different from
 * "removed because someone tidied the file".
 *
 * <p>These are deliberately assertions on the <em>shipped artefact</em> rather
 * than on the backend classes that read it. Reading the file is the only way to
 * catch the regression, because the bug is a config edit, not a code change.
 */
@DisplayName("Keycloak realm export holds the 7.1 / 7.9 authentication controls")
class RealmSecurityConfigTest {

    private static final int PASSWORD_HISTORY_FLOOR = 10;

    private static JsonNode realm;

    @BeforeAll
    static void loadRealm() throws IOException {
        realm = new ObjectMapper().readTree(locateRealmExport().toFile());
    }

    /**
     * Gradle runs tests with the module directory as the working directory, but the
     * realm export is a sibling of the module rather than a resource inside it --
     * it is an operator-facing artefact, not a jar input, and packaging it would
     * invite a runtime fallback that quietly diverges from what is deployed.
     */
    private static Path locateRealmExport() {
        List<Path> candidates = new ArrayList<>();
        for (String start : new String[] {"..", ".", "../..", "../../.."}) {
            candidates.add(Path.of(start, "keycloak", "realm", "incident-platform-realm.json"));
        }
        return candidates.stream()
                .filter(Files::exists)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "incident-platform-realm.json not found relative to "
                                + Path.of("").toAbsolutePath() + "; looked in " + candidates));
    }

    private static String passwordPolicy() {
        return realm.path("passwordPolicy").asText();
    }

    private static int passwordHistory() {
        Matcher matcher = Pattern.compile("passwordHistory\\((\\d+)\\)").matcher(passwordPolicy());
        assertThat(matcher.find())
                .as("7.1 requires 'no reuse of last %d passwords', which is expressed as "
                        + "passwordHistory(n). Policy found: %s", PASSWORD_HISTORY_FLOOR, passwordPolicy())
                .isTrue();
        return Integer.parseInt(matcher.group(1));
    }

    private static JsonNode client(String clientId) {
        for (JsonNode client : realm.path("clients")) {
            if (clientId.equals(client.path("clientId").asText())) {
                return client;
            }
        }
        throw new AssertionError("No client '" + clientId + "' in the realm export");
    }

    private static int accessTokenLifespanSeconds(String clientId) {
        JsonNode attributes = client(clientId).path("attributes");
        assertThat(attributes.has("access.token.lifespan"))
                .as("7.9 names a per-client access-token lifetime for %s; relying on the "
                        + "realm default would let a later accessTokenLifespan edit move "
                        + "this client off its specified value silently", clientId)
                .isTrue();
        return attributes.path("access.token.lifespan").asInt();
    }

    @Nested
    @DisplayName("7.1 password policy")
    class PasswordPolicy {

        @Test
        @DisplayName("no reuse of the last 10 passwords")
        void passwordHistoryMatchesTheSpec() {
            assertThat(passwordHistory())
                    .as("7.1: 'no reuse of last %d passwords'", PASSWORD_HISTORY_FLOOR)
                    .isGreaterThanOrEqualTo(PASSWORD_HISTORY_FLOOR);
        }

        @Test
        @DisplayName("minimum 12 characters")
        void lengthMatchesTheSpec() {
            Matcher matcher = Pattern.compile("length\\((\\d+)\\)").matcher(passwordPolicy());
            assertThat(matcher.find())
                    .as("7.1 requires a 12-character minimum. Policy found: %s", passwordPolicy())
                    .isTrue();
            assertThat(Integer.parseInt(matcher.group(1)))
                    .as("7.1: 'minimum 12 characters'")
                    .isGreaterThanOrEqualTo(12);
        }

        @Test
        @DisplayName("the username and email are excluded from the password")
        void notUsernameIsConfigured() {
            assertThat(passwordPolicy())
                    .as("7.1: 'complexity rules' -- notUsername is the clause that keeps the "
                            + "account name and email out of the password")
                    .contains("notUsername");
        }
    }

    @Nested
    @DisplayName("7.1 brute-force detection is incremental, not a flat window")
    class BruteForce {

        @Test
        @DisplayName("wait time increments rather than jumping to a fixed window")
        void waitIncrementIsPositive() {
            assertThat(realm.path("waitIncrementSeconds").asInt())
                    .as("7.1: 'wait duration increases with each consecutive failure ... rather than "
                            + "a single flat lockout window'. A fixed window is waitIncrementSeconds = 0, "
                            + "which is the configuration 7.1 explicitly rejects.")
                    .isGreaterThan(0);
        }

        @Test
        @DisplayName("the incremental wait is capped, not unbounded")
        void waitIsCapped() {
            int increment = realm.path("waitIncrementSeconds").asInt();
            int cap = realm.path("maxFailureWaitSeconds").asInt();

            assertThat(cap)
                    .as("7.1: wait time grows 'up to a capped maximum', so the cap must be real")
                    .isGreaterThan(0);
            assertThat(cap)
                    .as("A cap at or below the first increment would make every lockout identical, "
                            + "which is the flat-window behaviour 7.1 rejects wearing a different value")
                    .isGreaterThan(increment);
        }

        @Test
        @DisplayName("protection is enabled and is not a permanent lockout")
        void protectionEnabledWithoutPermanentLockout() {
            assertThat(realm.path("bruteForceProtected").asBoolean())
                    .as("7.1 requires Brute Force Detection to be on")
                    .isTrue();

            assertThat(realm.path("permanentLockout").asBoolean())
                    .as("permanentLockout = true locks the account indefinitely, which removes the "
                            + "incremental wait entirely -- the account never returns, so no wait is "
                            + "applied. It must be false for 7.1's incremental behaviour to mean anything.")
                    .isFalse();
        }

        @Test
        @DisplayName("Quick Login Check covers rapid-fire attempts")
        void quickLoginCheckConfigured() {
            assertThat(realm.path("quickLoginCheckMilliSeconds").asLong())
                    .as("7.1: 'plus Quick Login Check for rapid-fire attempts'")
                    .isGreaterThan(0);
            assertThat(realm.path("minimumQuickLoginWaitSeconds").asLong())
                    .as("The Quick Login Check wait must be set, or the check detects and does nothing")
                    .isGreaterThan(0);
        }

        @Test
        @DisplayName("the failure counter decays so old failures do not accumulate forever")
        void failureCounterDecays() {
            assertThat(realm.path("maxDeltaTimeSeconds").asLong())
                    .as("Without a decay window a user who failed four times a year apart locks on "
                            + "the fifth attempt today")
                    .isGreaterThan(0);
        }

        @Test
        @DisplayName("the backend's wait math agrees with the shipped realm values")
        void waitGrowsToACap() {
            // Deliberately driven through the production BruteForcePolicy rather than a
            // reimplementation of the arithmetic here. The point of the check is that the
            // backend's reconstruction of Keycloak's lockout (7.1's mechanism note: the
            // wait-math "must read the same waitIncrementSeconds/maxWait/failureFactor values
            // as the realm config ... so the two can't silently drift apart") is computed
            // from the numbers actually shipped. A copy of the formula in this test would
            // pass even if BruteForcePolicy drifted.
            BruteForcePolicy policy = new BruteForcePolicy(
                    realm.path("failureFactor").asInt(),
                    realm.path("waitIncrementSeconds").asInt(),
                    realm.path("maxFailureWaitSeconds").asInt(),
                    realm.path("maxDeltaTimeSeconds").asInt(),
                    realm.path("bruteForceProtected").asBoolean());

            long previous = 0;
            for (int failures = 1; failures <= 8; failures++) {
                long wait = policy.waitSecondsFor(failures);

                if (failures < policy.failureFactor()) {
                    assertThat(wait)
                            .as("Below failureFactor=%d nothing is held, so a user is never locked out "
                                    + "for a single typo", policy.failureFactor())
                            .isZero();
                    continue;
                }

                assertThat(wait)
                        .as("The wait must never shrink as failures accumulate (at %d failures)", failures)
                        .isGreaterThanOrEqualTo(previous);
                assertThat(wait)
                        .as("The wait must never exceed the configured cap (at %d failures)", failures)
                        .isLessThanOrEqualTo(policy.maxFailureWaitSeconds());
                assertThat(policy.isLocked(failures))
                        .as("At or past the factor the account is locked")
                        .isTrue();
                previous = wait;
            }

            assertThat(previous)
                    .as("The final wait must be strictly positive, or nothing is ever actually held")
                    .isPositive();
        }
    }

    @Nested
    @DisplayName("7.1 breached-password check is deferred explicitly, not silently")
    class BreachedPasswordDeferral {

        @Test
        @DisplayName("the deferral is recorded with a status, a reason and a target phase")
        void deferralIsRecorded() {
            JsonNode deferrals = realm.path("_deferred_security_controls");
            assertThat(deferrals.isArray() && !deferrals.isEmpty())
                    .as("7.1 permits deferring the breached-password check 'but the deferral itself must "
                            + "be flagged back for sign-off, not silently dropped'. Deleting this block "
                            + "turns a recorded deferral into a silent omission, which is the failure "
                            + "the clause exists to prevent.")
                    .isTrue();

            JsonNode breach = null;
            for (JsonNode entry : deferrals) {
                if (entry.path("requirement").asText().toLowerCase().contains("breached-password")) {
                    breach = entry;
                }
            }
            assertThat(breach)
                    .as("The breached-password deferral must be identifiable by requirement")
                    .isNotNull();

            assertThat(breach.path("status").asText())
                    .as("A deferral needs an explicit status, so it cannot be mistaken for 'done'")
                    .contains("DEFERRED");

            assertThat(breach.path("why").asText())
                    .as("7.1 names the condition precisely: deferrable only if it needs a custom SPI. "
                            + "The reason must say so.")
                    .isNotBlank();

            assertThat(breach.path("target_phase").asText())
                    .as("A deferral with no target phase is just an omission with a comment attached")
                    .isNotBlank();
        }
    }

    @Nested
    @DisplayName("7.9 token lifetimes are set per client type")
    class TokenLifetimes {

        @ParameterizedTest(name = "{0} access-token TTL is {1}s")
        @CsvSource({
                "incident-platform-spa, 900",
                "incident-platform-ingest, 300",
                "incident-platform-api, 900"
        })
        @DisplayName("each client's access-token TTL is the value 7.9 names")
        void accessTokenTtlMatchesClientType(String clientId, int expectedSeconds) {
            assertThat(accessTokenLifespanSeconds(clientId))
                    .as("7.9: 900s for the interactive SPA client, 300s (5 min) for the "
                            + "service-account/ingest client")
                    .isEqualTo(expectedSeconds);
        }

        @Test
        @DisplayName("refresh-token rotation and reuse detection are enabled")
        void refreshTokensRotateAndDetectReuse() {
            assertThat(realm.path("revokeRefreshToken").asBoolean())
                    .as("7.9: 'refresh tokens subject to rotation and reuse detection'. "
                            + "revokeRefreshToken makes a refresh token single-use, so replaying one "
                            + "is detected as reuse and the session family is revoked rather than a "
                            + "new token being minted.")
                    .isTrue();

            assertThat(realm.path("refreshTokenMaxReuse").asInt())
                    .as("7.9: 'a reused/replayed refresh token immediately revokes the whole session "
                            + "family'. A value above 0 permits a refresh token to be replayed without "
                            + "detection.")
                    .isZero();
        }

        @Test
        @DisplayName("the SPA client is a public client using PKCE")
        void spaClientIsPublicWithPkce() {
            JsonNode spa = client("incident-platform-spa");
            assertThat(spa.path("publicClient").asBoolean())
                    .as("A confidential SPA would put a client secret in shipped browser code")
                    .isTrue();
            assertThat(spa.path("attributes").path("pkce.code.challenge.method").asText())
                    .as("7.9/7.5: a public client relies on PKCE for authorization-code interception "
                            + "protection")
                    .isEqualTo("S256");
        }
    }

    @Nested
    @DisplayName("7.1 account lifecycle and 7.11 event source")
    class Events {

        @ParameterizedTest
        @ValueSource(strings = {"REPORTER", "ANALYST", "SECURITY_LEAD", "SECURITY_ADMIN", "AUDITOR",
                "SERVICE_ACCOUNT"})
        @DisplayName("every coarse role 7.2.1 depends on exists in the realm")
        void coarseRolesAreDefined(String role) {
            boolean found = false;
            for (JsonNode r : realm.path("roles").path("realm")) {
                if (role.equals(r.path("name").asText())) {
                    found = true;
                }
            }
            assertThat(found)
                    .as("7.2.1 scopes visibility by coarse role; a role the realm does not define is "
                            + "a role no token can carry, and the backend converter fails closed on it")
                    .isTrue();
        }

        @Test
        @DisplayName("user events are enabled -- the lockout monitor's only input")
        void userEventsEnabled() {
            assertThat(realm.path("eventsEnabled").asBoolean())
                    .as("7.1's lockout mechanism is the backend polling /admin/realms/{realm}/events "
                            + "for LOGIN and LOGIN_ERROR. With eventsEnabled = false there is nothing to "
                            + "poll and lockout alerting silently never fires.")
                    .isTrue();
        }

        @Test
        @DisplayName("admin events are retained long enough for the application projection to stay current")
        void adminEventsExpireEventually() {
            assertThat(realm.path("eventsExpiration").asLong())
                    .as("6.2.4 keeps the application role projection in sync from Keycloak admin events; "
                            + "a short retention is a deliberate choice, but a zero/absent value is not")
                    .isGreaterThan(0);
        }
    }
}
