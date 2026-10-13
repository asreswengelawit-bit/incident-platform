package com.company.incidentplatform.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Section 7.1 -- MFA enforcement, the Section 10 "MFA required for privileged
 * roles" row of the test matrix.
 *
 * <p>Two distinct properties are under test, and conflating them is the easy
 * mistake: that the <em>policy</em> says which roles need a second factor, and
 * that the <em>evidence</em> is actually present in the token. A system can
 * satisfy the first and fail the second, which is how a role that is supposed to
 * require MFA ends up reachable with a password alone.
 */
class MfaVerifierTest {

    private final MfaVerifier verifier = new MfaVerifier("mfa");

    @Nested
    @DisplayName("7.1 which roles require MFA")
    class Policy {

        @ParameterizedTest
        @ValueSource(strings = {"ANALYST", "SECURITY_LEAD", "SECURITY_ADMIN", "AUDITOR"})
        @DisplayName("privileged roles require MFA unconditionally")
        void privilegedRolesRequireMfa(String roleName) {
            PlatformRole role = PlatformRole.valueOf(roleName);
            PlatformUser user = userWith(role);

            var check = verifier.requireMfa(user, List.of(), null, false);

            assertThat(role.requiresMfa()).isTrue();
            assertThat(check.passed()).isFalse();
            assertThat(check.deniedReason()).isEqualTo(DeniedReason.MFA_REQUIRED);
        }

        @Test
        @DisplayName("a privileged role with MFA evidence passes")
        void privilegedRoleWithEvidencePasses() {
            var check = verifier.requireMfa(userWith(PlatformRole.ANALYST), List.of("pwd", "otp"), null, false);

            assertThat(check.passed()).isTrue();
            assertThat(check.rule()).isEqualTo("mfa.satisfied");
        }

        @Test
        @DisplayName("Reporters do not require MFA by default -- 7.1 says configurable")
        void reporterMfaOptionalByDefault() {
            var check = verifier.requireMfa(userWith(PlatformRole.REPORTER), List.of(), null, false);

            assertThat(check.passed()).isTrue();
            assertThat(check.rule()).isEqualTo("mfa.not_required");
        }

        @Test
        @DisplayName("Reporters require MFA when the deployment configures it to")
        void reporterMfaWhenRequired() {
            var check = verifier.requireMfa(userWith(PlatformRole.REPORTER), List.of(), null, true);

            assertThat(check.passed()).isFalse();
            assertThat(check.deniedReason()).isEqualTo(DeniedReason.MFA_REQUIRED);
        }

        @Test
        @DisplayName("the Service Account is not a human and does not present MFA")
        void serviceAccountExempt() {
            // FR-1.4/1.5: automated ingestion authenticates with a client
            // secret, not a second factor. Requiring MFA of it would make the
            // ingestion path unusable, and it holds no read access to protect.
            var check = verifier.requireMfa(userWith(PlatformRole.SERVICE_ACCOUNT), List.of(), null, true);

            assertThat(check.passed()).isTrue();
        }
    }

    @Nested
    @DisplayName("what counts as MFA evidence in the token")
    class Evidence {

        @ParameterizedTest
        @ValueSource(strings = {"mfa", "otp", "totp", "hotp", "sms", "webauthn", "fido2", "piv", "hwk", "skid"})
        @DisplayName("a recognised multi-factor amr value satisfies the requirement")
        void recognisedAmrValues(String method) {
            assertThat(verifier.isMfaSatisfied(List.of("pwd", method), null)).isTrue();
        }

        @ParameterizedTest
        @ValueSource(strings = {"MFA", "Otp", "TOTP", "WebAuthn"})
        @DisplayName("amr matching is case-insensitive")
        void amrCaseInsensitive(String method) {
            // Keycloak's vocabulary casing is not something the API should
            // depend on; a case difference must not read as "no MFA".
            assertThat(verifier.isMfaSatisfied(List.of("pwd", method), null)).isTrue();
        }

        @Test
        @DisplayName("a single password method is not MFA")
        void passwordOnlyIsNotMfa() {
            // The central case. A token whose only amr is "pwd" means a
            // password-only login, and must not satisfy the requirement.
            assertThat(verifier.isMfaSatisfied(List.of("pwd"), null)).isFalse();
        }

        @ParameterizedTest
        @EmptySource
        @DisplayName("an absent amr claim is not MFA evidence")
        void absentAmr(List<String> amr) {
            assertThat(verifier.isMfaSatisfied(amr, null)).isFalse();
        }

        @Test
        @DisplayName("a null element in amr does not throw")
        void nullAmrElement() {
            java.util.List<String> amr = new java.util.ArrayList<>();
            amr.add(null);

            assertThat(verifier.isMfaSatisfied(amr, null)).isFalse();
        }

        @Test
        @DisplayName("a matching acr satisfies the requirement even without a recognisable amr")
        void acrAloneSatisfies() {
            // A custom authenticator may populate only acr. Requiring both would
            // make MFA unverifiable for that deployment.
            assertThat(verifier.isMfaSatisfied(List.of("custom-otp"), "mfa")).isTrue();
        }

        @Test
        @DisplayName("a weaker acr does not satisfy the requirement")
        void weakerAcrRejected() {
            assertThat(verifier.isMfaSatisfied(List.of("pwd"), "low")).isFalse();
        }

        @Test
        @DisplayName("acr matching is case-insensitive")
        void acrCaseInsensitive() {
            assertThat(verifier.isMfaSatisfied(List.of("pwd"), "MFA")).isTrue();
        }

        @Test
        @DisplayName("a blank required acr never satisfies on its own")
        void blankRequiredAcrNeverSatisfies() {
            // Guards against a deployment that leaves required-acr empty and
            // therefore accepts any acr value at all.
            var laxVerifier = new MfaVerifier("   ");

            assertThat(laxVerifier.isMfaSatisfied(List.of("pwd"), "anything")).isFalse();
        }

        @Test
        @DisplayName("amr evidence still works when no acr is configured")
        void amrWorksWithoutAcrConfig() {
            var noAcrVerifier = new MfaVerifier(null);

            assertThat(noAcrVerifier.isMfaSatisfied(List.of("mfa"), null)).isTrue();
            assertThat(noAcrVerifier.isMfaSatisfied(List.of("pwd"), null)).isFalse();
        }
    }

    private static PlatformUser userWith(PlatformRole role) {
        RolePermissions permissions =
                RolePermissions.fromJson(new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode());
        return new PlatformUser(
                java.util.UUID.randomUUID(), "kc-sub", "user@example.test", "User",
                "SECURITY", role, permissions, true, false);
    }
}
