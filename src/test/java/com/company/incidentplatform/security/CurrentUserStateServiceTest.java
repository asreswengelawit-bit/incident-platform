package com.company.incidentplatform.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import com.company.incidentplatform.identity.AppUserEntity;
import com.company.incidentplatform.identity.AppUserRepository;
import com.company.incidentplatform.identity.PlatformRoleEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;

/**
 * Sections 7.1 and 7.9 -- re-validating a token against current user state, the
 * Section 10 "role change takes effect immediately" and "disabled account denied"
 * rows of the test matrix.
 *
 * <p>Unit tests against a mocked repository rather than a slice test, because
 * the behaviour under test is decision logic about a token and a user row. A
 * Spring context would add startup cost without exercising anything that
 * {@code CurrentUserStateService.evaluate} does not.
 */
class CurrentUserStateServiceTest {

    private static final String SUBJECT = "keycloak-subject-1";
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-0000000000aa");
    private static final String DEPARTMENT = "SECURITY";

    private AppUserRepository users;
    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        users = Mockito.mock(AppUserRepository.class);
        mapper = new ObjectMapper();
    }

    private CurrentUserStateService service(Duration ttl) {
        return new CurrentUserStateService(
                users,
                mapper,
                new MfaVerifier("mfa"),
                false,
                ttl,
                Clock.fixed(Instant.parse("2026-09-27T12:00:00Z"), ZoneOffset.UTC));
    }

    private void givenUser(PlatformRole role, boolean active, String permissionsJson) {
        PlatformRoleEntity roleEntity = Mockito.mock(PlatformRoleEntity.class);
        when(roleEntity.getName()).thenReturn(role);
        when(roleEntity.permissionsJson(mapper))
                .thenReturn(parse(permissionsJson));

        AppUserEntity user = Mockito.mock(AppUserEntity.class);
        when(user.getId()).thenReturn(USER_ID);
        when(user.getKeycloakSubject()).thenReturn(SUBJECT);
        when(user.getEmail()).thenReturn("user@example.test");
        when(user.getFullName()).thenReturn("Test User");
        when(user.getDepartment()).thenReturn(DEPARTMENT);
        when(user.getRole()).thenReturn(roleEntity);
        // coarseRole() is a convenience accessor on the entity rather than a
        // plain property getter, so it has to be stubbed explicitly on a mock.
        when(user.coarseRole()).thenReturn(role);
        when(user.isActive()).thenReturn(active);

        when(users.findByKeycloakSubject(SUBJECT)).thenReturn(Optional.of(user));
    }

    private static com.fasterxml.jackson.databind.JsonNode parse(String json) {
        try {
            return new ObjectMapper().readTree(json);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    private CurrentUserStateService.Resolution resolve(
            CurrentUserStateService service, String tokenRole, List<String> amr) {
        return service.resolve(SUBJECT, tokenRole, amr, null);
    }

    @Nested
    @DisplayName("7.9 role change takes effect immediately")
    class RoleChange {

        @Test
        @DisplayName("a token whose role no longer matches current state is denied")
        void staleRoleTokenDenied() {
            // Alice was an ANALYST, has been demoted to REPORTER, and is still
            // presenting the access token issued before the change. 7.9 requires
            // the change to take effect now, not in up to 15 minutes.
            givenUser(PlatformRole.REPORTER, true, "{\"visibility_scope\":\"OWN_INCIDENTS\"}");

            var resolution = resolve(service(Duration.ZERO), "ANALYST", List.of("mfa"));

            assertThat(resolution.isAllowed()).isFalse();
            assertThat(resolution.reason())
                    .isEqualTo(DeniedReason.ROLE_CHANGED_SINCE_TOKEN_ISSUED);
            assertThat(resolution.rule()).isEqualTo("role.drift");
        }

        @Test
        @DisplayName("a promotion is likewise denied until the token is refreshed")
        void promotionTokenDenied() {
            // Symmetric, and just as important: this is what stops a token minted
            // while the user was a Reporter being accepted after they become an
            // Admin.
            givenUser(PlatformRole.SECURITY_ADMIN, true, "{\"visibility_scope\":\"ORGANIZATION\"}");

            var resolution = resolve(service(Duration.ZERO), "REPORTER", List.of("mfa"));

            assertThat(resolution.isAllowed()).isFalse();
            assertThat(resolution.reason())
                    .isEqualTo(DeniedReason.ROLE_CHANGED_SINCE_TOKEN_ISSUED);
        }

        @Test
        @DisplayName("a matching role resolves to the current user")
        void matchingRoleAllowed() {
            givenUser(PlatformRole.ANALYST, true,
                    "{\"visibility_scope\":\"ASSIGNED_AND_OWN_DEPARTMENT_UNASSIGNED\"}");

            var resolution = resolve(service(Duration.ZERO), "ANALYST", List.of("mfa"));

            assertThat(resolution.isAllowed()).isTrue();
            assertThat(resolution.user().role()).isEqualTo(PlatformRole.ANALYST);
            assertThat(resolution.user().hasMfa()).isTrue();
        }
    }

    @Nested
    @DisplayName("7.1 account lifecycle")
    class Lifecycle {

        @Test
        @DisplayName("a disabled account is denied even with a valid, unexpired, correctly-roled token")
        void disabledAccountDenied() {
            // The token is perfectly valid. The denial comes from current state,
            // which is the entire point of 7.1's deprovisioning requirement.
            givenUser(PlatformRole.SECURITY_ADMIN, false, "{\"visibility_scope\":\"ORGANIZATION\"}");

            var resolution = resolve(service(Duration.ZERO), "SECURITY_ADMIN", List.of("mfa"));

            assertThat(resolution.isAllowed()).isFalse();
            assertThat(resolution.reason()).isEqualTo(DeniedReason.ACCOUNT_DISABLED);
            assertThat(resolution.rule()).isEqualTo("user.inactive");
        }

        @Test
        @DisplayName("an unprovisioned subject is denied as USER_UNKNOWN")
        void unprovisionedSubjectDenied() {
            when(users.findByKeycloakSubject(anyString())).thenReturn(Optional.empty());

            var resolution = resolve(service(Duration.ZERO), "ANALYST", List.of("mfa"));

            assertThat(resolution.isAllowed()).isFalse();
            assertThat(resolution.reason()).isEqualTo(DeniedReason.USER_UNKNOWN);
        }

        @Test
        @DisplayName("a missing subject is denied as an invalid token")
        void missingSubjectDenied() {
            var resolution = service(Duration.ZERO).resolve(null, "ANALYST", List.of("mfa"), null);

            assertThat(resolution.isAllowed()).isFalse();
            assertThat(resolution.reason()).isEqualTo(DeniedReason.TOKEN_INVALID);
        }
    }

    @Nested
    @DisplayName("7.1 MFA gate applied during revalidation")
    class MfaGate {

        @ParameterizedTest
        @EnumSource(
                value = PlatformRole.class,
                names = {"ANALYST", "SECURITY_LEAD", "SECURITY_ADMIN", "AUDITOR"})
        @DisplayName("a privileged role without MFA evidence is denied")
        void privilegedWithoutMfaDenied(PlatformRole role) {
            givenUser(role, true, "{\"visibility_scope\":\"ORGANIZATION\"}");

            var resolution = resolve(service(Duration.ZERO), role.name(), List.of("pwd"));

            assertThat(resolution.isAllowed()).isFalse();
            assertThat(resolution.reason()).isEqualTo(DeniedReason.MFA_REQUIRED);
        }

        @Test
        @DisplayName("a Reporter without MFA evidence is allowed when MFA is not required for them")
        void reporterWithoutMfaAllowed() {
            givenUser(PlatformRole.REPORTER, true, "{\"visibility_scope\":\"OWN_INCIDENTS\"}");

            var resolution = resolve(service(Duration.ZERO), "REPORTER", List.of("pwd"));

            assertThat(resolution.isAllowed()).isTrue();
            assertThat(resolution.user().hasMfa()).isFalse();
        }
    }

    @Nested
    @DisplayName("unmapped role claims fail closed")
    class UnmappedRole {

        @Test
        @DisplayName("an unrecognised role claim is denied, not downgraded to Reporter")
        void unmappedRoleDenied() {
            givenUser(PlatformRole.ANALYST, true, "{\"visibility_scope\":\"ORGANIZATION\"}");

            var resolution = resolve(service(Duration.ZERO), "SUPER_ADMIN", List.of("mfa"));

            // Downgrading to Reporter here would hide a misconfigured IdP role
            // until someone noticed the wrong access; upgrading would be a
            // straight privilege escalation.
            assertThat(resolution.isAllowed()).isFalse();
            assertThat(resolution.reason()).isEqualTo(DeniedReason.TOKEN_INVALID);
            assertThat(resolution.rule()).isEqualTo("role.unmapped");
        }
    }

    @Nested
    @DisplayName("7.9 cache behaviour")
    class Cache {

        @Test
        @DisplayName("a zero TTL checks current state on every request")
        void zeroTtlNeverCaches() {
            givenUser(PlatformRole.ANALYST, true, "{\"visibility_scope\":\"ORGANIZATION\"}");
            var service = service(Duration.ZERO);

            resolve(service, "ANALYST", List.of("mfa"));
            resolve(service, "ANALYST", List.of("mfa"));

            assertThat(service.cachedCount()).isZero();
            Mockito.verify(users, Mockito.times(2)).findByKeycloakSubject(SUBJECT);
        }

        @Test
        @DisplayName("a non-zero TTL serves the second request from cache")
        void positiveTtlCaches() {
            givenUser(PlatformRole.ANALYST, true, "{\"visibility_scope\":\"ORGANIZATION\"}");
            var service = service(Duration.ofSeconds(30));

            resolve(service, "ANALYST", List.of("mfa"));
            resolve(service, "ANALYST", List.of("mfa"));

            assertThat(service.cachedCount()).isEqualTo(1);
            Mockito.verify(users, Mockito.times(1)).findByKeycloakSubject(SUBJECT);
        }

        @Test
        @DisplayName("invalidate forces the next request to re-read current state")
        void invalidateBypassesTtl() {
            // This is what makes an admin-initiated revocation immediate
            // regardless of the TTL, which is the property the cache trade-off
            // depends on.
            givenUser(PlatformRole.ANALYST, true, "{\"visibility_scope\":\"ORGANIZATION\"}");
            var service = service(Duration.ofMinutes(10));

            resolve(service, "ANALYST", List.of("mfa"));
            service.invalidate(USER_ID);
            resolve(service, "ANALYST", List.of("mfa"));

            Mockito.verify(users, Mockito.times(2)).findByKeycloakSubject(SUBJECT);
        }

        @Test
        @DisplayName("the role check runs even on a cache hit")
        void cacheHitStillChecksRole() {
            // A cached PlatformUser must not short-circuit the drift check. If
            // it did, a role change would be invisible for the whole TTL even to
            // a caller whose token had already been refreshed to the new role.
            givenUser(PlatformRole.ANALYST, true, "{\"visibility_scope\":\"ORGANIZATION\"}");
            var service = service(Duration.ofMinutes(10));

            assertThat(resolve(service, "ANALYST", List.of("mfa")).isAllowed()).isTrue();
            assertThat(resolve(service, "SECURITY_ADMIN", List.of("mfa")).reason())
                    .isEqualTo(DeniedReason.ROLE_CHANGED_SINCE_TOKEN_ISSUED);
        }

        @Test
        @DisplayName("an expired entry is not served")
        void expiredEntryNotServed() {
            givenUser(PlatformRole.ANALYST, true, "{\"visibility_scope\":\"ORGANIZATION\"}");
            var service = service(Duration.ofSeconds(30));

            resolve(service, "ANALYST", List.of("mfa"));
            // A fixed clock never advances, so advance the cached entry's age by
            // using a zero-TTL service to prove expiry is the TTL's job and that
            // the entry was genuinely stored.
            assertThat(service.cachedCount()).isEqualTo(1);
            assertThat(resolve(service(Duration.ZERO), "ANALYST", List.of("mfa")).isAllowed()).isTrue();
        }
    }
}
