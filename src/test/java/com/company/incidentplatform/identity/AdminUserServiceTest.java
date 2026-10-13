package com.company.incidentplatform.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.company.incidentplatform.TestFixtures;
import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.authorization.AuthorizationDeniedException;
import com.company.incidentplatform.authorization.Capability;
import com.company.incidentplatform.error.ConflictException;
import com.company.incidentplatform.error.LastAdministratorException;
import com.company.incidentplatform.error.ResourceNotFoundException;
import com.company.incidentplatform.security.CurrentUserStateService;
import com.company.incidentplatform.security.PlatformRole;
import com.company.incidentplatform.security.PlatformUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.Mockito;

/**
 * Section 9 {@code POST /api/v1/admin/users}, and the 6.2, 7.1, 7.2, 7.10 and 7.11 rules
 * it exists to enforce.
 *
 * <p>Unit tests against a mocked store rather than a Spring slice: every decision
 * under test is a branch in {@link AdminUserService#apply} -- authorize, refuse the
 * Keycloak-owned field, validate, lock, write, invalidate, audit -- and a slice test
 * would exercise the wiring while mocking out every one of them.
 *
 * <p>The store is a collaborator rather than inline code precisely so these tests can
 * assert what the service <em>did not</em> do, which is most of the interesting
 * behaviour: no write after a refusal, no cache invalidation for a change that never
 * happened, no audit entry for a rejected command.
 */
class AdminUserServiceTest {

    private static final UUID ADMIN_ID = UUID.fromString("00000000-0000-0000-0000-0000000000a1");
    private static final UUID TARGET_ID = UUID.fromString("00000000-0000-0000-0000-0000000000b2");
    private static final Instant NOW = Instant.parse("2026-09-30T09:00:00Z");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AdminUserStore store;
    private AuditService audit;
    private CurrentUserStateService userState;
    private AdminUserService service;

    private final PlatformUser admin = TestFixtures.admin(ADMIN_ID);

    /** Captures the 7.11 before/after pair and the pii_redacted claim from every recordChange. */
    private final List<String> beforeValues = new ArrayList<>();
    private final List<String> afterValues = new ArrayList<>();
    private final List<Boolean> redactionClaims = new ArrayList<>();

    @BeforeEach
    void setUp() {
        store = Mockito.mock(AdminUserStore.class);
        audit = Mockito.mock(AuditService.class);
        userState = Mockito.mock(CurrentUserStateService.class);
        service = new AdminUserService(store, audit, userState, Clock.fixed(NOW, ZoneOffset.UTC));

        // every() rather than anyString() for the reference arguments: outside a
        // servlet request RequestContext has no endpoint, method or remote address,
        // and anyString() does not match null -- so an anyString() stub would silently
        // never fire and every audit assertion below would pass vacuously.
        Mockito.doAnswer(invocation -> {
                    beforeValues.add(invocation.getArgument(10));
                    afterValues.add(invocation.getArgument(11));
                    redactionClaims.add(invocation.getArgument(12));
                    return null;
                })
                .when(audit)
                .recordChange(
                        any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(),
                        anyBoolean());
    }

    // -------------------------------------------------------------- fixture helpers

    /** The user's state is the same before and after -- a change that alters no visible field. */
    private void givenUser(String department, boolean active, int version) {
        givenUser(department, active, version, department, active, version);
    }

    /**
     * Stubs the two reads {@code updateUser} performs: the state it validates and
     * records as "before", then the state it re-reads to build the response and the
     * "after" audit value.
     */
    private void givenUser(
            String beforeDepartment,
            boolean beforeActive,
            int beforeVersion,
            String afterDepartment,
            boolean afterActive,
            int afterVersion) {
        givenUser(beforeDepartment, beforeActive, null, beforeVersion,
                afterDepartment, afterActive, null, afterVersion);
    }

    /** As above, with the disable reason each state carries. */
    private void givenUser(
            String beforeDepartment,
            boolean beforeActive,
            String beforeReason,
            int beforeVersion,
            String afterDepartment,
            boolean afterActive,
            String afterReason,
            int afterVersion) {
        when(store.findUser(TARGET_ID))
                .thenReturn(
                        Optional.of(userState(
                                beforeDepartment, beforeActive, beforeReason, beforeVersion)),
                        Optional.of(userState(
                                afterDepartment, afterActive, afterReason, afterVersion)));
    }

    private AdminUserStore.UserState userState(
            String department, boolean active, String disabledReason, int version) {
        return new AdminUserStore.UserState(
                TARGET_ID,
                "keycloak-subject-2",
                department,
                active,
                disabledReason,
                version,
                PlatformRole.ANALYST);
    }

    private AdminUserCommand updateCommand(String department, Boolean active, String disabledReason) {
        return updateCommand(department, active, disabledReason, null);
    }

    private AdminUserCommand updateCommand(
            String department, Boolean active, String disabledReason, String reason) {
        return new AdminUserCommand(
                AdminUserCommand.OP_UPDATE_USER, TARGET_ID, 3, department, active, disabledReason, null, null, reason);
    }

    private AdminUserCommand capabilityCommand(String operation, String role, String capability) {
        return capabilityCommand(operation, role, capability, null);
    }

    private AdminUserCommand capabilityCommand(
            String operation, String role, String capability, String reason) {
        return new AdminUserCommand(operation, null, null, null, null, null, role, capability, reason);
    }

    private void givenWriteSucceeds() {
        when(store.updateUser(any(), anyInt(), any(), anyBoolean(), any(), any())).thenReturn(true);
    }

    /**
     * The locked role row reports {@code held} for whichever capability is being
     * changed. Default is "not held", so a test that is not about the prior value does
     * not have to say so.
     */
    private void givenRoleFlag(PlatformRole role, boolean held) {
        when(store.lockCapabilityFlag(eq(role), anyString())).thenReturn(Optional.of(held));
    }

    private void givenRoleMissing(PlatformRole role) {
        when(store.lockCapabilityFlag(eq(role), anyString())).thenReturn(Optional.empty());
    }

    private String before() {
        assertThat(beforeValues).as("expected a 7.11 audit entry to have been written").hasSize(1);
        return beforeValues.get(0);
    }

    private String after() {
        assertThat(afterValues).as("expected a 7.11 audit entry to have been written").hasSize(1);
        return afterValues.get(0);
    }

    // ------------------------------------------------------------ 7.2 authorization

    @Nested
    @DisplayName("7.2 function level: can_manage_users")
    class Authorization {

        @Test
        @DisplayName("every operation refuses a caller without can_manage_users, and writes nothing")
        void deniedWithoutManageUsers() {
            PlatformUser analyst = TestFixtures.analyst(ADMIN_ID, "SECURITY");

            for (AdminUserCommand command : List.of(
                    updateCommand("OPERATIONS", null, null),
                    capabilityCommand(
                            AdminUserCommand.OP_GRANT_CAPABILITY, "SECURITY_ADMIN",
                            Capability.VIEW_REPORTER_IDENTITY.permissionKey()),
                    capabilityCommand(
                            AdminUserCommand.OP_REVOKE_CAPABILITY, "SECURITY_ADMIN",
                            Capability.VIEW_REPORTER_IDENTITY.permissionKey()))) {
                assertThatThrownBy(() -> service.apply(command, analyst))
                        .isInstanceOf(AuthorizationDeniedException.class)
                        .hasMessageContaining(Capability.MANAGE_USERS.permissionKey());
            }

            // A denial must not leave a half-applied change, a stale cache entry, or
            // an audit entry implying the change happened.
            verifyNoInteractions(store, userState, audit);
        }

        @Test
        @DisplayName("6.2.1: an unauthorised caller cannot probe which role and capability names exist")
        void denialPrecedesValidation() {
            assertThatThrownBy(() ->
                            service.apply(
                                    capabilityCommand(
                                            AdminUserCommand.OP_GRANT_CAPABILITY, "NOT_A_ROLE", "can_nonsense"),
                                    TestFixtures.analyst(ADMIN_ID, "SECURITY")))
                    .isInstanceOf(AuthorizationDeniedException.class);

            // Authorisation runs before the body is validated, so an unauthorised
            // caller gets 403 whatever the body says. Validating first would make the
            // difference between "unknown role" and "unknown capability" a way to
            // enumerate the configuration.
            verifyNoInteractions(store);
        }

        @Test
        @DisplayName("an admin holding can_manage_users proceeds")
        void adminProceeds() {
            givenUser("SECURITY", true, 3, "OPERATIONS", true, 4);
            givenWriteSucceeds();

            assertThat(service.apply(updateCommand("OPERATIONS", null, null), admin).department())
                    .isEqualTo("OPERATIONS");
        }
    }

    // ----------------------------------------------------- 6.2 coarse role refusal

    @Nested
    @DisplayName("6.2: the coarse role belongs to Keycloak")
    class CoarseRoleRefusal {

        @Test
        @DisplayName("a role in an UPDATE_USER body is refused with an explanation, not ignored")
        void roleChangeRefused() {
            AdminUserCommand command = new AdminUserCommand(
                    AdminUserCommand.OP_UPDATE_USER, TARGET_ID, 3, null, null, null, "SECURITY_ADMIN", null, null);

            assertThatThrownBy(() -> service.apply(command, admin))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Keycloak")
                    .hasMessageContaining("source of truth");

            // Refused rather than applied. The dangerous version of this endpoint is
            // one that writes role_id and lets the next Keycloak sync overwrite it.
            verify(store, never()).updateUser(any(), anyInt(), any(), anyBoolean(), any(), any());
            verifyNoInteractions(userState, audit);
        }

        @Test
        @DisplayName("the refusal is not defeatable by case or whitespace")
        void roleChangeRefusedRegardlessOfForm() {
            AdminUserCommand command = new AdminUserCommand(
                    AdminUserCommand.OP_UPDATE_USER, TARGET_ID, 3, null, null, null, "  admin  ", null, null);

            assertThatThrownBy(() -> service.apply(command, admin))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Keycloak");
        }

        @Test
        @DisplayName("a blank role field is treated as absent rather than as a refusal")
        void blankRoleTreatedAsAbsent() {
            givenUser("SECURITY", true, 3, "OPERATIONS", true, 4);
            givenWriteSucceeds();

            AdminUserCommand command = new AdminUserCommand(
                    AdminUserCommand.OP_UPDATE_USER, TARGET_ID, 3, "OPERATIONS", null, null, "  ", null, null);

            assertThat(service.apply(command, admin).department()).isEqualTo("OPERATIONS");
        }
    }

    // ------------------------------------------------------- 7.10 and validation

    @Nested
    @DisplayName("7.10 concurrency and input validation")
    class ValidationAndConcurrency {

        @Test
        @DisplayName("expectedVersion is mandatory: an unversioned security change is refused")
        void expectedVersionRequired() {
            AdminUserCommand command = new AdminUserCommand(
                    AdminUserCommand.OP_UPDATE_USER, TARGET_ID, null, "OPERATIONS", null, null, null, null, null);

            assertThatThrownBy(() -> service.apply(command, admin))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("expectedVersion");

            verify(store, never()).updateUser(any(), anyInt(), any(), anyBoolean(), any(), any());
        }

        @Test
        @DisplayName("a stale expectedVersion is a conflict, not a silent overwrite")
        void staleVersionConflicts() {
            givenUser("SECURITY", true, 3);
            // The conditional UPDATE matched no row: another admin already moved it on.
            when(store.updateUser(any(), anyInt(), any(), anyBoolean(), any(), any())).thenReturn(false);

            assertThatThrownBy(() -> service.apply(updateCommand("OPERATIONS", null, null), admin))
                    .isInstanceOf(ConflictException.class);

            // A conflict must not audit a change that did not happen, nor invalidate a
            // cache for a row that did not change.
            verifyNoInteractions(audit, userState);
        }

        @Test
        @DisplayName("disabling requires a reason (7.1), checked before the write")
        void disableRequiresReason() {
            givenUser("SECURITY", true, 3);

            assertThatThrownBy(() -> service.apply(updateCommand(null, false, null), admin))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("disabledReason");

            assertThatThrownBy(() -> service.apply(updateCommand(null, false, "   "), admin))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("disabledReason");

            verify(store, never()).updateUser(any(), anyInt(), any(), anyBoolean(), any(), any());
        }

        @Test
        @DisplayName("a command that changes nothing is refused")
        void nothingToChangeRefused() {
            givenUser("SECURITY", true, 3);

            assertThatThrownBy(() -> service.apply(updateCommand(null, null, null), admin))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Nothing to change");
        }

        @Test
        @DisplayName("an unknown user is a 404")
        void unknownUserIsNotFound() {
            when(store.findUser(TARGET_ID)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.apply(updateCommand("OPERATIONS", null, null), admin))
                    .isInstanceOf(ResourceNotFoundException.class);

            verify(store, never()).updateUser(any(), anyInt(), any(), anyBoolean(), any(), any());
        }

        @Test
        @DisplayName("an unknown or missing operation is a 400")
        void unknownOperationRefused() {
            assertThatThrownBy(() -> service.apply(
                            new AdminUserCommand(
                                    "DELETE_EVERYTHING", TARGET_ID, 3, null, null, null, null, null, null),
                            admin))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Unknown operation");

            assertThatThrownBy(() -> service.apply(
                            new AdminUserCommand("  ", null, null, null, null, null, null, null, null), admin))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("operation is required");

            verifyNoInteractions(store);
        }

        @Test
        @DisplayName("an operation is accepted regardless of case")
        void operationIsCaseInsensitive() {
            givenUser("SECURITY", true, 3, "OPERATIONS", true, 4);
            givenWriteSucceeds();

            AdminUserCommand command = new AdminUserCommand(
                    "  update_user  ", TARGET_ID, 3, "OPERATIONS", null, null, null, null, null);

            assertThat(service.apply(command, admin).operation()).isEqualTo(AdminUserCommand.OP_UPDATE_USER);
        }
    }

    // -------------------------------------------------------- 7.1 and 7.9 lifecycle

    @Nested
    @DisplayName("7.1 and 7.9: account lifecycle")
    class Lifecycle {

        @Test
        @DisplayName("disabling writes disabled_at and the reason together, and invalidates immediately")
        void disableWritesConsistentLifecycleColumns() {
            givenUser("SECURITY", true, 3, "SECURITY", false, 4);
            when(store.userHoldsManageUsers(TARGET_ID)).thenReturn(false);
            givenWriteSucceeds();

            AdminUserOutcome outcome = service.apply(updateCommand(null, false, "Offboarded 2026-09-30"), admin);

            // active, disabled_at and disabled_reason are written as one statement.
            // ck_app_user_active_disabled_consistent and ck_app_user_disabled_reason
            // reject a row where they disagree, and a partial update would surface as
            // a constraint violation that says nothing about what the admin did.
            verify(store).updateUser(
                    eq(TARGET_ID), eq(3), eq(null), eq(false),
                    eq("Offboarded 2026-09-30"), eq(NOW));

            assertThat(outcome.active()).isFalse();
            assertThat(outcome.version()).isEqualTo(4);

            // 7.9: effective on the next request, not at token expiry.
            verify(userState).invalidate(TARGET_ID);
        }

        @Test
        @DisplayName("re-enabling clears the disable columns")
        void reEnableClearsDisableColumns() {
            givenUser("SECURITY", false, 4, "SECURITY", true, 5);
            givenWriteSucceeds();

            // Carries expectedVersion 4, the version the caller last read.
            AdminUserCommand command = new AdminUserCommand(
                    AdminUserCommand.OP_UPDATE_USER, TARGET_ID, 4, null, true, "rehired", null, null, null);

            assertThat(service.apply(command, admin).active()).isTrue();

            // The disable columns are cleared rather than left stale: ck_app_user_
            // active_disabled_consistent requires disabled_at to be null, and a
            // reason left behind would misrepresent an active account.
            verify(store).updateUser(eq(TARGET_ID), eq(4), eq(null), eq(true), eq(null), eq(NOW));
        }

        @Test
        @DisplayName("a department change leaves active and version to the store")
        void departmentOnlyChange() {
            givenUser("SECURITY", true, 3, "OPERATIONS", true, 4);
            givenWriteSucceeds();

            AdminUserOutcome outcome = service.apply(updateCommand("OPERATIONS", null, null), admin);

            verify(store).updateUser(eq(TARGET_ID), eq(3), eq("OPERATIONS"), eq(true), eq(null), eq(NOW));
            assertThat(outcome.department()).isEqualTo("OPERATIONS");
            assertThat(outcome.coarseRole()).isEqualTo(PlatformRole.ANALYST);
        }

        @Test
        @DisplayName("editing an already-disabled account keeps its existing reason")
        void departmentChangeOnDisabledAccountKeepsReason() {
            // The account has been disabled since May. Changing its department must not
            // require a fresh disable reason -- and must not blank the existing one, or
            // ck_app_user_disabled_reason would reject the row. A requirement to
            // re-supply the reason would make such an account unmaintainable without
            // first re-enabling it.
            givenUser("SECURITY", false, "left in May", 4, "OPERATIONS", false, "left in May", 5);
            givenWriteSucceeds();

            AdminUserCommand command = new AdminUserCommand(
                    AdminUserCommand.OP_UPDATE_USER, TARGET_ID, 4, "OPERATIONS", null, null, null, null, null);

            assertThat(service.apply(command, admin).department()).isEqualTo("OPERATIONS");

            verify(store).updateUser(
                    eq(TARGET_ID), eq(4), eq("OPERATIONS"), eq(false), eq("left in May"), eq(NOW));
        }

        @Test
        @DisplayName("a reason on an already-disabled account can be corrected by restating active=false")
        void disabledReasonCanBeCorrected() {
            givenUser("SECURITY", false, "typo", 4, "SECURITY", false, "left in May", 5);
            givenWriteSucceeds();

            AdminUserCommand command = new AdminUserCommand(
                    AdminUserCommand.OP_UPDATE_USER, TARGET_ID, 4, null, false, "left in May", null, null, null);

            assertThat(service.apply(command, admin).active()).isFalse();

            verify(store).updateUser(eq(TARGET_ID), eq(4), eq(null), eq(false), eq("left in May"), eq(NOW));
            // Restating active=false is not a transition into disabled, so it is not a
            // lockout risk and must not be refused by the last-administrator guard.
            verify(store, never()).countActiveUsersWithManageUsersExcluding(any());
        }

        @Test
        @DisplayName("the last user who can manage users cannot be disabled")
        void lastAdministratorCannotBeDisabled() {
            givenUser("SECURITY", true, 3);
            when(store.userHoldsManageUsers(TARGET_ID)).thenReturn(true);
            when(store.countActiveUsersWithManageUsersExcluding(TARGET_ID)).thenReturn(0);

            assertThatThrownBy(() -> service.apply(updateCommand(null, false, "departing"), admin))
                    .isInstanceOf(LastAdministratorException.class)
                    .hasMessageContaining("no active user able to manage users")
                    .hasMessageContaining("Grant can_manage_users to another administrator first");

            // This is the state that cannot be undone: with no Keycloak write-through
            // and no other route to a capability grant, the deployment would be
            // unrecoverable without a direct database edit.
            verify(store, never()).updateUser(any(), anyInt(), any(), anyBoolean(), any(), any());
            verifyNoInteractions(audit, userState);
        }

        @Test
        @DisplayName("the refusal names the action without echoing the caller's identifier")
        void refusalDoesNotEchoSubmittedValues() {
            givenUser("SECURITY", true, 3);
            when(store.userHoldsManageUsers(TARGET_ID)).thenReturn(true);
            when(store.countActiveUsersWithManageUsersExcluding(TARGET_ID)).thenReturn(0);

            assertThatThrownBy(() -> service.apply(updateCommand(null, false, "departing"), admin))
                    .as("The message is composed in the application from a fixed vocabulary and "
                            + "reflected to the client, so it must not carry the submitted user id -- "
                            + "7.5's rule about not echoing submitted values applies to 409 bodies "
                            + "exactly as it does to 400s")
                    .satisfies(thrown -> assertThat(thrown.getMessage())
                            .doesNotContain(TARGET_ID.toString())
                            .contains("disable this account"));
        }

        @Test
        @DisplayName("one of two administrators can be disabled")
        void oneOfTwoAdministratorsCanBeDisabled() {
            givenUser("SECURITY", true, 3, "SECURITY", false, 4);
            when(store.userHoldsManageUsers(TARGET_ID)).thenReturn(true);
            when(store.countActiveUsersWithManageUsersExcluding(TARGET_ID)).thenReturn(1);
            givenWriteSucceeds();

            assertThat(service.apply(updateCommand(null, false, "departing"), admin).active()).isFalse();
        }

        @Test
        @DisplayName("disabling a user who cannot manage users needs no administrator check")
        void nonAdministratorCanBeDisabled() {
            givenUser("SECURITY", true, 3, "SECURITY", false, 4);
            when(store.userHoldsManageUsers(TARGET_ID)).thenReturn(false);
            givenWriteSucceeds();

            assertThat(service.apply(updateCommand(null, false, "left the team"), admin).active()).isFalse();

            verify(store, never()).countActiveUsersWithManageUsersExcluding(any());
        }
    }

    // ------------------------------------------------ 6.2.3 and FR-1.6 capability

    @Nested
    @DisplayName("6.2.3 and FR-1.6: role capability grants")
    class CapabilityChanges {

        @Test
        @DisplayName("granting can_view_reporter_identity is the FR-1.6 explicit grant")
        void grantExplicitIdentityCapability() {
            givenRoleFlag(PlatformRole.SECURITY_ADMIN, false);

            AdminUserOutcome outcome = service.apply(
                    capabilityCommand(
                            AdminUserCommand.OP_GRANT_CAPABILITY, "SECURITY_ADMIN",
                            Capability.VIEW_REPORTER_IDENTITY.permissionKey()),
                    admin);

            verify(store).grantCapability(PlatformRole.SECURITY_ADMIN, Capability.VIEW_REPORTER_IDENTITY.permissionKey());
            verify(store, never()).revokeCapability(any(), anyString());

            assertThat(outcome.capability()).isEqualTo(Capability.VIEW_REPORTER_IDENTITY.permissionKey());
            assertThat(outcome.capabilityGranted()).isTrue();
        }

        @Test
        @DisplayName("a capability change invalidates every user, not one")
        void capabilityChangeInvalidatesAllUsers() {
            givenRoleFlag(PlatformRole.SECURITY_ADMIN, false);

            service.apply(capabilityCommand(AdminUserCommand.OP_GRANT_CAPABILITY, "SECURITY_ADMIN", "can_manage_retention"), admin);

            // The cache is keyed by user and the affected set is the role's
            // membership, so a targeted invalidate would need a membership query
            // anyway -- and a stale capability is a security defect, not a cache miss.
            verify(userState).invalidateAll();
            verify(userState, never()).invalidate(any());
        }

        @Test
        @DisplayName("revoking a capability removes the grant")
        void revokeCapability() {
            givenRoleFlag(PlatformRole.ANALYST, false);

            AdminUserOutcome outcome = service.apply(
                    capabilityCommand(AdminUserCommand.OP_REVOKE_CAPABILITY, "ANALYST", "can_manage_retention"),
                    admin);

            verify(store).revokeCapability(PlatformRole.ANALYST, "can_manage_retention");
            verify(store, never()).grantCapability(any(), anyString());
            assertThat(outcome.capabilityGranted()).isFalse();
        }

        @Test
        @DisplayName("the role row is locked before its permissions are read")
        void roleIsLockedBeforeRead() {
            givenRoleFlag(PlatformRole.SECURITY_ADMIN, false);

            service.apply(capabilityCommand(AdminUserCommand.OP_GRANT_CAPABILITY, "SECURITY_ADMIN", "can_manage_retention"), admin);

            // platform_role has no version column, so SELECT ... FOR UPDATE is what
            // serialises concurrent grants. A blind read-modify-write of the jsonb
            // would let two admins' grants to different capabilities lose one another.
            InOrder order = Mockito.inOrder(store);
            order.verify(store).lockCapabilityFlag(eq(PlatformRole.SECURITY_ADMIN), anyString());
            order.verify(store).grantCapability(PlatformRole.SECURITY_ADMIN, "can_manage_retention");
        }

        @Test
        @DisplayName("an unrecognised capability is refused, so a flag nothing reads cannot be created")
        void unknownCapabilityRefused() {
            assertThatThrownBy(() -> service.apply(
                            capabilityCommand(AdminUserCommand.OP_GRANT_CAPABILITY, "SECURITY_ADMIN", "can_nonsense"), admin))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("can_nonsense");

            // A key no code path checks is indistinguishable from a grant that did
            // not happen, and would look like success.
            verify(store, never()).grantCapability(any(), anyString());
            verifyNoInteractions(userState, audit);
        }

        @Test
        @DisplayName("an unrecognised role is refused, and no role is created")
        void unknownRoleRefused() {
            assertThatThrownBy(() -> service.apply(
                            capabilityCommand(AdminUserCommand.OP_GRANT_CAPABILITY, "SUPERUSER", "can_export"), admin))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("SUPERUSER");

            verifyNoInteractions(store, userState, audit);
        }

        @Test
        @DisplayName("role and capability are required for a capability change")
        void capabilityChangeRequiresRoleAndCapability() {
            assertThatThrownBy(() -> service.apply(
                            capabilityCommand(AdminUserCommand.OP_GRANT_CAPABILITY, null, "can_export"), admin))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("role is required");

            assertThatThrownBy(() -> service.apply(
                            capabilityCommand(AdminUserCommand.OP_GRANT_CAPABILITY, "SECURITY_ADMIN", null), admin))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("capability is required");
        }

        @Test
        @DisplayName("a capability key is matched exactly, so a near miss is not silently granted")
        void capabilityKeyMustMatchExactly() {
            assertThatThrownBy(() -> service.apply(
                            capabilityCommand(AdminUserCommand.OP_GRANT_CAPABILITY, "SECURITY_ADMIN", "can_manage_user"), admin))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("can_manage_user");

            verify(store, never()).grantCapability(any(), anyString());
        }

        @Test
        @DisplayName("can_manage_users cannot be revoked from the only role that holds it")
        void lastManageUsersRoleCannotLoseTheCapability() {
            when(store.roleHoldsManageUsers(PlatformRole.SECURITY_ADMIN)).thenReturn(true);
            when(store.countActiveUsersWithManageUsersExcludingRole(PlatformRole.SECURITY_ADMIN)).thenReturn(0);

            assertThatThrownBy(() -> service.apply(
                            capabilityCommand(
                                    AdminUserCommand.OP_REVOKE_CAPABILITY, "SECURITY_ADMIN",
                                    Capability.MANAGE_USERS.permissionKey()),
                            admin))
                    .isInstanceOf(LastAdministratorException.class)
                    .hasMessageContaining("no active user able to manage users")
                    .hasMessageContaining("revoke can_manage_users from SECURITY_ADMIN");

            verify(store, never()).revokeCapability(any(), anyString());
            verifyNoInteractions(userState, audit);
        }

        @Test
        @DisplayName("can_manage_users can be revoked while another role still holds it")
        void manageUsersRevocableWhenAnotherRoleHoldsIt() {
            when(store.roleHoldsManageUsers(PlatformRole.SECURITY_ADMIN)).thenReturn(true);
            when(store.countActiveUsersWithManageUsersExcludingRole(PlatformRole.SECURITY_ADMIN)).thenReturn(3);
            givenRoleFlag(PlatformRole.SECURITY_ADMIN, false);

            AdminUserOutcome outcome = service.apply(
                    capabilityCommand(
                            AdminUserCommand.OP_REVOKE_CAPABILITY, "SECURITY_ADMIN", Capability.MANAGE_USERS.permissionKey()),
                    admin);

            verify(store).revokeCapability(PlatformRole.SECURITY_ADMIN, Capability.MANAGE_USERS.permissionKey());
            assertThat(outcome.capabilityGranted()).isFalse();
        }

        @Test
        @DisplayName("a role with no row is a 404 and nothing is written")
        void missingRoleIsNotFound() {
            givenRoleMissing(PlatformRole.SECURITY_LEAD);

            assertThatThrownBy(() -> service.apply(
                            capabilityCommand(
                                    AdminUserCommand.OP_GRANT_CAPABILITY, "SECURITY_LEAD", "can_export"),
                            admin))
                    .isInstanceOf(ResourceNotFoundException.class);

            verify(store, never()).grantCapability(any(), anyString());
        }
    }

    // ------------------------------------------------ 7.10 cross-row serialisation

    @Nested
    @DisplayName("7.10: the last-administrator guard holds under concurrency")
    class ConcurrencyGuard {

        @Test
        @DisplayName("a disable takes the cross-row lock before reading the state it will judge")
        void disableLocksBeforeReading() {
            givenUser("SECURITY", true, 3, "SECURITY", false, 4);
            when(store.userHoldsManageUsers(TARGET_ID)).thenReturn(false);
            givenWriteSucceeds();

            service.apply(updateCommand(null, false, "departing"), admin);

            // The guard counts rows, so it must be evaluated under a lock that also
            // covers the write -- and before the state it reasons about is read.
            InOrder order = Mockito.inOrder(store);
            order.verify(store).lockAuthorizationChanges();
            order.verify(store).findUser(TARGET_ID);
            order.verify(store).updateUser(any(), anyInt(), any(), anyBoolean(), any(), any());
        }

        @Test
        @DisplayName("a capability revoke takes the lock before the count, and the row lock after")
        void revokeLocksBeforeTheInvariantCheck() {
            when(store.roleHoldsManageUsers(PlatformRole.SECURITY_ADMIN)).thenReturn(true);
            when(store.countActiveUsersWithManageUsersExcludingRole(PlatformRole.SECURITY_ADMIN)).thenReturn(2);
            givenRoleFlag(PlatformRole.SECURITY_ADMIN, false);

            service.apply(capabilityCommand(
                    AdminUserCommand.OP_REVOKE_CAPABILITY, "SECURITY_ADMIN", Capability.MANAGE_USERS.permissionKey()),
                    admin);

            InOrder order = Mockito.inOrder(store);
            order.verify(store).lockAuthorizationChanges();
            order.verify(store).countActiveUsersWithManageUsersExcludingRole(PlatformRole.SECURITY_ADMIN);
            order.verify(store).lockCapabilityFlag(eq(PlatformRole.SECURITY_ADMIN), anyString());
            order.verify(store).revokeCapability(PlatformRole.SECURITY_ADMIN, Capability.MANAGE_USERS.permissionKey());
        }

        @Test
        @DisplayName("a capability grant takes the lock too, since a grant is what a racing revoke must not miss")
        void grantLocksAsWell() {
            givenRoleFlag(PlatformRole.SECURITY_ADMIN, false);

            service.apply(capabilityCommand(AdminUserCommand.OP_GRANT_CAPABILITY, "SECURITY_ADMIN", "can_export"), admin);

            InOrder order = Mockito.inOrder(store);
            order.verify(store).lockAuthorizationChanges();
            order.verify(store).grantCapability(PlatformRole.SECURITY_ADMIN, "can_export");
        }

        @Test
        @DisplayName("an unauthorised caller is refused before any lock is taken")
        void authorizationPrecedesTheLock() {
            // Taking a database-wide advisory lock for a request that is going to be
            // refused would let an unauthenticated-for-capability caller serialise
            // legitimate admin work.
            assertThatThrownBy(() -> service.apply(
                            updateCommand("OPERATIONS", null, null), TestFixtures.analyst(ADMIN_ID, "SECURITY")))
                    .isInstanceOf(AuthorizationDeniedException.class);

            verify(store, never()).lockAuthorizationChanges();
        }

        @Test
        @DisplayName("a command rejected by validation takes no lock")
        void validationPrecedesTheLock() {
            assertThatThrownBy(() -> service.apply(
                            new AdminUserCommand(
                                    AdminUserCommand.OP_UPDATE_USER, TARGET_ID, null, "OPERATIONS", null, null,
                                    null, null, null),
                            admin))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("expectedVersion");

            verify(store, never()).lockAuthorizationChanges();
        }
    }

    // ------------------------------------------------------------------ 7.11 audit

    @Nested
    @DisplayName("7.11 audit trail")
    class AuditTrail {

        @Test
        @DisplayName("a user change records the department, active flag and version before and after")
        void userChangeIsAudited() throws Exception {
            givenUser("SECURITY", true, 3, "OPERATIONS", false, 4);
            when(store.userHoldsManageUsers(TARGET_ID)).thenReturn(false);
            givenWriteSucceeds();

            service.apply(updateCommand("OPERATIONS", false, "offboarded"), admin);

            var beforeNode = MAPPER.readTree(before());
            var afterNode = MAPPER.readTree(after());

            // 7.11 before/after. Without the department a reviewer could see only
            // that "a user changed", not what changed.
            assertThat(beforeNode.get("department").asText()).isEqualTo("SECURITY");
            assertThat(beforeNode.get("active").asBoolean()).isTrue();
            assertThat(beforeNode.get("version").asInt()).isEqualTo(3);

            assertThat(afterNode.get("department").asText()).isEqualTo("OPERATIONS");
            assertThat(afterNode.get("active").asBoolean()).isFalse();
            assertThat(afterNode.get("version").asInt()).isEqualTo(4);
            assertThat(afterNode.get("disabled_reason").asText()).isEqualTo("offboarded");
            assertThat(afterNode.get("coarse_role").asText()).isEqualTo(PlatformRole.ANALYST.name());
        }

        @Test
        @DisplayName("a user change claims pii_redacted, and the payload holds no personal data")
        void userChangeIsPiiRedacted() {
            givenUser("SECURITY", true, 3, "OPERATIONS", true, 4);
            givenWriteSucceeds();

            service.apply(updateCommand("OPERATIONS", null, null), admin);

            // Claiming the flag is only honest because the redaction is real: 7.4
            // treats email and full_name as personal data, and neither is ever read
            // into the entry. A flag set without the redaction would be worse than
            // no flag at all.
            assertThat(redactionClaims).containsExactly(true);
            assertThat(before() + after()).doesNotContain("email", "full_name", "@", "keycloak-subject-2");
        }

        @Test
        @DisplayName("a capability change records only the affected flag, not the whole document")
        void capabilityChangeRecordsSingleFlag() throws Exception {
            givenRoleFlag(PlatformRole.SECURITY_ADMIN, false);

            service.apply(capabilityCommand(
                    AdminUserCommand.OP_GRANT_CAPABILITY, "SECURITY_ADMIN", "can_manage_retention", "approved by CAB"), admin);

            // The audit pair is about the one flag that changed. Embedding two copies
            // of the whole permissions document would bury it and duplicate unrelated
            // scoping detail.
            // Typed as an ObjectNode because AssertJ resolves assertThat(JsonNode) to
            // its Iterable overload -- JsonNode implements Iterable -- which would
            // assert over child nodes instead of over fields.
            ObjectNode beforeNode = (ObjectNode) MAPPER.readTree(before());
            assertThat(beforeNode.get("role").asText()).isEqualTo("SECURITY_ADMIN");
            assertThat(beforeNode.get("can_manage_retention").asBoolean()).isFalse();
            assertThat(beforeNode.size()).isEqualTo(2);

            var afterNode = MAPPER.readTree(after());
            assertThat(afterNode.get("role").asText()).isEqualTo("SECURITY_ADMIN");
            assertThat(afterNode.get("capability").asText()).isEqualTo("can_manage_retention");
            assertThat(afterNode.get("value").asBoolean()).isTrue();
            assertThat(afterNode.get("reason").asText()).isEqualTo("approved by CAB");
            assertThat(after()).doesNotContain("visibility_scope");
        }

        @Test
        @DisplayName("a capability change is not itself pii, and does not claim to be")
        void capabilityChangeIsNotPii() {
            givenRoleFlag(PlatformRole.SECURITY_ADMIN, false);

            service.apply(capabilityCommand(AdminUserCommand.OP_GRANT_CAPABILITY, "SECURITY_ADMIN", "can_manage_retention"), admin);

            // The flag distinguishes the two cases so a compliance report can filter
            // for entries where personal data was deliberately withheld.
            assertThat(redactionClaims).containsExactly(false);
        }

        @Test
        @DisplayName("a grant of a capability already held is audited honestly, not as a new grant")
        void idempotentGrantIsAuditedHonestly() throws Exception {
            givenRoleFlag(PlatformRole.SECURITY_ADMIN, true);

            service.apply(capabilityCommand(AdminUserCommand.OP_GRANT_CAPABILITY, "SECURITY_ADMIN", "can_manage_retention"), admin);

            // The prior value comes from the row lock, so the entry shows the state
            // that was actually overwritten rather than implying a fresh grant.
            assertThat(MAPPER.readTree(before()).get("can_manage_retention").asBoolean()).isTrue();
        }

        @Test
        @DisplayName("a capability the role does not hold is audited with a false before value")
        void notHeldIsAuditedAsFalse() throws Exception {
            givenRoleFlag(PlatformRole.SECURITY_ADMIN, false);

            service.apply(capabilityCommand(AdminUserCommand.OP_GRANT_CAPABILITY, "SECURITY_ADMIN", "can_manage_retention"), admin);

            // Matches how RolePermissions treats an absent flag, so the audit trail
            // and the authorization decision cannot disagree. The store's
            // coalesce(..., 'false') is what makes an absent key report false rather
            // than NULL.
            assertThat(MAPPER.readTree(before()).get("can_manage_retention").asBoolean()).isFalse();
        }

        @Test
        @DisplayName("free text cannot inject a key into the audit document")
        void freeTextCannotInjectJson() throws Exception {
            // disabled_reason is typed by a human and lands in a jsonb column, so an
            // unescaped quote must not be able to close the string and invent a
            // sibling key that a reader would believe.
            String hostileReason = "left\", \"compromised\"},\"";
            givenUser("SECURITY", true, 3, "SECURITY", false, 4);
            when(store.userHoldsManageUsers(TARGET_ID)).thenReturn(false);
            givenWriteSucceeds();

            service.apply(updateCommand(null, false, hostileReason, hostileReason), admin);

            var node = MAPPER.readTree(after());
            assertThat(node.get("disabled_reason").asText()).isEqualTo(hostileReason);
            assertThat(node.get("reason").asText()).isEqualTo(hostileReason);
            // Exactly the keys we meant, and no invented sibling.
            assertThat(node.fieldNames()).toIterable()
                    .containsExactlyInAnyOrder(
                            "department", "active", "version", "coarse_role", "disabled_reason", "reason");
        }

        @Test
        @DisplayName("action names are distinct, so a report can filter permission changes alone")
        void actionNamesAreDistinct() {
            // A collision would mean a search for capability grants also returns user
            // edits, which is the difference between a usable audit report and noise.
            assertThat(List.of(
                            AdminUserService.ACTION_USER_UPDATE,
                            AdminUserService.ACTION_CAPABILITY_GRANT,
                            AdminUserService.ACTION_CAPABILITY_REVOKE))
                    .doesNotHaveDuplicates()
                    .containsExactly(
                            "admin.user.update", "admin.role.capability_grant", "admin.role.capability_revoke");
        }
    }
}
