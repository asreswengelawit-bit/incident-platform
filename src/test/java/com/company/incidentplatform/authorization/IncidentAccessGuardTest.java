package com.company.incidentplatform.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import com.company.incidentplatform.TestFixtures;
import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.DeniedReason;
import com.company.incidentplatform.security.PlatformUser;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;

/**
 * Section 7.2 function-level authorization and the read-only rule, the Section
 * 10 "BFLA" row of the test matrix.
 *
 * <p>BFLA -- broken function-level authorization -- is a valid user calling an
 * endpoint their role has no business calling. Unlike BOLA it is not about which
 * object is named, so it cannot be caught by an object-level check: an Admin
 * holds every capability and would pass any object test, which is exactly why
 * they must not be able to reach an Analyst-only endpoint.
 */
class IncidentAccessGuardTest {

    private static final UUID ANALYST = UUID.fromString("00000000-0000-0000-0000-0000000000b2");
    private static final UUID ADMIN = UUID.fromString("00000000-0000-0000-0000-0000000000f6");
    private static final UUID AUDITOR = UUID.fromString("00000000-0000-0000-0000-0000000000a7");
    private static final UUID ALICE = UUID.fromString("00000000-0000-0000-0000-0000000000a1");
    private static final UUID INCIDENT = UUID.fromString("00000000-0000-0000-0000-0000000000c1");
    private static final String ENGINEERING = "ENGINEERING";

    private IncidentSnapshotRepository repository;
    private IncidentAccessGuard guard;

    private void setUp(IncidentSnapshot snapshot) {
        repository = Mockito.mock(IncidentSnapshotRepository.class);
        when(repository.findById(INCIDENT)).thenReturn(Optional.ofNullable(snapshot));
        guard = new IncidentAccessGuard(
                repository, new IncidentObjectAuthorizer(GroupVisibilityPolicy.EXPLICIT_COLLABORATION_ONLY));
    }

    @Nested
    @DisplayName("7.2 function level: capability required for a write")
    class FunctionLevel {

        @Test
        @DisplayName("a role lacking the capability is denied before the incident is even loaded")
        void missingCapabilityDenied() {
            setUp(TestFixtures.incident(INCIDENT, ALICE, ENGINEERING, ENGINEERING, ANALYST));
            PlatformUser analyst = TestFixtures.analyst(ANALYST, ENGINEERING);

            assertThatThrownBy(() -> guard.requireWrite(analyst, INCIDENT, Capability.REASSIGN))
                    .isInstanceOf(AuthorizationDeniedException.class)
                    .satisfies(thrown -> {
                        var denied = (AuthorizationDeniedException) thrown;
                        assertThat(denied.decision().checkType())
                                .isEqualTo(AuthorizationCheckType.FUNCTION_LEVEL);
                        assertThat(denied.decision().deniedReason())
                                .isEqualTo(DeniedReason.INSUFFICIENT_ROLE);
                        assertThat(denied.decision().rule()).isEqualTo("capability.can_reassign");
                    });
        }

        @Test
        @DisplayName("a capability is never sufficient without object access")
        void capabilityWithoutObjectAccessDenied() {
            // The lead holds REASSIGN but does not lead ENGINEERING. Proving the
            // object check still runs is the point.
            setUp(TestFixtures.incident(INCIDENT, ALICE, ENGINEERING, ENGINEERING, null));
            PlatformUser lead = TestFixtures.lead(
                    UUID.fromString("00000000-0000-0000-0000-0000000000e5"), "SECURITY", "FINANCE");

            assertThatThrownBy(() -> guard.requireWrite(lead, INCIDENT, Capability.REASSIGN))
                    .isInstanceOf(AuthorizationDeniedException.class)
                    .satisfies(thrown -> assertThat(((AuthorizationDeniedException) thrown).decision().checkType())
                            .isEqualTo(AuthorizationCheckType.OBJECT_LEVEL));
        }

        @ParameterizedTest
        @EnumSource(
                value = Capability.class,
                names = {"REASSIGN", "ESCALATE", "APPROVE_CLOSURE", "REOPEN_CLOSED", "OVERRIDE_SEVERITY"})
        @DisplayName("every mutation capability is refused to an Analyst who lacks it")
        void analystCannotInvokeMutationEndpoints(Capability capability) {
            setUp(TestFixtures.incident(INCIDENT, ALICE, ENGINEERING, ENGINEERING, ANALYST));
            PlatformUser analyst = TestFixtures.analyst(ANALYST, ENGINEERING);

            assertThat(capability.isHeldBy(analyst.permissions()))
                    .as("%s must not be held by an Analyst", capability)
                    .isFalse();
            assertThatThrownBy(() -> guard.requireWrite(analyst, INCIDENT, capability))
                    .isInstanceOf(AuthorizationDeniedException.class);
        }
    }

    @Nested
    @DisplayName("7.2.1 Auditor is read-only")
    class ReadOnly {

        @ParameterizedTest
        @EnumSource(
                value = Capability.class,
                names = {"CLASSIFY", "REASSIGN", "ESCALATE", "APPROVE_CLOSURE", "REOPEN_CLOSED"})
        @DisplayName("no write capability is honoured for a read-only role")
        void auditorCannotWrite(Capability capability) {
            setUp(TestFixtures.incident(INCIDENT, ALICE, ENGINEERING, ENGINEERING, null));
            PlatformUser auditor = TestFixtures.auditor(AUDITOR);

            assertThatThrownBy(() -> guard.requireWrite(auditor, INCIDENT, capability))
                    .isInstanceOf(AuthorizationDeniedException.class)
                    .satisfies(thrown -> assertThat(((AuthorizationDeniedException) thrown).decision().rule())
                            .isEqualTo("capability.write_blocked_read_only"));
        }

        @Test
        @DisplayName("read-only is a blanket write refusal, not a per-capability one")
        void blanketRefusal() {
            // Deliberately not expressed as "the Auditor lacks capability X". A
            // blanket rule means granting an Auditor a capability later still
            // cannot make it writable, which a per-capability rule would.
            PlatformUser auditor = TestFixtures.auditor(AUDITOR);

            assertThat(auditor.permissions().isReadOnly()).isTrue();
        }

        @Test
        @DisplayName("an Auditor can still read")
        void auditorCanRead() {
            setUp(TestFixtures.incident(INCIDENT, ALICE, ENGINEERING, ENGINEERING, null));
            PlatformUser auditor = TestFixtures.auditor(AUDITOR);

            assertThat(guard.requireRead(auditor, INCIDENT)).isNotNull();
        }

        @Test
        @DisplayName("an Admin is not read-only")
        void adminIsNotReadOnly() {
            setUp(TestFixtures.incident(INCIDENT, ALICE, ENGINEERING, ENGINEERING, null));
            PlatformUser admin = TestFixtures.admin(ADMIN);

            assertThat(admin.permissions().isReadOnly()).isFalse();
            assertThat(guard.requireWrite(admin, INCIDENT, Capability.REASSIGN)).isNotNull();
        }
    }

    @Nested
    @DisplayName("object level through the guard")
    class ObjectLevel {

        @Test
        @DisplayName("a denied read throws a denial carrying a 7.11 reason")
        void deniedReadCarriesReason() {
            setUp(TestFixtures.incident(INCIDENT, ALICE, "FINANCE", "FINANCE", null));
            PlatformUser analyst = TestFixtures.analyst(ANALYST, ENGINEERING);

            assertThatThrownBy(() -> guard.requireRead(analyst, INCIDENT))
                    .isInstanceOf(AuthorizationDeniedException.class)
                    .satisfies(thrown -> {
                        var denied = (AuthorizationDeniedException) thrown;
                        assertThat(denied.decision().deniedReason())
                                .isEqualTo(DeniedReason.CROSS_USER_OBJECT_ACCESS);
                        assertThat(denied.resourceId()).isEqualTo(INCIDENT);
                    });
        }

        @Test
        @DisplayName("a missing incident is denied, not treated as an allowed empty result")
        void missingIncidentDenied() {
            setUp(null);

            assertThatThrownBy(() -> guard.requireRead(TestFixtures.admin(ADMIN), INCIDENT))
                    .isInstanceOf(AuthorizationDeniedException.class);
        }

        @Test
        @DisplayName("the denial message carries no resource detail")
        void messageLeaksNothing() {
            // 7.5: the response must not reveal whether the incident exists or
            // which department owns it, or the difference becomes an enumeration
            // oracle.
            setUp(TestFixtures.incident(INCIDENT, ALICE, "FINANCE", "FINANCE", null));

            assertThatThrownBy(() -> guard.requireRead(TestFixtures.analyst(ANALYST, ENGINEERING), INCIDENT))
                    .isInstanceOf(AuthorizationDeniedException.class)
                    .satisfies(thrown -> {
                        var message = thrown.getMessage();
                        assertThat(message).doesNotContain("FINANCE");
                        assertThat(message).doesNotContain(INCIDENT.toString());
                    });
        }
        @Test
        @DisplayName("Admin with includeDeleted opt-in can read a soft-deleted incident")
        void adminCanReadSoftDeletedWithOptIn() {
            setUp(TestFixtures.incident(
                    INCIDENT, ALICE, ENGINEERING, ENGINEERING, ANALYST,
                    null, TestFixtures.collaborators(), true));

            var snapshot = guard.requireRead(TestFixtures.admin(ADMIN), INCIDENT, true);
            assertThat(snapshot).isNotNull();
            assertThat(snapshot.softDeleted()).isTrue();
        }

        @Test
        @DisplayName("Admin without includeDeleted opt-in cannot read a soft-deleted incident")
        void adminCannotReadSoftDeletedWithoutOptIn() {
            setUp(TestFixtures.incident(
                    INCIDENT, ALICE, ENGINEERING, ENGINEERING, ANALYST,
                    null, TestFixtures.collaborators(), true));

            assertThatThrownBy(() -> guard.requireRead(TestFixtures.admin(ADMIN), INCIDENT, false))
                    .isInstanceOf(AuthorizationDeniedException.class);
        }
    }

    @Nested
    @DisplayName("defence in depth for list results")
    class ListFiltering {

        @Test
        @DisplayName("invisible rows are filtered out of an already-paged result")
        void filtersInvisible() {
            setUp(TestFixtures.incident(INCIDENT, ALICE, ENGINEERING, ENGINEERING, null));
            PlatformUser analyst = TestFixtures.analyst(ANALYST, ENGINEERING);

            var candidates = List.of(
                    TestFixtures.unassignedIn(INCIDENT, ALICE, ENGINEERING),
                    TestFixtures.unassignedIn(
                            UUID.randomUUID(), ALICE, "FINANCE"),
                    TestFixtures.incident(INCIDENT, ALICE, ENGINEERING, ENGINEERING, ANALYST));

            var visible = guard.filterVisible(analyst, candidates);

            assertThat(visible).hasSize(2);
            assertThat(visible).allSatisfy(s -> assertThat(s.effectiveDepartment()).isEqualTo(ENGINEERING));
        }

        @Test
        @DisplayName("a short page is the correct failure direction when query and rule disagree")
        void shortPageIsSafe() {
            setUp(TestFixtures.incident(INCIDENT, ALICE, ENGINEERING, ENGINEERING, null));
            PlatformUser analyst = TestFixtures.analyst(ANALYST, ENGINEERING);

            var visible = guard.filterVisible(analyst, List.of(
                    TestFixtures.unassignedIn(UUID.randomUUID(), ALICE, "FINANCE")));

            assertThat(visible).isEmpty();
        }

        @Test
        @DisplayName("Admin with includeDeleted opt-in preserves soft-deleted rows in list results")
        void adminCanIncludeDeletedInList() {
            // filterVisible never consults the repository, so the snapshot passed
            // to setUp is irrelevant here; what matters is that the guard itself
            // exists, which is why these two tests could not run without it.
            setUp(null);
            var deletedIncident = TestFixtures.incident(
                    INCIDENT, ALICE, ENGINEERING, ENGINEERING, ANALYST,
                    null, TestFixtures.collaborators(), true);

            var visible = guard.filterVisible(TestFixtures.admin(ADMIN), List.of(deletedIncident), true);
            assertThat(visible).hasSize(1);
        }

        @Test
        @DisplayName("Admin without includeDeleted filters out soft-deleted rows by default")
        void adminFiltersDeletedByDefaultInList() {
            setUp(null);
            var deletedIncident = TestFixtures.incident(
                    INCIDENT, ALICE, ENGINEERING, ENGINEERING, ANALYST,
                    null, TestFixtures.collaborators(), true);

            var visible = guard.filterVisible(TestFixtures.admin(ADMIN), List.of(deletedIncident), false);
            assertThat(visible).isEmpty();
        }
    }
}
