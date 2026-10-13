package com.company.incidentplatform.incident;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.company.incidentplatform.TestFixtures;
import com.company.incidentplatform.identity.AppUserEntity;
import com.company.incidentplatform.security.PlatformRole;
import com.company.incidentplatform.security.PlatformUser;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Section 8.2 -- the transition matrix, and the role boundaries drawn on it.
 *
 * <p>The centre of gravity here is the Security Administrator. 8.2 states the
 * absence is deliberate: "Security Administrator is deliberately absent from this
 * table (explicit, not an oversight)". An Admin holds every capability in 12.1
 * and sees every incident in 7.2.1, so any test of this class that only checked
 * "is the role allowed" would pass with Admin in the matrix -- the defect is
 * invisible from the capability side. It has to be tested as a denial.
 */
class IncidentStateMachineTest {

    private final IncidentStateMachine machine = new IncidentStateMachine();

    private static final UUID REPORTER = UUID.fromString("00000000-0000-0000-0000-0000000000a1");
    private static final UUID ANALYST = UUID.fromString("00000000-0000-0000-0000-0000000000b2");
    private static final UUID LEAD = UUID.fromString("00000000-0000-0000-0000-0000000000c3");
    private static final UUID ADMIN = UUID.fromString("00000000-0000-0000-0000-0000000000f6");
    private static final UUID AUDITOR = UUID.fromString("00000000-0000-0000-0000-0000000000a7");
    private static final UUID INCIDENT = UUID.fromString("00000000-0000-0000-0000-0000000000c1");
    private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-02-01T08:00:00Z");

    private static PlatformUser user(UUID id, PlatformRole role) {
        return switch (role) {
            case REPORTER -> TestFixtures.reporter(id, TestFixtures.ENGINEERING);
            case ANALYST -> TestFixtures.analyst(id, TestFixtures.ENGINEERING);
            case SECURITY_LEAD -> TestFixtures.lead(id, TestFixtures.ENGINEERING, TestFixtures.ENGINEERING);
            case SECURITY_ADMIN -> TestFixtures.admin(id);
            case AUDITOR -> TestFixtures.auditor(id);
            case SERVICE_ACCOUNT -> TestFixtures.serviceAccount(id);
        };
    }

    private static AppUserEntity assignee(UUID id, PlatformRole role, boolean active) {
        AppUserEntity user = mock(AppUserEntity.class);
        when(user.getId()).thenReturn(id);
        when(user.coarseRole()).thenReturn(role);
        when(user.isActive()).thenReturn(active);
        return user;
    }

    private IncidentEntity incident(IncidentStatus status, IncidentSeverity severity) {
        IncidentEntity entity = new IncidentEntity(
                INCIDENT, "Suspicious login", "Multiple failed logins", null,
                severity, mock(AppUserEntity.class), NOW, NOW,
                "okta", TestFixtures.ENGINEERING, false, false, IncidentSource.WEB_UI, null);
        entity.setStatus(status);
        return entity;
    }

    private static IncidentStateMachine.TransitionContext context(
            IncidentSeverity severity, AppUserEntity target, String reason, String summary, long actions) {
        return new IncidentStateMachine.TransitionContext(severity, target, reason, summary, actions);
    }

    @Nested
    @DisplayName("8.2: Security Administrator is deliberately absent from the matrix")
    class AdminIsNotAnOperator {

        @Test
        @DisplayName("an Admin cannot triage, even holding every capability 12.1 grants")
        void adminCannotTriage() {
            IncidentEntity entity = incident(IncidentStatus.NEW, null);

            assertThatThrownBy(() -> machine.validateTransition(
                    entity, IncidentStatus.TRIAGED, user(ADMIN, PlatformRole.SECURITY_ADMIN),
                    context(IncidentSeverity.HIGH, null, null, null, 0)))
                    .isInstanceOf(InvalidStatusTransitionException.class)
                    .hasMessageContaining("SECURITY_ADMIN");
        }

        @Test
        @DisplayName("an Admin cannot be handed a queued incident")
        void adminCannotBeAssigned() {
            IncidentEntity entity = incident(IncidentStatus.TRIAGED, IncidentSeverity.MEDIUM);

            // A Lead tries to hand the incident to an Admin. The refusal is about
            // who would be doing the investigating work, which is 8.2's rule
            // ("Assignee must be an active Analyst") rather than the Lead's own
            // authority to assign.
            assertThatThrownBy(() -> machine.validateTransition(
                    entity, IncidentStatus.ASSIGNED, user(LEAD, PlatformRole.SECURITY_LEAD),
                    context(null, assignee(ADMIN, PlatformRole.SECURITY_ADMIN, true), null, null, 0)))
                    .isInstanceOf(InvalidStatusTransitionException.class)
                    .hasMessageContaining("Analyst or Lead");
        }

        @Test
        @DisplayName("an Admin cannot approve closure of a Medium+ incident")
        void adminCannotCloseMedium() {
            IncidentEntity entity = incident(IncidentStatus.RESOLVED, IncidentSeverity.MEDIUM);
            entity.setResolutionSummary("Host rebuilt and re-imaged");

            assertThatThrownBy(() -> machine.validateTransition(
                    entity, IncidentStatus.CLOSED, user(ADMIN, PlatformRole.SECURITY_ADMIN),
                    context(null, null, null, null, 0)))
                    .isInstanceOf(InvalidStatusTransitionException.class)
                    .hasMessageContaining("SECURITY_ADMIN");
        }

        @Test
        @DisplayName("Low severity removes the Lead sign-off, not the role boundary")
        void adminCannotCloseLowEither() {
            IncidentEntity entity = incident(IncidentStatus.RESOLVED, IncidentSeverity.LOW);
            entity.setResolutionSummary("False positive, closed");

            assertThatThrownBy(() -> machine.validateTransition(
                    entity, IncidentStatus.CLOSED, user(ADMIN, PlatformRole.SECURITY_ADMIN),
                    context(null, null, null, null, 0)))
                    .isInstanceOf(InvalidStatusTransitionException.class);
        }

        @Test
        @DisplayName("an Admin cannot reopen a closed incident, which is Lead-only")
        void adminCannotReopenClosed() {
            IncidentEntity entity = incident(IncidentStatus.CLOSED, IncidentSeverity.MEDIUM);

            assertThatThrownBy(() -> machine.validateTransition(
                    entity, IncidentStatus.REOPENED, user(ADMIN, PlatformRole.SECURITY_ADMIN),
                    context(null, null, "Recurrence reported", null, 0)))
                    .isInstanceOf(InvalidStatusTransitionException.class);
        }

        @Test
        @DisplayName("an Admin cannot drive investigation-stage transitions")
        void adminCannotContain() {
            IncidentEntity entity = incident(IncidentStatus.INVESTIGATING, IncidentSeverity.MEDIUM);

            assertThatThrownBy(() -> machine.validateTransition(
                    entity, IncidentStatus.CONTAINED, user(ADMIN, PlatformRole.SECURITY_ADMIN),
                    context(null, null, null, null, 0)))
                    .isInstanceOf(InvalidStatusTransitionException.class);
        }

        @Test
        @DisplayName("the Auditor is read-only and holds no workflow edge either")
        void auditorHoldsNoEdge() {
            IncidentEntity entity = incident(IncidentStatus.TRIAGED, IncidentSeverity.MEDIUM);

            assertThatThrownBy(() -> machine.validateTransition(
                    entity, IncidentStatus.ASSIGNED, user(AUDITOR, PlatformRole.AUDITOR),
                    context(null, assignee(ANALYST, PlatformRole.ANALYST, true), null, null, 0)))
                    .isInstanceOf(InvalidStatusTransitionException.class)
                    .hasMessageContaining("AUDITOR");
        }
    }

    @Nested
    @DisplayName("8.2: the edges 12.1's capabilities do grant")
    class GrantedEdges {

        @Test
        @DisplayName("an Analyst can triage, and classification comes with it")
        void analystCanTriage() {
            IncidentEntity entity = incident(IncidentStatus.NEW, null);

            assertThatCode(() -> machine.validateTransition(
                    entity, IncidentStatus.TRIAGED, user(ANALYST, PlatformRole.ANALYST),
                    context(IncidentSeverity.HIGH, null, null, null, 0)))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("triage without a computed severity is refused -- 12.2 makes classification atomic with it")
        void triageRequiresClassification() {
            IncidentEntity entity = incident(IncidentStatus.NEW, null);

            assertThatThrownBy(() -> machine.validateTransition(
                    entity, IncidentStatus.TRIAGED, user(ANALYST, PlatformRole.ANALYST),
                    IncidentStateMachine.TransitionContext.empty()))
                    .isInstanceOf(InvalidStatusTransitionException.class)
                    .hasMessageContaining("Impact and likelihood");
        }

        @Test
        @DisplayName("a Lead can reopen a closed incident")
        void leadCanReopenClosed() {
            IncidentEntity entity = incident(IncidentStatus.CLOSED, IncidentSeverity.MEDIUM);

            assertThatCode(() -> machine.validateTransition(
                    entity, IncidentStatus.REOPENED, user(LEAD, PlatformRole.SECURITY_LEAD),
                    context(null, null, "Same actor, new host", null, 0)))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("a Lead who did not investigate can close a Medium+ incident")
        void independentLeadCanClose() {
            IncidentEntity entity = incident(IncidentStatus.RESOLVED, IncidentSeverity.HIGH);
            entity.setAssignee(assignee(ANALYST, PlatformRole.ANALYST, true));
            entity.setResolutionSummary("Malware removed, host re-imaged");

            assertThatCode(() -> machine.validateTransition(
                    entity, IncidentStatus.CLOSED, user(LEAD, PlatformRole.SECURITY_LEAD),
                    context(null, null, null, null, 0)))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("7.3 maker-checker on closure")
    class MakerChecker {

        @Test
        @DisplayName("the investigating analyst cannot approve their own Medium+ closure")
        void makerCannotBeChecker() {
            // A Lead who took the incident and did the containment work is the
            // realistic maker here: 7.3's rule is about independence, and it
            // binds a Lead exactly as it binds an Analyst.
            IncidentEntity entity = incident(IncidentStatus.RESOLVED, IncidentSeverity.HIGH);
            entity.setAssignee(assignee(LEAD, PlatformRole.SECURITY_LEAD, true));
            entity.setResolutionSummary("Done");

            assertThatThrownBy(() -> machine.validateTransition(
                    entity, IncidentStatus.CLOSED, user(LEAD, PlatformRole.SECURITY_LEAD),
                    context(null, null, null, null, 0)))
                    .isInstanceOf(InvalidStatusTransitionException.class)
                    .hasMessageContaining("Maker-checker");
        }

        @Test
        @DisplayName("the same analyst may close a Low incident, which needs no second pair of eyes")
        void makerCheckerAppliesFromMediumUp() {
            IncidentEntity entity = incident(IncidentStatus.RESOLVED, IncidentSeverity.LOW);
            entity.setAssignee(assignee(ANALYST, PlatformRole.ANALYST, true));
            entity.setResolutionSummary("Duplicate report");

            assertThatCode(() -> machine.validateTransition(
                    entity, IncidentStatus.CLOSED, user(ANALYST, PlatformRole.ANALYST),
                    context(null, null, null, null, 0)))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("8.2 / FR-3.3 preconditions")
    class Preconditions {

        @Test
        @DisplayName("resolution requires a recorded Response Action and a summary")
        void resolutionRequiresBoth() {
            IncidentEntity entity = incident(IncidentStatus.CONTAINED, IncidentSeverity.HIGH);
            entity.setAssignee(assignee(ANALYST, PlatformRole.ANALYST, true));

            assertThatThrownBy(() -> machine.validateTransition(
                    entity, IncidentStatus.RESOLVED, user(ANALYST, PlatformRole.ANALYST),
                    context(null, null, null, "Cleaned", 0)))
                    .isInstanceOf(InvalidStatusTransitionException.class)
                    .hasMessageContaining("Response Action");

            assertThatThrownBy(() -> machine.validateTransition(
                    entity, IncidentStatus.RESOLVED, user(ANALYST, PlatformRole.ANALYST),
                    context(null, null, null, "  ", 2)))
                    .isInstanceOf(InvalidStatusTransitionException.class)
                    .hasMessageContaining("Resolution summary");

            assertThatCode(() -> machine.validateTransition(
                    entity, IncidentStatus.RESOLVED, user(ANALYST, PlatformRole.ANALYST),
                    context(null, null, null, "Host re-imaged", 2)))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("an inactive user cannot take an assignment")
        void assigneeMustBeActive() {
            IncidentEntity entity = incident(IncidentStatus.TRIAGED, IncidentSeverity.MEDIUM);

            assertThatThrownBy(() -> machine.validateTransition(
                    entity, IncidentStatus.ASSIGNED, user(LEAD, PlatformRole.SECURITY_LEAD),
                    context(null, assignee(ANALYST, PlatformRole.ANALYST, false), null, null, 0)))
                    .isInstanceOf(InvalidStatusTransitionException.class)
                    .hasMessageContaining("active user");
        }

        @Test
        @DisplayName("only the assigned analyst can start an investigation")
        void onlyAssigneeInvestigates() {
            IncidentEntity entity = incident(IncidentStatus.ASSIGNED, IncidentSeverity.MEDIUM);
            entity.setAssignee(assignee(ANALYST, PlatformRole.ANALYST, true));

            assertThatThrownBy(() -> machine.validateTransition(
                    entity, IncidentStatus.INVESTIGATING, user(LEAD, PlatformRole.SECURITY_LEAD),
                    IncidentStateMachine.TransitionContext.empty()))
                    .isInstanceOf(InvalidStatusTransitionException.class);

            assertThatCode(() -> machine.validateTransition(
                    entity, IncidentStatus.INVESTIGATING, user(ANALYST, PlatformRole.ANALYST),
                    IncidentStateMachine.TransitionContext.empty()))
                    .doesNotThrowAnyException();
        }

        @ParameterizedTest(name = "{0} is terminal")
        @EnumSource(value = IncidentStatus.class, names = "REJECTED")
        void rejectedIsTerminal(IncidentStatus from) {
            assertThatThrownBy(() -> machine.validateTransition(
                    incident(from, IncidentSeverity.MEDIUM), IncidentStatus.INVESTIGATING,
                    user(LEAD, PlatformRole.SECURITY_LEAD), IncidentStateMachine.TransitionContext.empty()))
                    .isInstanceOf(InvalidStatusTransitionException.class)
                    .hasMessageContaining("terminal");
        }

        @Test
        @DisplayName("a status may not be transitioned to itself")
        void selfTransitionRefused() {
            assertThatThrownBy(() -> machine.validateTransition(
                    incident(IncidentStatus.TRIAGED, IncidentSeverity.MEDIUM), IncidentStatus.TRIAGED,
                    user(LEAD, PlatformRole.SECURITY_LEAD), IncidentStateMachine.TransitionContext.empty()))
                    .isInstanceOf(InvalidStatusTransitionException.class)
                    .hasMessageContaining("already in status");
        }
    }
}
