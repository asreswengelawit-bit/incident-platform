package com.company.incidentplatform.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static com.company.incidentplatform.TestFixtures.ENGINEERING;
import static com.company.incidentplatform.TestFixtures.FINANCE;
import static com.company.incidentplatform.TestFixtures.HR;
import static com.company.incidentplatform.TestFixtures.SECURITY;

import com.company.incidentplatform.TestFixtures;
import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.DeniedReason;
import com.company.incidentplatform.security.PlatformUser;
import java.util.UUID;
import java.util.function.BiFunction;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Section 7.2.1 and the Section 10 BOLA/IDOR row of the authorization test
 * matrix.
 *
 * <p>Structured around the roles and departments the specification names, so a
 * failure message states which documented rule broke rather than which
 * permutation of a random fixture happened to fail.
 */
class IncidentObjectAuthorizerTest {

    private final IncidentObjectAuthorizer authorizer =
            new IncidentObjectAuthorizer(GroupVisibilityPolicy.EXPLICIT_COLLABORATION_ONLY);

    private static final UUID ALICE_REPORTER = UUID.fromString("00000000-0000-0000-0000-0000000000a1");
    private static final UUID BOB_ANALYST = UUID.fromString("00000000-0000-0000-0000-0000000000b2");
    private static final UUID CAROL_ANALYST = UUID.fromString("00000000-0000-0000-0000-0000000000c3");
    private static final UUID DAVE_OTHER = UUID.fromString("00000000-0000-0000-0000-0000000000d4");
    private static final UUID LEAD = UUID.fromString("00000000-0000-0000-0000-0000000000e5");
    private static final UUID ADMIN = UUID.fromString("00000000-0000-0000-0000-0000000000f6");
    private static final UUID AUDITOR = UUID.fromString("00000000-0000-0000-0000-0000000000a7");
    private static final UUID INGEST = UUID.fromString("00000000-0000-0000-0000-0000000000b8");
    private static final UUID INCIDENT = UUID.fromString("00000000-0000-0000-0000-0000000000c1");

    @Nested
    @DisplayName("7.2.1 Reporter: own submitted incidents only")
    class Reporter {

        private final PlatformUser reporter = TestFixtures.reporter(ALICE_REPORTER, ENGINEERING);

        @Test
        @DisplayName("can read their own submission")
        void ownSubmissionAllowed() {
            var incident = TestFixtures.unassignedIn(INCIDENT, ALICE_REPORTER, ENGINEERING);

            var decision = authorizer.authorizeRead(reporter, incident);

            assertThat(decision.allowed()).isTrue();
            assertThat(decision.rule()).isEqualTo("incident.read.own_submission");
            assertThat(decision.checkType()).isEqualTo(AuthorizationCheckType.OBJECT_LEVEL);
        }

        @Test
        @DisplayName("cannot read another user's incident, even unassigned in their own department")
        void othersSubmissionDenied() {
            // The BOLA case: a real, legitimate user with a legitimate role,
            // reaching for an incident that is not theirs.
            var incident = TestFixtures.unassignedIn(INCIDENT, DAVE_OTHER, ENGINEERING);

            var decision = authorizer.authorizeRead(reporter, incident);

            assertThat(decision.allowed()).isFalse();
            assertThat(decision.deniedReason()).isEqualTo(DeniedReason.CROSS_USER_OBJECT_ACCESS);
        }

        @Test
        @DisplayName("explicit collaboration does not widen a Reporter beyond their own submissions")
        void collaborationDoesNotWidenReporter() {
            // 7.2.1 says "own submitted incidents only". A share cannot grant a
            // user visibility their role does not have, or the role table would
            // be advisory. Recorded as a deliberate literal reading.
            var incident = TestFixtures.incident(
                    INCIDENT, DAVE_OTHER, ENGINEERING, ENGINEERING, null,
                    null, TestFixtures.collaborators(ALICE_REPORTER), false);

            var decision = authorizer.authorizeRead(reporter, incident);

            assertThat(decision.allowed()).isFalse();
            assertThat(decision.rule()).isEqualTo("incident.read.reporter_own_only");
        }
    }

    @Nested
    @DisplayName("7.2.1 Analyst: assigned, plus unassigned in own department")
    class Analyst {

        @Test
        @DisplayName("can read an incident assigned to them, in any department")
        void assignedAllowed() {
            // 7.2.1 grants an Analyst their own assignments. Restricting those by
            // department would strand an incident whose department changed during
            // investigation, which is a workflow failure not a security one.
            var analyst = TestFixtures.analyst(BOB_ANALYST, ENGINEERING);
            var incident = TestFixtures.incident(INCIDENT, ALICE_REPORTER, HR, FINANCE, BOB_ANALYST);

            var decision = authorizer.authorizeRead(analyst, incident);

            assertThat(decision.allowed()).isTrue();
            assertThat(decision.rule()).isEqualTo("incident.read.assigned_to_self");
        }

        @Test
        @DisplayName("can read an unassigned incident in their own department")
        void unassignedOwnDepartmentAllowed() {
            var analyst = TestFixtures.analyst(BOB_ANALYST, ENGINEERING);
            var incident = TestFixtures.unassignedIn(INCIDENT, ALICE_REPORTER, ENGINEERING);

            var decision = authorizer.authorizeRead(analyst, incident);

            assertThat(decision.allowed()).isTrue();
            assertThat(decision.rule()).isEqualTo("incident.read.unassigned_own_department");
        }

        @Test
        @DisplayName("cannot read an unassigned incident in another department")
        void unassignedOtherDepartmentDenied() {
            // The core 7.2.1 protection. An unassigned queue scoped to the wrong
            // department is the most likely real-world leak, because it is a
            // single missing WHERE clause.
            var analyst = TestFixtures.analyst(BOB_ANALYST, ENGINEERING);
            var incident = TestFixtures.unassignedIn(INCIDENT, ALICE_REPORTER, FINANCE);

            var decision = authorizer.authorizeRead(analyst, incident);

            assertThat(decision.allowed()).isFalse();
            assertThat(decision.deniedReason()).isEqualTo(DeniedReason.CROSS_USER_OBJECT_ACCESS);
            assertThat(decision.rule()).isEqualTo("incident.read.not_assigned_not_department");
        }

        @Test
        @DisplayName("cannot read another analyst's assigned incident")
        void colleaguesAssignmentDenied() {
            var analyst = TestFixtures.analyst(BOB_ANALYST, ENGINEERING);
            var incident = TestFixtures.incident(INCIDENT, ALICE_REPORTER, ENGINEERING, ENGINEERING, CAROL_ANALYST);

            var decision = authorizer.authorizeRead(analyst, incident);

            assertThat(decision.allowed()).isFalse();
            assertThat(decision.rule()).isEqualTo("incident.read.not_assigned_not_department");
        }

        @Test
        @DisplayName("an explicit collaborator may read across departments")
        void collaboratorCrossDepartmentAllowed() {
            var analyst = TestFixtures.analyst(BOB_ANALYST, ENGINEERING);
            var incident = TestFixtures.incident(
                    INCIDENT, ALICE_REPORTER, HR, FINANCE, CAROL_ANALYST,
                    null, TestFixtures.collaborators(BOB_ANALYST), false);

            var decision = authorizer.authorizeRead(analyst, incident);

            assertThat(decision.allowed()).isTrue();
            assertThat(decision.rule()).isEqualTo("incident.read.explicit_collaborator");
        }

        @Test
        @DisplayName("a removed collaborator loses access")
        void removedCollaboratorDenied() {
            // incident_collaborator rows are soft-ended with removed_at, and the
            // snapshot only carries live ones. If that filter were dropped, a
            // revoked cross-department grant would persist invisibly.
            var analyst = TestFixtures.analyst(BOB_ANALYST, ENGINEERING);
            var incident = TestFixtures.incident(
                    INCIDENT, ALICE_REPORTER, HR, FINANCE, null,
                    null, TestFixtures.collaborators(), false);

            var decision = authorizer.authorizeRead(analyst, incident);

            assertThat(decision.allowed()).isFalse();
        }

        @Test
        @DisplayName("department matching is case-insensitive")
        void departmentCaseInsensitive() {
            // Department names come from two independent sources -- the IdP user
            // profile and the intake form. A case difference must not silently
            // empty a user's queue.
            var analyst = TestFixtures.analyst(BOB_ANALYST, "engineering");
            var incident = TestFixtures.unassignedIn(INCIDENT, ALICE_REPORTER, "ENGINEERING");

            assertThat(authorizer.authorizeRead(analyst, incident).allowed()).isTrue();
        }
    }

    @Nested
    @DisplayName("confirmed department-precedence decision")
    class DepartmentPrecedence {

        @Test
        @DisplayName("affected_department takes precedence over the reporter's department")
        void affectedDepartmentWins() {
            var analyst = TestFixtures.analyst(BOB_ANALYST, ENGINEERING);
            // Reported by Finance, affecting Engineering: it belongs in Bob's
            // queue because that is the department affected.
            var incident = TestFixtures.unassignedIn(INCIDENT, ALICE_REPORTER, FINANCE);
            incident = TestFixtures.incident(INCIDENT, ALICE_REPORTER, FINANCE, ENGINEERING, null);

            assertThat(incident.effectiveDepartment()).isEqualTo(ENGINEERING);
            assertThat(authorizer.authorizeRead(analyst, incident).allowed()).isTrue();
        }

        @Test
        @DisplayName("a blank affected_department queues under the reporter's department")
        void blankAffectedDepartmentFallsBackToReporter() {
            // The reporter-department fallback: the incident is not orphaned, and
            // triage corrects it as an audited change.
            var reporterInEngineering = TestFixtures.analyst(BOB_ANALYST, ENGINEERING);
            var incident = TestFixtures.incident(INCIDENT, ALICE_REPORTER, ENGINEERING, null, null);

            assertThat(incident.effectiveDepartment()).isEqualTo(ENGINEERING);
            assertThat(authorizer.authorizeRead(reporterInEngineering, incident).allowed()).isTrue();
        }

        @Test
        @DisplayName("a whitespace-only affected_department is treated as blank")
        void whitespaceAffectedDepartmentTreatedAsBlank() {
            var incident = TestFixtures.incident(INCIDENT, ALICE_REPORTER, ENGINEERING, "   ", null);

            assertThat(incident.effectiveDepartment()).isEqualTo(ENGINEERING);
        }

        @Test
        @DisplayName("when both are blank the incident is not visible in any department queue")
        void bothBlankIsNotVisible() {
            // Fails closed: an incident with no department and a reporter with no
            // department must not match, or two blank values would compare equal
            // and produce cross-department visibility.
            var analyst = TestFixtures.analyst(BOB_ANALYST, null);
            var incident = TestFixtures.incident(INCIDENT, ALICE_REPORTER, null, null, null);

            assertThat(incident.effectiveDepartment()).isNull();
            assertThat(authorizer.authorizeRead(analyst, incident).allowed()).isFalse();
        }
    }

    @Nested
    @DisplayName("7.2.1 Security Lead: led departments")
    class SecurityLead {

        @Test
        @DisplayName("can read incidents in a department they lead")
        void ledDepartmentAllowed() {
            var lead = TestFixtures.lead(LEAD, SECURITY, SECURITY, FINANCE);
            var incident = TestFixtures.incident(INCIDENT, ALICE_REPORTER, HR, FINANCE, null);

            var decision = authorizer.authorizeRead(lead, incident);

            assertThat(decision.allowed()).isTrue();
            assertThat(decision.rule()).isEqualTo("incident.read.led_department");
        }

        @Test
        @DisplayName("cannot read incidents in a department they do not lead")
        void notLedDepartmentDenied() {
            var lead = TestFixtures.lead(LEAD, SECURITY, SECURITY);
            var incident = TestFixtures.incident(INCIDENT, ALICE_REPORTER, HR, ENGINEERING, null);

            var decision = authorizer.authorizeRead(lead, incident);

            assertThat(decision.allowed()).isFalse();
            assertThat(decision.rule()).isEqualTo("incident.read.not_led_department");
        }

        @Test
        @DisplayName("an empty led_departments grants no departmental visibility at all")
        void emptyLedDepartmentsGrantsNothing() {
            var lead = TestFixtures.lead(LEAD, SECURITY);
            var incident = TestFixtures.incident(INCIDENT, ALICE_REPORTER, SECURITY, SECURITY, null);

            assertThat(lead.permissions().ledDepartments()).isEmpty();
            assertThat(authorizer.authorizeRead(lead, incident).allowed()).isFalse();
        }

        @Test
        @DisplayName("led department matching is case-insensitive")
        void ledDepartmentCaseInsensitive() {
            var lead = TestFixtures.lead(LEAD, SECURITY, "security");
            var incident = TestFixtures.incident(INCIDENT, ALICE_REPORTER, HR, SECURITY, null);

            assertThat(authorizer.authorizeRead(lead, incident).allowed()).isTrue();
        }
    }

    @Nested
    @DisplayName("7.2.1 Admin and Auditor")
    class OrganisationWide {

        @Test
        @DisplayName("an Admin can read any incident in any department")
        void adminOrganisationWide() {
            var incident = TestFixtures.incident(INCIDENT, ALICE_REPORTER, HR, ENGINEERING, null);

            var decision = authorizer.authorizeRead(TestFixtures.admin(ADMIN), incident);

            assertThat(decision.allowed()).isTrue();
            assertThat(decision.rule()).isEqualTo("incident.read.organisation");
        }

        @Test
        @DisplayName("an Auditor can read any incident, including one that is closed")
        void auditorOrganisationWide() {
            // 7.2.1 grants the Auditor organisation-wide read-only access
            // "including closed incidents". Read scope is what the Auditor needs;
            // read-only is enforced at the function level in IncidentAccessGuard.
            var incident = TestFixtures.incident(INCIDENT, ALICE_REPORTER, HR, ENGINEERING, null);

            var decision = authorizer.authorizeRead(TestFixtures.auditor(AUDITOR), incident);

            assertThat(decision.allowed()).isTrue();
            assertThat(decision.rule()).isEqualTo("incident.read.organisation");
        }
    }

    @Nested
    @DisplayName("soft-deleted incidents (Section 7.14 compliance/audit visibility)")
    class SoftDeleted {

        @ParameterizedTest
        @CsvSource({
            "reporter_self, OWN_INCIDENTS",
            "analyst_assigned, ASSIGNED_AND_OWN_DEPARTMENT_UNASSIGNED",
            "lead, LED_DEPARTMENTS",
            "admin, ORGANIZATION",
            "auditor, ORGANIZATION"
        })
        @DisplayName("are hidden by default from everyone, including Admins and Auditors")
        void softDeletedInvisibleByDefault(String who, String scope) {
            PlatformUser user = switch (who) {
                case "reporter_self" -> TestFixtures.reporter(ALICE_REPORTER, ENGINEERING);
                case "analyst_assigned" -> TestFixtures.analyst(BOB_ANALYST, ENGINEERING);
                case "lead" -> TestFixtures.lead(LEAD, SECURITY, ENGINEERING);
                case "admin" -> TestFixtures.admin(ADMIN);
                default -> TestFixtures.auditor(AUDITOR);
            };
            var incident = TestFixtures.incident(
                    INCIDENT, ALICE_REPORTER, ENGINEERING, ENGINEERING, BOB_ANALYST,
                    null, TestFixtures.collaborators(), true);

            var decision = authorizer.authorizeRead(user, incident);

            assertThat(decision.allowed()).as("default read must hide soft-deleted for scope %s", scope).isFalse();
            assertThat(decision.rule()).isEqualTo("incident.read.not_deleted");
        }

        @Test
        @DisplayName("Admin with explicit includeDeleted opt-in can read soft-deleted incidents")
        void adminWithOptInCanReadSoftDeleted() {
            var admin = TestFixtures.admin(ADMIN);
            var incident = TestFixtures.incident(
                    INCIDENT, ALICE_REPORTER, ENGINEERING, ENGINEERING, BOB_ANALYST,
                    null, TestFixtures.collaborators(), true);

            var decision = authorizer.authorizeRead(admin, incident, true);

            assertThat(decision.allowed()).isTrue();
            assertThat(decision.rule()).isEqualTo("incident.read.soft_deleted_audit");
            assertThat(decision.checkType()).isEqualTo(AuthorizationCheckType.OBJECT_LEVEL);
        }

        @Test
        @DisplayName("Auditor with explicit includeDeleted opt-in can read soft-deleted incidents for compliance review")
        void auditorWithOptInCanReadSoftDeleted() {
            var auditor = TestFixtures.auditor(AUDITOR);
            var incident = TestFixtures.incident(
                    INCIDENT, ALICE_REPORTER, ENGINEERING, ENGINEERING, BOB_ANALYST,
                    null, TestFixtures.collaborators(), true);

            var decision = authorizer.authorizeRead(auditor, incident, true);

            assertThat(decision.allowed()).isTrue();
            assertThat(decision.rule()).isEqualTo("incident.read.soft_deleted_audit");
            assertThat(decision.checkType()).isEqualTo(AuthorizationCheckType.OBJECT_LEVEL);
        }

        @ParameterizedTest
        @CsvSource({
            "reporter_self",
            "analyst_assigned",
            "lead"
        })
        @DisplayName("includeDeleted opt-in is denied for non-Admin/Auditor roles")
        void optInDeniedForNonOrgRoles(String who) {
            PlatformUser user = switch (who) {
                case "reporter_self" -> TestFixtures.reporter(ALICE_REPORTER, ENGINEERING);
                case "analyst_assigned" -> TestFixtures.analyst(BOB_ANALYST, ENGINEERING);
                default -> TestFixtures.lead(LEAD, SECURITY, ENGINEERING);
            };
            var incident = TestFixtures.incident(
                    INCIDENT, ALICE_REPORTER, ENGINEERING, ENGINEERING, BOB_ANALYST,
                    null, TestFixtures.collaborators(), true);

            var decision = authorizer.authorizeRead(user, incident, true);

            assertThat(decision.allowed()).isFalse();
            assertThat(decision.rule()).isEqualTo("incident.read.not_deleted");
        }

        @Test
        @DisplayName("soft-deleted incidents are immutable and cannot be written to by anyone")
        void softDeletedCannotBeWritten() {
            var admin = TestFixtures.admin(ADMIN);
            var incident = TestFixtures.incident(
                    INCIDENT, ALICE_REPORTER, ENGINEERING, ENGINEERING, BOB_ANALYST,
                    null, TestFixtures.collaborators(), true);

            var decision = authorizer.authorizeWrite(admin, incident, true, "capability.can_reassign");

            assertThat(decision.allowed()).isFalse();
            assertThat(decision.rule()).isEqualTo("incident.write.soft_deleted_immutable");
        }
    }

    @Nested
    @DisplayName("5.3 Service Account")
    class ServiceAccount {

        @Test
        @DisplayName("cannot read back the incidents it created")
        void cannotReadOwnIngestedIncidents() {
            // The service account is the reporter of the incidents it ingests. If
            // it could read them, a leaked ingest token would become a covert
            // channel to organisation-wide incident data.
            var serviceAccount = TestFixtures.serviceAccount(INGEST);
            var incident = TestFixtures.unassignedIn(INCIDENT, INGEST, null);

            var decision = authorizer.authorizeRead(serviceAccount, incident);

            assertThat(decision.allowed()).isFalse();
            assertThat(decision.deniedReason()).isEqualTo(DeniedReason.INSUFFICIENT_ROLE);
            assertThat(decision.rule()).contains("scope_none");
        }
    }

    @Nested
    @DisplayName("Incident Group visibility policy")
    class GroupPolicy {

        @Test
        @DisplayName("under the default policy, group membership confers no visibility")
        void defaultPolicyGrantsNothing() {
            var analyst = TestFixtures.analyst(BOB_ANALYST, ENGINEERING);
            var groupId = UUID.fromString("00000000-0000-0000-0000-0000000000g1".replace("g", "9"));
            var incident = TestFixtures.incident(
                    INCIDENT, ALICE_REPORTER, FINANCE, FINANCE, CAROL_ANALYST,
                    groupId, TestFixtures.collaborators(), false);

            var decision = new IncidentObjectAuthorizer(GroupVisibilityPolicy.EXPLICIT_COLLABORATION_ONLY)
                    .withGroupMembershipChecker((userId, gid) -> true)
                    .authorizeRead(analyst, incident);

            assertThat(decision.allowed())
                    .as("EXPLICIT_COLLABORATION_ONLY must ignore group membership entirely")
                    .isFalse();
        }

        @Test
        @DisplayName("under GROUP_MEMBERSHIP, a shared campaign confers visibility")
        void groupMembershipPolicyGrants() {
            var analyst = TestFixtures.analyst(BOB_ANALYST, ENGINEERING);
            var groupId = UUID.fromString("00000000-0000-0000-0000-000000000099");
            var incident = TestFixtures.incident(
                    INCIDENT, ALICE_REPORTER, FINANCE, FINANCE, CAROL_ANALYST,
                    groupId, TestFixtures.collaborators(), false);

            var decision = new IncidentObjectAuthorizer(GroupVisibilityPolicy.GROUP_MEMBERSHIP)
                    .withGroupMembershipChecker((userId, gid) -> gid.equals(groupId))
                    .authorizeRead(analyst, incident);

            assertThat(decision.allowed()).isTrue();
            assertThat(decision.rule()).isEqualTo("incident.read.group_shared");
        }

        @Test
        @DisplayName("GROUP_MEMBERSHIP does not resurrect a soft-deleted incident")
        void groupPolicyCannotResurrectSoftDeleted() {
            var analyst = TestFixtures.analyst(BOB_ANALYST, ENGINEERING);
            var groupId = UUID.fromString("00000000-0000-0000-0000-000000000099");
            var incident = TestFixtures.incident(
                    INCIDENT, ALICE_REPORTER, FINANCE, FINANCE, null,
                    groupId, TestFixtures.collaborators(), true);

            var decision = new IncidentObjectAuthorizer(GroupVisibilityPolicy.GROUP_MEMBERSHIP)
                    .withGroupMembershipChecker((userId, gid) -> true)
                    .authorizeRead(analyst, incident);

            assertThat(decision.allowed()).isFalse();
        }
    }

    @Nested
    @DisplayName("7.2 write path")
    class WritePath {

        @Test
        @DisplayName("a held capability plus object access is allowed")
        void capabilityAndObjectAllowed() {
            var lead = TestFixtures.lead(LEAD, SECURITY, SECURITY);
            var incident = TestFixtures.incident(INCIDENT, ALICE_REPORTER, HR, SECURITY, null);

            var decision = authorizer.authorizeWrite(
                    lead, incident, Capability.REASSIGN.isHeldBy(lead.permissions()), Capability.REASSIGN.rule());

            assertThat(decision.allowed()).isTrue();
            assertThat(decision.checkType()).isEqualTo(AuthorizationCheckType.OBJECT_LEVEL);
        }

        @Test
        @DisplayName("object access without the capability is denied at the function level")
        void missingCapabilityDenied() {
            var analyst = TestFixtures.analyst(BOB_ANALYST, ENGINEERING);
            var incident = TestFixtures.incident(INCIDENT, ALICE_REPORTER, ENGINEERING, ENGINEERING, BOB_ANALYST);

            var decision = authorizer.authorizeWrite(
                    analyst, incident, Capability.REASSIGN.isHeldBy(analyst.permissions()),
                    Capability.REASSIGN.rule());

            assertThat(decision.allowed()).isFalse();
            assertThat(decision.checkType()).isEqualTo(AuthorizationCheckType.FUNCTION_LEVEL);
            assertThat(decision.deniedReason()).isEqualTo(DeniedReason.INSUFFICIENT_ROLE);
        }

        @Test
        @DisplayName("holding the capability does not bypass the object check")
        void capabilityDoesNotBypassObjectCheck() {
            // The Lead holds REASSIGN organisation-wide, but only within led
            // departments. A capability must never be sufficient on its own.
            var lead = TestFixtures.lead(LEAD, SECURITY, SECURITY);
            var incident = TestFixtures.incident(INCIDENT, ALICE_REPORTER, HR, ENGINEERING, null);

            var decision = authorizer.authorizeWrite(
                    lead, incident, Capability.REASSIGN.isHeldBy(lead.permissions()), Capability.REASSIGN.rule());

            assertThat(decision.allowed()).isFalse();
            assertThat(decision.checkType()).isEqualTo(AuthorizationCheckType.OBJECT_LEVEL);
        }

        @Test
        @DisplayName("a denial always names a 7.11 reason code")
        void denialsAlwaysCarryAReason() {
            // 7.11 is what makes BOLA probing detectable. A denial with a null
            // reason would be an unclassifiable event.
            BiFunction<PlatformUser, IncidentSnapshot, AuthorizationDecision> check =
                    authorizer::authorizeRead;

            var denied = check.apply(
                    TestFixtures.analyst(BOB_ANALYST, ENGINEERING),
                    TestFixtures.unassignedIn(INCIDENT, DAVE_OTHER, FINANCE));

            assertThat(denied.deniedReason()).isNotNull();
            assertThat(denied.rule()).isNotBlank();
        }
    }

    @Test
    @DisplayName("a null incident is denied rather than throwing")
    void nullIncidentDenied() {
        // A missing row must not become a 500, and must not become an allow.
        var decision = authorizer.authorizeRead(TestFixtures.admin(ADMIN), null);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.deniedReason()).isEqualTo(DeniedReason.CROSS_USER_OBJECT_ACCESS);
    }
}
