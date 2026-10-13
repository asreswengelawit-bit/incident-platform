package com.company.incidentplatform.authorization;

import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.DeniedReason;
import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.security.VisibilityScope;
import java.util.Locale;

/**
 * Section 7.2.1 -- object-level authorization for incidents.
 *
 * <p>This is the BOLA/IDOR gate. It is the reason an Analyst cannot read a
 * colleague's incident, and it is a single class rather than a condition
 * appended to each repository query, because a per-query check is a check that
 * eventually gets forgotten on the one endpoint added under deadline.
 *
 * <p>Reads and writes are authorised through the same object-level gate, then
 * separated by function-level capability. Keeping them in one place means a
 * write can never accidentally skip the object check that its corresponding read
 * performs.
 */
public final class IncidentObjectAuthorizer {

    private final GroupVisibilityPolicy groupVisibilityPolicy;

    /** Optional, supplied only when {@link GroupVisibilityPolicy#GROUP_MEMBERSHIP} is selected. */
    private GroupMembershipChecker groupMembershipChecker;

    public IncidentObjectAuthorizer(GroupVisibilityPolicy groupVisibilityPolicy) {
        this.groupVisibilityPolicy = groupVisibilityPolicy;
    }

    public IncidentObjectAuthorizer withGroupMembershipChecker(GroupMembershipChecker checker) {
        this.groupMembershipChecker = checker;
        return this;
    }

    /** Answers whether a user shares an Incident Group with the incident under review. */
    @FunctionalInterface
    public interface GroupMembershipChecker {
        boolean sharesGroupWith(java.util.UUID userId, java.util.UUID groupId);
    }

    /**
     * 7.2.1 department-scoped read access, evaluated against current state.
     *
     * <p>Implemented exactly as 7.2.1 specifies:
     *
     * <table>
     *   <caption>7.2.1 visibility by role</caption>
     *   <tr><th>Role</th><th>Visibility</th></tr>
     *   <tr><td>Reporter</td><td>Own submitted incidents only</td></tr>
     *   <tr><td>Analyst</td><td>Assigned to them, plus unassigned incidents in their own department</td></tr>
     *   <tr><td>Security Lead</td><td>All incidents in the department(s) they lead</td></tr>
     *   <tr><td>Admin</td><td>Organisation-wide, all departments</td></tr>
     *   <tr><td>Auditor</td><td>Organisation-wide <em>read-only</em>, including closed incidents</td></tr>
     * </table>
     *
     * <p>Note that Auditor inherits Admin's read scope here. The read-only half
     * of that role is enforced as a function-level restriction on write
     * endpoints, not by narrowing read visibility -- an Auditor who could not
     * read closed incidents could not perform the after-the-fact review
     * 7.2.1 grants them.
     */
    public AuthorizationDecision authorizeRead(PlatformUser user, IncidentSnapshot incident) {
        return authorizeRead(user, incident, false);
    }

    public AuthorizationDecision authorizeRead(
            PlatformUser user, IncidentSnapshot incident, boolean includeDeleted) {
        if (incident == null) {
            return AuthorizationDecision.deny(
                    AuthorizationCheckType.OBJECT_LEVEL,
                    "incident.read.exists",
                    DeniedReason.CROSS_USER_OBJECT_ACCESS);
        }

        VisibilityScope scope = user.permissions().visibilityScope();

        // 7.14 / 6.2: Soft-deleted incidents are hidden by default from all roles.
        // Admin and Auditor get an explicit opt-in (includeDeleted = true) for audit/compliance.
        // Using it is an audited action. For all other roles, or when includeDeleted is false,
        // soft-deleted incidents remain invisible.
        if (incident.softDeleted()) {
            if (includeDeleted && scope == VisibilityScope.ORGANIZATION) {
                return AuthorizationDecision.allow(
                        AuthorizationCheckType.OBJECT_LEVEL, "incident.read.soft_deleted_audit");
            }
            return AuthorizationDecision.deny(
                    AuthorizationCheckType.OBJECT_LEVEL,
                    "incident.read.not_deleted",
                    DeniedReason.CROSS_USER_OBJECT_ACCESS);
        }

        return switch (scope) {
            case NONE -> denyScope(user);
            case ORGANIZATION -> AuthorizationDecision.allow(
                    AuthorizationCheckType.OBJECT_LEVEL, "incident.read.organisation");
            case LED_DEPARTMENTS -> leadDecision(user, incident);
            case OWN_INCIDENTS -> reporterDecision(user, incident);
            case ASSIGNED_AND_OWN_DEPARTMENT_UNASSIGNED -> analystDecision(user, incident);
        };
    }

    /**
     * Writes. Same object-level gate as reads, then the function-level
     * capability for the specific mutation. Soft-deleted incidents are always
     * immutable (read-only for compliance/audit).
     */
    public AuthorizationDecision authorizeWrite(
            PlatformUser user,
            IncidentSnapshot incident,
            boolean capabilityHeld,
            String capabilityRule) {
        if (!capabilityHeld) {
            return AuthorizationDecision.deny(
                    AuthorizationCheckType.FUNCTION_LEVEL,
                    capabilityRule,
                    DeniedReason.INSUFFICIENT_ROLE);
        }
        if (incident != null && incident.softDeleted()) {
            return AuthorizationDecision.deny(
                    AuthorizationCheckType.OBJECT_LEVEL,
                    "incident.write.soft_deleted_immutable",
                    DeniedReason.CROSS_USER_OBJECT_ACCESS);
        }
        AuthorizationDecision objectLevel = authorizeRead(user, incident, false);
        if (objectLevel.denied()) {
            return objectLevel;
        }
        return AuthorizationDecision.allow(AuthorizationCheckType.OBJECT_LEVEL, capabilityRule);
    }

    private AuthorizationDecision reporterDecision(PlatformUser user, IncidentSnapshot incident) {
        if (incident.reporterId() != null && incident.reporterId().equals(user.id())) {
            return AuthorizationDecision.allow(
                    AuthorizationCheckType.OBJECT_LEVEL, "incident.read.own_submission");
        }
        // A Reporter is confined to their own submissions. Explicit collaboration
        // does not widen this: 7.2.1 is unambiguous that a Reporter sees "own
        // submitted incidents only", and a share cannot grant a user visibility
        // their role does not have. Flagged in the Phase 2 summary as a
        // deliberate literal reading.
        return AuthorizationDecision.deny(
                AuthorizationCheckType.OBJECT_LEVEL,
                "incident.read.reporter_own_only",
                DeniedReason.CROSS_USER_OBJECT_ACCESS);
    }

    private AuthorizationDecision analystDecision(PlatformUser user, IncidentSnapshot incident) {
        if (incident.assigneeId() != null && incident.assigneeId().equals(user.id())) {
            return AuthorizationDecision.allow(
                    AuthorizationCheckType.OBJECT_LEVEL, "incident.read.assigned_to_self");
        }
        if (incident.isCollaborator(user.id())) {
            return AuthorizationDecision.allow(
                    AuthorizationCheckType.OBJECT_LEVEL, "incident.read.explicit_collaborator");
        }
        if (groupVisibilityPolicy == GroupVisibilityPolicy.GROUP_MEMBERSHIP
                && incident.groupId() != null
                && groupMembershipChecker != null
                && groupMembershipChecker.sharesGroupWith(user.id(), incident.groupId())) {
            return AuthorizationDecision.allow(
                    AuthorizationCheckType.OBJECT_LEVEL, "incident.read.group_shared");
        }
        if (incident.isUnassigned() && inDepartment(user.department(), incident.effectiveDepartment())) {
            return AuthorizationDecision.allow(
                    AuthorizationCheckType.OBJECT_LEVEL, "incident.read.unassigned_own_department");
        }
        // The 7.11 signature of BOLA probing: a caller who is a real user, holds
        // a legitimate role, and is reaching for an incident outside both their
        // assignments and their department.
        return AuthorizationDecision.deny(
                AuthorizationCheckType.OBJECT_LEVEL,
                "incident.read.not_assigned_not_department",
                DeniedReason.CROSS_USER_OBJECT_ACCESS);
    }

    private AuthorizationDecision leadDecision(PlatformUser user, IncidentSnapshot incident) {
        if (IncidentResponsibilityResolver.leadsDepartment(
                user.permissions().ledDepartments(), incident.effectiveDepartment())) {
            return AuthorizationDecision.allow(
                    AuthorizationCheckType.OBJECT_LEVEL, "incident.read.led_department");
        }
        if (incident.isCollaborator(user.id())) {
            return AuthorizationDecision.allow(
                    AuthorizationCheckType.OBJECT_LEVEL, "incident.read.explicit_collaborator");
        }
        return AuthorizationDecision.deny(
                AuthorizationCheckType.OBJECT_LEVEL,
                "incident.read.not_led_department",
                DeniedReason.CROSS_USER_OBJECT_ACCESS);
    }

    private AuthorizationDecision denyScope(PlatformUser user) {
        // A Service Account reaches the platform only through the ingestion path
        // (section 5.3, FR-1.4/1.5). It must never be able to read back the
        // incidents it created -- that would be a covert channel around 7.2.1
        // giving it visibility of the whole organisation.
        return AuthorizationDecision.deny(
                AuthorizationCheckType.OBJECT_LEVEL,
                "incident.read.scope_none:" + user.role().name().toLowerCase(Locale.ROOT),
                DeniedReason.INSUFFICIENT_ROLE);
    }

    /**
     * Department comparison is case-insensitive because department names arrive
     * from two independent sources -- the IdP user profile and the incident
     * intake form -- and a case difference between them must not silently
     * downgrade a user's queue to empty.
     */
    private static boolean inDepartment(String userDepartment, String incidentDepartment) {
        return DepartmentKey.matches(userDepartment, incidentDepartment);
    }
}
