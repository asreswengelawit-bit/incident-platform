package com.company.incidentplatform;

import com.company.incidentplatform.authorization.IncidentSnapshot;
import com.company.incidentplatform.security.PlatformRole;
import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.security.RolePermissions;
import com.company.incidentplatform.security.VisibilityScope;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Fixtures for the Section 10 authorization tests.
 *
 * <p>Builds users from the same jsonb shape {@code platform_role.permissions}
 * holds, rather than from hand-constructed {@link RolePermissions} objects. That
 * matters: a test that injects a permission object directly proves the authorizer
 * works against a permission object, but not that the production path -- jsonb
 * text to parsed flags to decision -- preserves the rule. Building from JSON
 * means these tests would still catch a parsing regression.
 */
public final class TestFixtures {

    public static final String SECURITY = "SECURITY";
    public static final String FINANCE = "FINANCE";
    public static final String ENGINEERING = "ENGINEERING";
    public static final String HR = "HR";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private TestFixtures() {
    }

    public static PlatformUser user(
            UUID id, String email, String department, PlatformRole role, String permissionsJson) {
        try {
            return new PlatformUser(
                    id,
                    "kc-" + id,
                    email,
                    email,
                    department,
                    role,
                    RolePermissions.fromJson(MAPPER.readTree(permissionsJson)),
                    true,
                    true);
        } catch (Exception e) {
            throw new IllegalArgumentException("Bad test fixture permissions for " + email, e);
        }
    }

    public static PlatformUser reporter(UUID id, String department) {
        return user(id, "reporter-" + shortId(id), department, PlatformRole.REPORTER, """
                {
                  "visibility_scope": "OWN_INCIDENTS"
                }
                """);
    }

    public static PlatformUser analyst(UUID id, String department) {
        return user(id, "analyst-" + shortId(id), department, PlatformRole.ANALYST, """
                {
                  "visibility_scope": "ASSIGNED_AND_OWN_DEPARTMENT_UNASSIGNED",
                  "can_view_investigation_notes": true,
                  "can_record_response_action": true,
                  "can_assign_self": true,
                  "can_classify": true
                }
                """);
    }

    public static PlatformUser lead(UUID id, String homeDepartment, String... ledDepartments) {
        String led = "\"" + String.join("\", \"", ledDepartments) + "\"";
        return user(id, "lead-" + shortId(id), homeDepartment, PlatformRole.SECURITY_LEAD, """
                {
                  "visibility_scope": "LED_DEPARTMENTS",
                  "led_departments": [%s],
                  "can_view_investigation_notes": true,
                  "can_record_response_action": true,
                  "can_reassign": true,
                  "can_escalate": true,
                  "can_override_severity": true,
                  "can_approve_closure": true,
                  "can_reopen_closed": true
                }
                """.formatted(led));
    }

    public static PlatformUser admin(UUID id) {
        // Mirrors V10 + V12 for SECURITY_ADMIN. Note the absence of
        // can_view_investigation_notes: 12.1 does not grant it to the Admin role,
        // and V10 seeds it for Analyst, Lead and Auditor only. Organisation-wide
        // incident visibility (visibility_scope) is therefore not the same thing
        // as visibility of internal investigation findings -- the 7.2.1 table
        // governs which incidents are listed, and the capability governs which
        // fields those incidents may include. Worth confirming against 12.1, but
        // the fixture has to match what a fresh deployment actually gets, or
        // these tests would pass against a configuration nobody runs.
        return user(id, "admin-" + shortId(id), SECURITY, PlatformRole.SECURITY_ADMIN, """
                {
                  "visibility_scope": "ORGANIZATION",
                  "can_record_response_action": true,
                  "can_reassign": true,
                  "can_escalate": true,
                  "can_override_severity": true,
                  "can_approve_closure": true,
                  "can_reopen_closed": true,
                  "can_create_incident": true,
                  "can_comment": true,
                  "can_view_audit_log": true,
                  "can_export": true,
                  "can_manage_users": true,
                  "can_manage_categories": true,
                  "can_manage_severity_matrix": true,
                  "can_manage_sla": true,
                  "can_manage_notification_rules": true,
                  "can_manage_retention": true
                }
                """);
    }

    /**
     * 7.2.1: the Auditor is organisation-wide read-only. Note the deliberate
     * absence of {@code can_view_reporter_identity} -- per the confirmed
     * decision it is granted to no one at deployment, not even to Admins.
     */
    public static PlatformUser auditor(UUID id) {
        return user(id, "auditor-" + shortId(id), SECURITY, PlatformRole.AUDITOR, """
                {
                  "visibility_scope": "ORGANIZATION",
                  "read_only": true,
                  "can_view_audit_log": true,
                  "can_view_investigation_notes": true,
                  "can_export": true
                }
                """);
    }

    public static PlatformUser serviceAccount(UUID id) {
        return user(id, "svc-" + shortId(id), null, PlatformRole.SERVICE_ACCOUNT, """
                {
                  "visibility_scope": "NONE",
                  "can_ingest_incidents": true
                }
                """);
    }

    /** An Admin who has been granted reporter-identity visibility (FR-1.6). */
    public static PlatformUser adminWithReporterIdentity(UUID id) {
        return user(id, "admin-rpi-" + shortId(id), SECURITY, PlatformRole.SECURITY_ADMIN, """
                {
                  "visibility_scope": "ORGANIZATION",
                  "can_manage_users": true,
                  "can_view_reporter_identity": true
                }
                """);
    }

    /**
     * An Admin holding <em>both</em> grants, which is the only role that can
     * exercise the FR-1.6 identity-disclosure branch of the audit-log read.
     *
     * <p>Separate from {@link #adminWithReporterIdentity} because that fixture
     * deliberately lacks {@code can_view_audit_log}, and so is refused by the
     * audit endpoint before redaction is ever reached. Modelling the two grants as
     * a single fixture would hide that ordering: the interesting case is precisely
     * a caller who clears the function-level gate and is then still redacted.
     */
    public static PlatformUser adminWithAuditLogAndReporterIdentity(UUID id) {
        return user(id, "admin-rpi-audit-" + shortId(id), SECURITY, PlatformRole.SECURITY_ADMIN, """
                {
                  "visibility_scope": "ORGANIZATION",
                  "can_view_audit_log": true,
                  "can_view_reporter_identity": true
                }
                """);
    }

    public static IncidentSnapshot incident(
            UUID id,
            UUID reporterId,
            String reporterDepartment,
            String affectedDepartment,
            UUID assigneeId) {
        return incident(id, reporterId, reporterDepartment, affectedDepartment, assigneeId,
                null, Set.of(), false);
    }

    public static IncidentSnapshot incident(
            UUID id,
            UUID reporterId,
            String reporterDepartment,
            String affectedDepartment,
            UUID assigneeId,
            UUID groupId,
            Set<UUID> collaborators,
            boolean softDeleted) {
        return new IncidentSnapshot(
                id, reporterId, reporterDepartment, affectedDepartment, assigneeId,
                groupId, softDeleted, collaborators);
    }

    public static IncidentSnapshot unassignedIn(UUID id, UUID reporterId, String department) {
        return incident(id, reporterId, department, department, null);
    }

    public static Set<UUID> collaborators(UUID... ids) {
        return ids.length == 0 ? Set.of() : Set.of(ids);
    }

    private static String shortId(UUID id) {
        return id.toString().substring(0, 8);
    }

    public static List<PlatformRole> allRoles() {
        return List.of(PlatformRole.values());
    }
}
