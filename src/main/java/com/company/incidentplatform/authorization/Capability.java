package com.company.incidentplatform.authorization;

import com.company.incidentplatform.security.RolePermissions;

/**
 * Section 7.2 function-level capabilities, each bound to a
 * {@link RolePermissions} flag rather than to a role name.
 *
 * <p>Binding to a data-driven flag is what makes FR-6.2 real: an Admin can grant
 * or revoke a capability by editing {@code platform_role.permissions}, with no
 * code change and no redeploy. Hard-coding {@code if (role == SECURITY_LEAD)}
 * would make the same reconfiguration impossible, and would scatter role
 * knowledge across every endpoint -- the pattern that produces BFLA holes.
 *
 * <p>This is the layer that stops a valid, authenticated user from calling an
 * endpoint their role has no business calling, regardless of which object they
 * name. {@link IncidentObjectAuthorizer} cannot do this: it decides about
 * <em>this</em> incident, and would happily let an Analyst who is assigned
 * incident #7 call a "reassign to any department" endpoint on it.
 */
public enum Capability {

    CREATE_INCIDENT("can_create_incident"),
    UPLOAD_EVIDENCE("can_upload_evidence"),
    VIEW_INCIDENT("can_view_investigation_notes"),
    ADD_INVESTIGATION_NOTE("can_add_investigation_note"),
    ADD_COMMENT("can_comment"),
    RECORD_RESPONSE_ACTION("can_record_response_action"),
    ASSIGN_SELF("can_assign_self"),
    CLASSIFY("can_classify"),
    REASSIGN("can_reassign"),
    ESCALATE("can_escalate"),
    OVERRIDE_SEVERITY("can_override_severity"),
    APPROVE_CLOSURE("can_approve_closure"),
    REOPEN_CLOSED("can_reopen_closed"),
    VIEW_AUDIT_LOG("can_view_audit_log"),
    EXPORT("can_export"),
    INGEST_INCIDENT("can_ingest_incidents"),
    VIEW_REPORTER_IDENTITY("can_view_reporter_identity"),
    MANAGE_USERS("can_manage_users"),
    MANAGE_CATEGORIES("can_manage_categories"),
    MANAGE_SEVERITY_MATRIX("can_manage_severity_matrix"),
    MANAGE_SLA("can_manage_sla"),
    MANAGE_NOTIFICATION_RULES("can_manage_notification_rules"),
    MANAGE_RETENTION("can_manage_retention");

    private final String permissionKey;

    Capability(String permissionKey) {
        this.permissionKey = permissionKey;
    }

    public String permissionKey() {
        return permissionKey;
    }

    /** The audit rule string for this capability, e.g. {@code capability.can_reassign}. */
    public String rule() {
        return "capability." + permissionKey;
    }

    public boolean isHeldBy(RolePermissions permissions) {
        return switch (this) {
            case CREATE_INCIDENT -> permissions.canCreateIncident();
            case UPLOAD_EVIDENCE -> permissions.canUploadEvidence();
            case VIEW_INCIDENT -> permissions.canViewInvestigationNotes();
            case ADD_INVESTIGATION_NOTE -> permissions.canAddInvestigationNote();
            case ADD_COMMENT -> permissions.canComment();
            case RECORD_RESPONSE_ACTION -> permissions.canRecordResponseAction();
            case ASSIGN_SELF -> permissions.canAssignSelf();
            case CLASSIFY -> permissions.canClassify();
            case REASSIGN -> permissions.canReassign();
            case ESCALATE -> permissions.canEscalate();
            case OVERRIDE_SEVERITY -> permissions.canOverrideSeverity();
            case APPROVE_CLOSURE -> permissions.canApproveClosure();
            case REOPEN_CLOSED -> permissions.canReopenClosed();
            case VIEW_AUDIT_LOG -> permissions.canViewAuditLog();
            case EXPORT -> permissions.canExport();
            case INGEST_INCIDENT -> permissions.canIngestIncidents();
            case VIEW_REPORTER_IDENTITY -> permissions.canViewReporterIdentity();
            case MANAGE_USERS -> permissions.canManageUsers();
            case MANAGE_CATEGORIES -> permissions.canManageCategories();
            case MANAGE_SEVERITY_MATRIX -> permissions.canManageSeverityMatrix();
            case MANAGE_SLA -> permissions.canManageSla();
            case MANAGE_NOTIFICATION_RULES -> permissions.canManageNotificationRules();
            case MANAGE_RETENTION -> permissions.canManageRetention();
        };
    }
}
