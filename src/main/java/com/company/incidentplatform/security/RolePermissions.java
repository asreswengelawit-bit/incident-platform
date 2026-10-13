package com.company.incidentplatform.security;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Section 6.2.3 -- the fine-grained, business-specific authorization detail that
 * Keycloak does not model, read from {@code platform_role.permissions}.
 *
 * <p>This is the ONLY place capability flags live. Nothing in the codebase
 * branches on a hard-coded role name to decide what a role may do; it branches
 * on these flags. That is what lets FR-6.2 Admin configuration change behaviour
 * without a code change, and it is what stops a new capability from having to
 * be threaded through every authorisation check.
 *
 * <p>Every flag defaults to {@code false} when absent. Defaulting to permissive
 * would mean a typo in a role's JSON silently grants a capability.
 *
 * <p>Immutable and thread-safe.
 */
public final class RolePermissions {

    private final VisibilityScope visibilityScope;
    private final VisibilityScope unassignedVisibility;
    private final Set<String> ledDepartments;
    private final boolean createIncident;
    private final boolean viewInvestigationNotes;
    private final boolean addInvestigationNote;
    private final boolean comment;
    private final boolean recordResponseAction;
    private final boolean assignSelf;
    private final boolean classify;
    private final boolean reassign;
    private final boolean escalate;
    private final boolean overrideSeverity;
    private final boolean approveClosure;
    private final boolean reopenClosed;
    private final boolean readOnly;
    private final boolean uploadEvidence;
    private final boolean viewAuditLog;
    private final boolean export;
    private final boolean ingestIncidents;
    private final boolean viewReporterIdentity;
    private final boolean manageUsers;
    private final boolean manageCategories;
    private final boolean manageSeverityMatrix;
    private final boolean manageSla;
    private final boolean manageNotificationRules;
    private final boolean manageRetention;

    private RolePermissions(Builder b) {
        this.visibilityScope = b.visibilityScope;
        this.unassignedVisibility = b.unassignedVisibility;
        this.ledDepartments = Collections.unmodifiableSet(new LinkedHashSet<>(b.ledDepartments));
        this.createIncident = b.createIncident;
        this.viewInvestigationNotes = b.viewInvestigationNotes;
        this.addInvestigationNote = b.addInvestigationNote;
        this.comment = b.comment;
        this.recordResponseAction = b.recordResponseAction;
        this.assignSelf = b.assignSelf;
        this.classify = b.classify;
        this.reassign = b.reassign;
        this.escalate = b.escalate;
        this.overrideSeverity = b.overrideSeverity;
        this.approveClosure = b.approveClosure;
        this.reopenClosed = b.reopenClosed;
        this.readOnly = b.readOnly;
        this.uploadEvidence = b.uploadEvidence;
        this.viewAuditLog = b.viewAuditLog;
        this.export = b.export;
        this.ingestIncidents = b.ingestIncidents;
        this.viewReporterIdentity = b.viewReporterIdentity;
        this.manageUsers = b.manageUsers;
        this.manageCategories = b.manageCategories;
        this.manageSeverityMatrix = b.manageSeverityMatrix;
        this.manageSla = b.manageSla;
        this.manageNotificationRules = b.manageNotificationRules;
        this.manageRetention = b.manageRetention;
    }

    /**
     * Parses {@code platform_role.permissions}. A null or non-object node yields
     * an all-deny instance: a role row with missing configuration must not
     * become a role with implicit authority.
     */
    public static RolePermissions fromJson(JsonNode node) {
        Builder b = new Builder();
        if (node == null || !node.isObject()) {
            return b.build();
        }
        b.visibilityScope = VisibilityScope.fromKey(text(node, "visibility_scope"));
        b.unassignedVisibility = VisibilityScope.fromKey(text(node, "unassigned_visibility"));
        b.ledDepartments = stringSet(node, "led_departments");

        b.viewInvestigationNotes = flag(node, "can_view_investigation_notes");
        b.createIncident = flag(node, "can_create_incident");
        b.addInvestigationNote = flag(node, "can_add_investigation_note");
        b.comment = flag(node, "can_comment");
        b.recordResponseAction = flag(node, "can_record_response_action");
        b.assignSelf = flag(node, "can_assign_self");
        b.classify = flag(node, "can_classify");
        b.reassign = flag(node, "can_reassign");
        b.escalate = flag(node, "can_escalate");
        b.overrideSeverity = flag(node, "can_override_severity");
        b.approveClosure = flag(node, "can_approve_closure");
        b.reopenClosed = flag(node, "can_reopen_closed");
        b.readOnly = flag(node, "read_only");
        // V10 seeded the narrower `can_upload_evidence_on_own_incident` for the
        // Reporter role; V13 adds the function-level `can_upload_evidence` this
        // codebase checks. The V10 key is retained, not replaced -- see
        // EvidenceUploadCapability. Reading both would let a role be granted one
        // spelling and silently denied on the other.
        b.uploadEvidence = flag(node, "can_upload_evidence")
                || flag(node, "can_upload_evidence_on_own_incident");
        b.viewAuditLog = flag(node, "can_view_audit_log");
        b.export = flag(node, "can_export");
        b.ingestIncidents = flag(node, "can_ingest_incidents");
        b.viewReporterIdentity = flag(node, "can_view_reporter_identity");
        b.manageUsers = flag(node, "can_manage_users");
        b.manageCategories = flag(node, "can_manage_categories");
        b.manageSeverityMatrix = flag(node, "can_manage_severity_matrix");
        b.manageSla = flag(node, "can_manage_sla");
        b.manageNotificationRules = flag(node, "can_manage_notification_rules");
        b.manageRetention = flag(node, "can_manage_retention");
        return b.build();
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return (v == null || v.isNull()) ? null : v.asText();
    }

    private static boolean flag(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v != null && v.isBoolean() && v.asBoolean();
    }

    private static Set<String> stringSet(JsonNode node, String field) {
        JsonNode v = node.get(field);
        if (v == null || !v.isArray()) {
            return Set.of();
        }
        Set<String> out = new LinkedHashSet<>();
        v.forEach(n -> {
            if (n.isTextual() && !n.asText().isBlank()) {
                out.add(n.asText());
            }
        });
        return out;
    }

    public VisibilityScope visibilityScope() {
        return visibilityScope;
    }

    public VisibilityScope unassignedVisibility() {
        return unassignedVisibility;
    }

    public Set<String> ledDepartments() {
        return ledDepartments;
    }

    public boolean canViewInvestigationNotes() {
        return viewInvestigationNotes;
    }

    /**
     * FR-1.1 / Section 2: intake. A Reporter is "any authenticated user of the
     * organization", so this is the Platform's purpose rather than a privilege --
     * but it is still an explicit, grantable flag, because a Service Account that
     * may ingest and a role that may not are different trust decisions.
     */
    public boolean canCreateIncident() {
        return createIncident;
    }

    /**
     * FR-2.4: writing an investigation note. Kept distinct from
     * {@link #canViewInvestigationNotes()} because 7.2 separates function level
     * ("may this role add to the record") from property level ("may this role
     * read the record"), and a single flag cannot express both. An Auditor, for
     * example, reads notes for review and writes none.
     */
    public boolean canAddInvestigationNote() {
        return addInvestigationNote;
    }

    /**
     * FR-1.4 / FR-2.8: the shared two-way channel between a Reporter and the
     * investigating team. Deliberately <em>not</em> gated on
     * {@code can_view_investigation_notes}, because comments are the one
     * investigation artefact a Reporter is entitled to see and reply to.
     */
    public boolean canComment() {
        return comment;
    }

    public boolean canRecordResponseAction() {
        return recordResponseAction;
    }

    public boolean canAssignSelf() {
        return assignSelf;
    }

    public boolean canClassify() {
        return classify;
    }

    public boolean canReassign() {
        return reassign;
    }

    public boolean canEscalate() {
        return escalate;
    }

    public boolean canOverrideSeverity() {
        return overrideSeverity;
    }

    public boolean canApproveClosure() {
        return approveClosure;
    }

    public boolean canReopenClosed() {
        return reopenClosed;
    }

    public boolean isReadOnly() {
        return readOnly;
    }

    /**
     * FR-1.2 / Section 9: attaching evidence to an incident.
     *
     * <p>This is the <em>function</em>-level half of 7.6's upload control: may
     * this role call the upload endpoint at all. Which incidents it may then be
     * called against is decided separately, by 7.2.1 object level -- a Reporter
     * holding this flag is still confined to their own submissions, because
     * {@code IncidentObjectAuthorizer} never consults it.
     *
     * <p>Deliberately one flag rather than separate "own" and "any" spellings.
     * Two flags would make the scope an accident of which key a role happened to
     * be granted, and the narrower of the two would be the one nobody tests.
     */
    public boolean canUploadEvidence() {
        return uploadEvidence;
    }

    public boolean canViewAuditLog() {
        return viewAuditLog;
    }

    public boolean canExport() {
        return export;
    }

    public boolean canIngestIncidents() {
        return ingestIncidents;
    }

    /**
     * FR-1.6: gates access to the real identity behind an anonymous report.
     * Confirmed decision -- this is a grantable permission, not bound to a
     * specific role. Seeded as granted to NOBODY at deployment; a Security
     * Administrator grants it explicitly when there is a need, and every
     * exercise of it is separately audited.
     */
    public boolean canViewReporterIdentity() {
        return viewReporterIdentity;
    }

    public boolean canManageUsers() {
        return manageUsers;
    }

    public boolean canManageCategories() {
        return manageCategories;
    }

    public boolean canManageSeverityMatrix() {
        return manageSeverityMatrix;
    }

    public boolean canManageSla() {
        return manageSla;
    }

    public boolean canManageNotificationRules() {
        return manageNotificationRules;
    }

    public boolean canManageRetention() {
        return manageRetention;
    }

    private static final class Builder {
        private VisibilityScope visibilityScope = VisibilityScope.NONE;
        private VisibilityScope unassignedVisibility = VisibilityScope.NONE;
        private Set<String> ledDepartments = Set.of();
        private boolean createIncident;
        private boolean viewInvestigationNotes;
        private boolean addInvestigationNote;
        private boolean comment;
        private boolean recordResponseAction;
        private boolean assignSelf;
        private boolean classify;
        private boolean reassign;
        private boolean escalate;
        private boolean overrideSeverity;
        private boolean approveClosure;
        private boolean reopenClosed;
        private boolean readOnly;
        private boolean uploadEvidence;
        private boolean viewAuditLog;
        private boolean export;
        private boolean ingestIncidents;
        private boolean viewReporterIdentity;
        private boolean manageUsers;
        private boolean manageCategories;
        private boolean manageSeverityMatrix;
        private boolean manageSla;
        private boolean manageNotificationRules;
        private boolean manageRetention;

        RolePermissions build() {
            return new RolePermissions(this);
        }
    }
}
