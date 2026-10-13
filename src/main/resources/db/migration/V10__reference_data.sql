-- ============================================================================
-- V10 Reference data
-- Spec: 2 (role list), 6.1 (ROLE), 6.2.1/6.2.3 (coarse role from Keycloak;
--       fine-grained department scoping in ROLE.permissions), 7.2.1
--       (department-scoped visibility table), 7.11 (audit-log read access is
--       Admin + Auditor), FR-1.6 (who may view an anonymous report's identity),
--       FR-6.2 (SLA targets per severity), 12 (target response SLA per
--       severity).
--
-- These are the coarse-role ROWS only. Per 6.2.4 they are the application's
-- synced projection of Keycloak realm roles -- changing a user's role happens
-- in Keycloak (or via an admin UI that writes through to Keycloak), never by
-- editing these rows.
--
-- incident_category and severity_matrix_rule are deliberately NOT seeded. Both
-- are stakeholder content: Section 12 defines severity DEFINITIONS and response
-- SLAs but no category list and no impact x likelihood grid. See the Phase 1
-- summary -- inventing either would be a silent deviation.
-- ============================================================================

SET search_path TO incident_platform, public;

-- ---------------------------------------------------------------------------
-- Platform roles.
--
-- `visibility_scope` encodes 7.2.1 verbatim, per your confirmed decision to
-- implement it as written (no org-wide blanket visibility for Analysts):
--   REPORTER  -> OWN_INCIDENTS
--   ANALYST   -> ASSIGNED_AND_OWN_DEPARTMENT_UNASSIGNED  (not org-wide)
--   LEAD      -> LED_DEPARTMENTS
--   ADMIN     -> ORGANIZATION
--   AUDITOR   -> ORGANIZATION (read-only)
--
-- `led_departments` is the resolution of 7.2.1's "the department(s) they lead"
-- (plural), which a single app_user.department column cannot express. It
-- defaults to EMPTY, so a Security Lead sees nothing until an Admin populates
-- it. That is the safe direction: an unconfigured Lead under- rather than
-- over-sees.
-- ---------------------------------------------------------------------------
INSERT INTO platform_role (name, display_name, permissions) VALUES
(
    'REPORTER',
    'Reporter (Employee)',
    '{
        "visibility_scope": "OWN_INCIDENTS",
        "can_upload_evidence_on_own_incident": true,
        "can_comment_on_own_incident": true,
        "can_view_investigation_notes": false,
        "can_view_audit_log": false,
        "can_export": false,
        "can_view_reporter_identity": false
    }'::jsonb
),
(
    'ANALYST',
    'Security Analyst',
    '{
        "visibility_scope": "ASSIGNED_AND_OWN_DEPARTMENT_UNASSIGNED",
        "unassigned_visibility": "OWN_DEPARTMENT",
        "can_view_investigation_notes": true,
        "can_record_response_action": true,
        "can_assign_self": true,
        "can_classify": true,
        "can_view_audit_log": false,
        "can_export": false,
        "can_view_reporter_identity": false
    }'::jsonb
),
(
    'SECURITY_LEAD',
    'Security Lead / Officer',
    '{
        "visibility_scope": "LED_DEPARTMENTS",
        "led_departments": [],
        "can_view_investigation_notes": true,
        "can_reassign": true,
        "can_escalate": true,
        "can_override_severity": true,
        "can_approve_closure": true,
        "can_reopen_closed": true,
        "can_export": true,
        "can_view_audit_log": false,
        "can_view_reporter_identity": false
    }'::jsonb
),
(
    'SECURITY_ADMIN',
    'Security Administrator',
    '{
        "visibility_scope": "ORGANIZATION",
        "can_manage_users": true,
        "can_manage_categories": true,
        "can_manage_severity_matrix": true,
        "can_manage_sla": true,
        "can_manage_notification_rules": true,
        "can_manage_retention": true,
        "can_view_audit_log": true,
        "can_export": true,
        "can_view_reporter_identity": true
    }'::jsonb
),
(
    'AUDITOR',
    'Auditor (read-only)',
    '{
        "visibility_scope": "ORGANIZATION",
        "read_only": true,
        "can_view_investigation_notes": true,
        "can_view_audit_log": true,
        "can_export": true,
        "can_view_reporter_identity": false
    }'::jsonb
),
(
    'SERVICE_ACCOUNT',
    'System / Service Account',
    '{
        "visibility_scope": "NONE",
        "can_ingest_incidents": true,
        "can_view_audit_log": false,
        "can_export": false
    }'::jsonb
)
ON CONFLICT (name) DO NOTHING;

-- ---------------------------------------------------------------------------
-- SLA policies -- organization-wide defaults (category_id NULL), response SLA
-- taken verbatim from Section 12:
--     Critical 15 min, High 1 hour, Medium 4 hours, Low 1 business day.
--
-- resolution_sla_minutes is LEFT NULL. Section 12 specifies only a "Target
-- Response SLA"; resolution targets are not defined anywhere in the document.
-- Until stakeholders supply them, incident.sla_due_at has no resolution
-- component and FR-3.3's closure gate relies on the response SLA and the
-- >= 1 Response Action rule rather than on a resolution deadline.
-- ---------------------------------------------------------------------------
INSERT INTO incident_sla_policy (
    category_id, severity, response_sla_minutes, resolution_sla_minutes, business_hours_only
) VALUES
    (NULL, 'CRITICAL', 15,   NULL, false),
    (NULL, 'HIGH',     60,   NULL, false),
    (NULL, 'MEDIUM',   240,  NULL, false),
    (NULL, 'LOW',      1440, NULL, true)
ON CONFLICT DO NOTHING;
