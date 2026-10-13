-- ============================================================================
-- V4  Incident core: groups, the incident aggregate, collaborators, status
--      history, and the restricted reporter-identity record
-- Spec: 6.1 (INCIDENT), 3.1 FR-1.1/FR-1.2/FR-1.6, 3.2 FR-2.3/FR-2.6/FR-2.7,
--       3.3 FR-3.3, 5.4 (idempotent ingestion), 6.2 (group_id, soft delete),
--       6.3 (sla_due_at denormalization), 7.2.1 (explicit share / explicit
--       grouping as the routes to cross-department visibility), 7.10 (optimistic
--       locking).
-- ============================================================================

SET search_path TO incident_platform, public;

-- ---------------------------------------------------------------------------
-- INCIDENT_GROUP  (resolved Phase-1 decision #2)
-- ER 6.1 declares INCIDENT.group_id as a FK but defines no group entity,
-- drawing the relationship instead as a self-referencing "grouped/related".
-- Confirmed decision: a dedicated table, so group_id resolves to a real
-- campaign with FR-2.6 metadata, and so 7.2.1's "the incident being explicitly
-- ... grouped" cross-department rule keys off a concrete, auditable object
-- rather than a recursive adjacency walk on every visibility check.
-- ---------------------------------------------------------------------------
CREATE TABLE incident_group (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text        NOT NULL,
    description  text,
    created_by   uuid        NOT NULL REFERENCES app_user (id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    is_active    boolean     NOT NULL DEFAULT true,

    CONSTRAINT uq_incident_group_name UNIQUE (name),
    CONSTRAINT ck_incident_group_name_not_blank CHECK (length(btrim(name)) > 0)
);

CREATE TRIGGER trg_incident_group_updated_at
    BEFORE UPDATE ON incident_group
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- INCIDENT
-- ER 6.1: id, title, description, category_id, severity, status, reporter_id,
--          assignee_id, occurred_at, reported_at, resolved_at, group_id,
--          escalated, escalated_at, escalation_reason.
--
-- Columns beyond the ER are each traceable to an explicit requirement; see the
-- Phase 1 summary for the full mapping. The status/escalation CHECK constraints
-- below encode 8.1/8.2 invariants at the database level so an invalid lifecycle
-- state is unrepresentable, not merely rejected by the service layer.
-- ---------------------------------------------------------------------------
CREATE TABLE incident (
    id                          uuid              PRIMARY KEY DEFAULT gen_random_uuid(),
    title                       text              NOT NULL,
    description                 text              NOT NULL,
    category_id                 uuid              NOT NULL REFERENCES incident_category (id),
    -- FR-1.1 severity is SELF-ASSESSED AND OPTIONAL, so it is nullable. The
    -- 8.2 matrix makes "Analyst classifies" the New -> Triaged step, so by the
    -- time an incident leaves NEW it must be classified.
    severity                    incident_severity,
    status                      incident_status   NOT NULL DEFAULT 'NEW',
    reporter_id                 uuid              NOT NULL REFERENCES app_user (id),
    assignee_id                 uuid              REFERENCES app_user (id),
    occurred_at                 timestamptz       NOT NULL,
    reported_at                 timestamptz       NOT NULL DEFAULT now(),
    resolved_at                 timestamptz,
    group_id                    uuid              REFERENCES incident_group (id),
    -- FR-2.7 / 8.1: escalation is an ATTRIBUTE, not a status. It raises
    -- severity, sets these fields, and notifies the Security Lead, while
    -- `status` continues unchanged (most commonly staying INVESTIGATING).
    escalated                   boolean           NOT NULL DEFAULT false,
    escalated_at                timestamptz,
    escalation_reason           text,

    -- ---- beyond ER 6.1, each traceable to a requirement -------------------
    -- 5.4: synchronous REST ingestion carries an idempotency key so a SIEM or
    -- email gateway can retry a timed-out POST /api/v1/incidents without
    -- creating a duplicate incident.
    idempotency_key             text,
    -- 5.4 / 2: System / Service Account automated ingestion path.
    source                      incident_source   NOT NULL DEFAULT 'WEB_UI',
    -- FR-1.6: anonymous / whistleblower mode. The flag, not a NULL reporter,
    -- is what drives property-level suppression (see incident_reporter_identity).
    anonymous                   boolean           NOT NULL DEFAULT false,
    -- 7.4 PII minimization: flagged in the schema to support redaction in
    -- FR-5.3 exports and eventual data-subject requests.
    contains_pii                boolean           NOT NULL DEFAULT false,
    -- FR-1.1 "date/time of occurrence, location/system affected" and FR-5.2
    -- "top affected departments/systems". No home for these in ER 6.1.
    affected_system             text,
    affected_department         text,
    -- 7.2 property-level example: "internal severity override rationale" is
    -- analyst-only and must never reach a Reporter's DTO.
    severity_overridden_by      uuid              REFERENCES app_user (id),
    severity_override_reason    text,
    -- FR-3.3: closure requires a resolution summary.
    resolution_summary          text,
    resolved_by                 uuid              REFERENCES app_user (id),
    -- 8.2: Triaged -> Rejected requires a rejection reason.
    rejected_reason             text,
    closed_at                   timestamptz,
    closed_by                   uuid              REFERENCES app_user (id),
    -- 6.3: the one sanctioned denormalization -- computed at assignment time
    -- from category + severity so SLA-breach dashboard queries avoid a join.
    -- Recalculated (and the recalculation audited) on category/severity change.
    sla_response_due_at         timestamptz,
    sla_due_at                  timestamptz,
    -- 7.14 / FR-6.5: legal hold overrides the category retention policy.
    legal_hold                  boolean           NOT NULL DEFAULT false,
    legal_hold_reason           text,
    legal_hold_set_at           timestamptz,
    -- 6.2 soft delete over hard delete for audit-relevant data.
    deleted_at                  timestamptz,
    -- 7.10 optimistic locking: two analysts editing the same incident must
    -- produce a clear "this incident changed, please refresh" rather than a
    -- silent lost update.
    version                     integer           NOT NULL DEFAULT 0,

    CONSTRAINT ck_incident_title_not_blank CHECK (length(btrim(title)) > 0),
    CONSTRAINT ck_incident_description_not_blank CHECK (length(btrim(description)) > 0),
    CONSTRAINT ck_incident_version CHECK (version >= 0),

    -- FR-2.7 / 8.1: escalated=true if and only if escalated_at is set, and an
    -- escalation must carry a reason. Never a status value.
    CONSTRAINT ck_incident_escalation_consistent CHECK (
        (escalated AND escalated_at IS NOT NULL AND length(btrim(escalation_reason)) > 0)
        OR (NOT escalated AND escalated_at IS NULL)
    ),

    -- 8.2: `New -> Triaged` is "Analyst classifies", so classification is
    -- mandatory from TRIAGED onward.
    CONSTRAINT ck_incident_classified_past_new
        CHECK (status = 'NEW' OR severity IS NOT NULL),

    -- 8.2: Triaged -> Assigned requires "Assignee must be an active Analyst".
    -- Active-ness is a Keycloak/app_user property enforced at the service
    -- layer; the presence of an assignee is enforced here.
    CONSTRAINT ck_incident_assignee_present
        CHECK (status NOT IN ('ASSIGNED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED')
               OR assignee_id IS NOT NULL),

    -- FR-3.3 / 8.2: Resolved requires a resolution summary, and Closed
    -- requires resolution metadata plus the approver who gave sign-off.
    CONSTRAINT ck_incident_resolution_summary
        CHECK (status NOT IN ('RESOLVED', 'CLOSED') OR length(btrim(resolution_summary)) > 0),
    CONSTRAINT ck_incident_resolved_timestamp
        CHECK (status NOT IN ('RESOLVED', 'CLOSED') OR resolved_at IS NOT NULL),
    CONSTRAINT ck_incident_closed_signoff
        CHECK (status <> 'CLOSED' OR (closed_at IS NOT NULL AND closed_by IS NOT NULL)),

    -- 8.2: Triaged -> Rejected requires a rejection reason.
    CONSTRAINT ck_incident_rejected_reason
        CHECK (status <> 'REJECTED' OR length(btrim(rejected_reason)) > 0),

    -- 7.2 property-level: override rationale is either wholly absent or
    -- attributed to the analyst who set it.
    CONSTRAINT ck_incident_severity_override_attribution CHECK (
        (severity_overridden_by IS NULL AND severity_override_reason IS NULL)
        OR (severity_overridden_by IS NOT NULL AND length(btrim(severity_override_reason)) > 0)
    ),

    -- 7.14: legal hold must be attributable and reasoned.
    CONSTRAINT ck_incident_legal_hold_consistent CHECK (
        (legal_hold AND legal_hold_set_at IS NOT NULL AND length(btrim(legal_hold_reason)) > 0)
        OR (NOT legal_hold AND legal_hold_set_at IS NULL)
    )
);

COMMENT ON COLUMN incident.escalated IS
    'FR-2.7 / 8.1: escalation is an event/attribute, NOT a lifecycle status. An escalated incident has not stopped being investigated -- status continues to move through the normal lifecycle. Never add ESCALATED to the incident_status enum.';

COMMENT ON COLUMN incident.affected_department IS
    'FR-1.1. 7.2.1 department scoping resolves against this when present, falling back to the reporter''s app_user.department when null -- the exact precedence is a Phase 3 decision.';

COMMENT ON COLUMN incident.sla_due_at IS
    '6.3 sanctioned denormalization, derived from category + severity at assignment time. NULL until an Admin configures a resolution SLA (Section 12 defines response SLA only). Recalculation on category/severity change is itself audited.';

-- 5.4: at-most-once creation per ingestion idempotency key. Manual web reports
-- leave it NULL, which PostgreSQL treats as distinct under a unique index.
CREATE UNIQUE INDEX uq_incident_idempotency_key
    ON incident (idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- ---------------------------------------------------------------------------
-- INCIDENT_COLLABORATOR  (resolved Phase-1 decision #3)
-- FR-2.3 requires "optional additional collaborators", and 7.2.1 makes an
-- incident being "explicitly shared" one of only two routes to
-- cross-department visibility. Neither is expressible in ER 6.1, so this is
-- additive. It is the join target for 7.2 object-level authorization, which
-- must not degrade into a JSON scan.
-- ---------------------------------------------------------------------------
CREATE TABLE incident_collaborator (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id uuid        NOT NULL REFERENCES incident (id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL REFERENCES app_user (id),
    added_by    uuid        NOT NULL REFERENCES app_user (id),
    added_at    timestamptz NOT NULL DEFAULT now(),
    removed_at  timestamptz,

    -- 7.3 maker-checker: a user cannot add themselves as a collaborator, which
    -- would let a single identity manufacture the cross-department visibility
    -- that 7.2.1 reserves for a Lead/Admin action.
    CONSTRAINT ck_incident_collaborator_not_self CHECK (user_id <> added_by)
);

-- A user may hold at most one live collaboration per incident; re-adding after
-- removal is allowed and produces a new row.
CREATE UNIQUE INDEX uq_incident_collaborator_active
    ON incident_collaborator (incident_id, user_id)
    WHERE removed_at IS NULL;

-- ---------------------------------------------------------------------------
-- INCIDENT_STATUS_HISTORY
-- FR-1.3 (Reporter views "the status and timeline" of their own incidents) and
-- FR-5.1 (per-incident report summarizing the timeline) both need a status
-- trail that a Reporter can read WITHOUT audit-log access -- audit-log read is
-- restricted to Admin/Auditor by 7.11. Reusing AUDIT_LOG for this would either
-- over-expose audit data or require Reporter-visible audit reads, so the
-- lifecycle trail is a first-class table and AUDIT_LOG remains the
-- administrative/security record.
--
-- Also the durable evidence for 7.10's "state transitions and their side
-- effects execute within a single database transaction".
-- ---------------------------------------------------------------------------
CREATE TABLE incident_status_history (
    id           uuid            PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id  uuid            NOT NULL REFERENCES incident (id) ON DELETE CASCADE,
    from_status  incident_status,
    to_status    incident_status NOT NULL,
    changed_by   uuid            REFERENCES app_user (id),
    changed_at   timestamptz    NOT NULL DEFAULT now(),
    -- 8.2 requires a reason for Rejected and for either Reopened edge.
    reason       text,
    -- 7.11: ties the lifecycle trail to the audit entry for the same action.
    request_id   uuid
);

-- ---------------------------------------------------------------------------
-- INCIDENT_REPORTER_IDENTITY  (FR-1.6, additive to ER 6.1)
-- FR-1.6 requires that reporter_id, EMAIL, IP ADDRESS and BROWSER/USER-AGENT
-- are retained internally (legal/HR escalation, abuse prevention) while being
-- withheld from Analysts and Leads -- and that access to that identity is a
-- distinct, separately-audited action. ER 6.1 has reporter_id on INCIDENT but
-- no home for the contact/technical metadata, so it is isolated here.
--
-- This table is the designated data-minimization boundary: Analysts/Leads reach
-- incidents without ever joining to it, and the identity-viewing action writes
-- its own AUDIT_LOG row ("identity of anonymous report #X viewed by Y").
-- ---------------------------------------------------------------------------
CREATE TABLE incident_reporter_identity (
    incident_id            uuid            PRIMARY KEY REFERENCES incident (id) ON DELETE CASCADE,
    reporter_id            uuid            REFERENCES app_user (id),
    reporter_email         text,
    reporter_ip            inet,
    reporter_user_agent    text,
    source_channel         incident_source NOT NULL DEFAULT 'WEB_UI',
    created_at             timestamptz    NOT NULL DEFAULT now(),
    -- Convenience denormalization of the LAST identity view. The authoritative
    -- record of every such access is the AUDIT_LOG entry required by FR-1.6 /
    -- 7.11 -- these columns exist so an abuse investigation can spot a pattern
    -- without scanning the partitioned audit table.
    identity_accessed_at   timestamptz,
    identity_accessed_by   uuid            REFERENCES app_user (id)
);

COMMENT ON TABLE incident_reporter_identity IS
    'FR-1.6 restricted identity store. Never joined by Analyst/Lead-facing queries, never serialized into an API DTO, and never included in CSV/Excel exports, Slack/email notifications, or webhook payloads (FR-1.6). Access is gated by platform_role.permissions->can_view_anonymous_identity and every access is separately audited.';
