-- ============================================================================
-- V8  Indexes
-- Spec: 6.3 (indexing strategy), 9.1 (sorting restricted to an allow-list of
--       indexed, sortable columns -- arbitrary/unindexed sort fields are
--       rejected to prevent expensive query plans), 3.5 FR-5.2 / 2.1 FR-2.1
--       (dashboard filters), 4 Performance (<2s dashboard queries at 50k
--       incidents).
--
-- The 6.3-mandated indexes are marked [6.3]. Everything else exists to make a
-- named access pattern in the spec a non-sequential-scan query, and to give
-- 9.1's sort allow-list something valid to point at.
--
-- Note on 6.3 Caching: dashboard/analytics aggregates are to be served from a
-- materialized view refreshed every 1-5 minutes or a Redis cache rather than
-- computed live. That is a Phase 7 concern; the indexes here keep the
-- transactional and detail-query paths fast independently of it.
-- ============================================================================

SET search_path TO incident_platform, public;

-- ---------------------------------------------------------------------------
-- incident -- 6.3 mandated
-- ---------------------------------------------------------------------------

-- [6.3] composite (status, severity, assignee_id): serves the Analyst
-- dashboard's status/severity/assignee filters (FR-2.1) and SLA-breach queries.
CREATE INDEX ix_incident_status_severity_assignee
    ON incident (status, severity, assignee_id);

-- [6.3] (reported_at): date-range filters and reporting-period analytics.
CREATE INDEX ix_incident_reported_at
    ON incident (reported_at DESC);

-- FR-2.1 unassigned-work queue, and 7.10's atomic self-assign
-- (UPDATE ... WHERE id = ? AND assignee_id IS NULL) needs a selective
-- predicate on the unassigned set.
CREATE INDEX ix_incident_unassigned
    ON incident (reported_at DESC)
    WHERE assignee_id IS NULL AND deleted_at IS NULL AND status IN ('NEW', 'TRIAGED');

-- 6.3 sla_due_at exists to make SLA-breach queries cheap; without a partial
-- index the closed majority of the table would still be scanned.
CREATE INDEX ix_incident_sla_due_open
    ON incident (sla_due_at)
    WHERE sla_due_at IS NOT NULL
      AND status NOT IN ('CLOSED', 'REJECTED')
      AND deleted_at IS NULL;

-- 6.3 sanctions exactly ONE deliberate denormalization (sla_due_at). This index
-- supports the Rule-of-Management that an incident is not a member of exactly
-- one group (functional dependency on group_id), without adding a
-- second denormalized column.
CREATE INDEX ix_incident_group_id
    ON incident (group_id)
    WHERE group_id IS NOT NULL;

-- 7.2.1: Lead sees all incidents in the department(s) they lead; 7.12 watches
-- for bulk access to a large number of incidents in a short window.
CREATE INDEX ix_incident_affected_department
    ON incident (affected_department, reported_at DESC)
    WHERE affected_department IS NOT NULL AND deleted_at IS NULL;

-- FR-2.1 category filter, and FR-5.2 "incidents by category".
CREATE INDEX ix_incident_category_id
    ON incident (category_id, reported_at DESC);

-- FR-1.3: a Reporter listing their own submitted incidents.
CREATE INDEX ix_incident_reporter
    ON incident (reporter_id, reported_at DESC);

-- 7.14 / FR-6.5: retention purge must skip anything under legal hold and skip
-- anything not yet past its retention window.
CREATE INDEX ix_incident_retention_scan
    ON incident (reported_at)
    WHERE deleted_at IS NULL AND legal_hold = false;

-- 7.2 property-level: anonymous reports must never be joined to
-- incident_reporter_identity by Analyst-facing queries; this index serves the
-- authorized identity-lookup path instead.
CREATE INDEX ix_incident_anonymous
    ON incident (id)
    WHERE anonymous = true;

-- ---------------------------------------------------------------------------
-- incident_group
-- ---------------------------------------------------------------------------
CREATE INDEX ix_incident_group_active
    ON incident_group (is_active, name);

-- ---------------------------------------------------------------------------
-- incident_collaborator -- 7.2 object-level authorization choke point.
-- Every visibility check consults this; it must not degrade to a scan.
-- ---------------------------------------------------------------------------
CREATE INDEX ix_incident_collaborator_user
    ON incident_collaborator (user_id, incident_id)
    WHERE removed_at IS NULL;

CREATE INDEX ix_incident_collaborator_incident
    ON incident_collaborator (incident_id)
    WHERE removed_at IS NULL;

-- ---------------------------------------------------------------------------
-- incident_status_history -- FR-1.3 timeline, FR-5.1 report timeline.
-- ---------------------------------------------------------------------------
CREATE INDEX ix_incident_status_history_incident
    ON incident_status_history (incident_id, changed_at);

-- ---------------------------------------------------------------------------
-- incident_evidence
-- ---------------------------------------------------------------------------
CREATE INDEX ix_incident_evidence_incident
    ON incident_evidence (incident_id, uploaded_at);

-- 7.6 quarantine alerting to Admin / Security Lead: a partial index keeps the
-- scan off the (large) clean-file population.
CREATE INDEX ix_incident_evidence_quarantined
    ON incident_evidence (uploaded_at DESC)
    WHERE scan_status IN ('QUARANTINED', 'FAILED');

-- Chain-of-custody lookup and duplicate-upload detection.
CREATE INDEX ix_incident_evidence_sha256
    ON incident_evidence (sha256_hash);

-- 7.6: pending scans are the scanner's work queue.
CREATE INDEX ix_incident_evidence_pending_scan
    ON incident_evidence (uploaded_at)
    WHERE scan_status IN ('PENDING', 'SCANNING');

-- ---------------------------------------------------------------------------
-- investigation_note / response_action / incident_comment
-- ---------------------------------------------------------------------------
CREATE INDEX ix_investigation_note_incident
    ON investigation_note (incident_id, created_at);

CREATE INDEX ix_investigation_note_author
    ON investigation_note (author_id, created_at DESC);

CREATE INDEX ix_response_action_incident
    ON response_action (incident_id, performed_at);

CREATE INDEX ix_incident_comment_incident
    ON incident_comment (incident_id, created_at);

-- ---------------------------------------------------------------------------
-- audit_log -- 6.3 mandated.
--
-- On a partitioned table these propagate to every existing partition and to
-- partitions created later by create_audit_log_partition().
-- ---------------------------------------------------------------------------

-- [6.3] "show history of this record" view. Leading with entity_type and
-- entity_id lets PostgreSQL prune partitions by the timestamp bound as well.
CREATE INDEX ix_audit_log_entity
    ON audit_log (entity_type, entity_id, timestamp DESC);

-- [6.3] "show everything this user did" -- used both in investigations and in
-- periodic access reviews.
CREATE INDEX ix_audit_log_actor
    ON audit_log (actor_id, timestamp DESC);

-- 7.11/7.12: IDOR/BOLA probing shows up as repeated DENIED events against
-- sequential entity IDs by one actor. Without this index that detection query
-- is a sequential scan of the fastest-growing table in the system.
CREATE INDEX ix_audit_log_denied
    ON audit_log (actor_id, timestamp DESC)
    WHERE result = 'DENIED';

-- 7.12 bulk export/download activity alerting.
CREATE INDEX ix_audit_log_action_time
    ON audit_log (action, timestamp DESC);

-- ---------------------------------------------------------------------------
-- app_user -- 7.2.1 department scoping and 7.1 account lifecycle.
-- ---------------------------------------------------------------------------
CREATE INDEX ix_app_user_department
    ON app_user (department)
    WHERE active = true;

CREATE INDEX ix_app_user_role_active
    ON app_user (role_id)
    WHERE active = true;

-- 7.1 dormant-account detection (configurable inactivity period, e.g. 90 days)
-- over last_login_at, restricted to accounts still eligible for auto-disable.
CREATE INDEX ix_app_user_dormant_candidates
    ON app_user (last_login_at)
    WHERE active = true;

-- ---------------------------------------------------------------------------
-- Configuration tables -- small, but the uniqueness/lookup predicates the
-- service layer relies on still need to be explicit rather than incidental.
-- ---------------------------------------------------------------------------
CREATE INDEX ix_incident_sla_policy_lookup
    ON incident_sla_policy (severity, category_id)
    WHERE is_active;

CREATE INDEX ix_severity_matrix_rule_active
    ON severity_matrix_rule (impact, likelihood)
    WHERE is_active;
