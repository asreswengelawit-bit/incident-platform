-- ============================================================================
-- V6  Investigation notes, response actions, comments
-- Spec: 6.1 (INVESTIGATION_NOTE, RESPONSE_ACTION, INCIDENT_COMMENT),
--       3.2 FR-2.4/FR-2.5/FR-2.8, 3.3 FR-3.3, 5.5 (Command pattern for
--       response actions), 7.2 property-level authorization, 7.4 (PII
--       minimization).
--
-- NOTE vs COMMENT is a deliberate visibility split, not redundancy:
--   * investigation_note is ANALYST-ONLY. It is the 7.2 property-level example
--     ("a Reporter seeing internal-only fields on their own incident ... e.g.
--     analyst-only investigation notes") and must never appear in a Reporter DTO.
--   * incident_comment is the SHARED channel -- FR-2.8 analysts request
--     additional information from the original Reporter via comment, and
--     FR-1.4 the Reporter follows up on their own report. FR-1.4 also forbids
--     editing the original report after submission, so comments are append-only
--     and corrections are made by adding a further comment (evidentiary
--     integrity).
-- ---------------------------------------------------------------------------

SET search_path TO incident_platform, public;

-- ---------------------------------------------------------------------------
-- INVESTIGATION_NOTE  (FR-2.4: timestamped and attributable to the author)
-- ---------------------------------------------------------------------------
CREATE TABLE investigation_note (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id   uuid        NOT NULL REFERENCES incident (id) ON DELETE CASCADE,
    author_id     uuid        NOT NULL REFERENCES app_user (id),
    note          text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    -- 7.4: notes reach Admin exports (FR-5.3), so PII can be flagged for the
    -- redaction option.
    contains_pii  boolean     NOT NULL DEFAULT false,

    CONSTRAINT ck_investigation_note_not_blank CHECK (length(btrim(note)) > 0)
);

-- ---------------------------------------------------------------------------
-- RESPONSE_ACTION  (FR-2.5: structured action, timestamp, outcome)
-- 5.5 Command pattern: each action is a discrete command object with its own
-- outcome and audit trail, so SOAR automation can later trigger the same
-- commands (Section 13, explicitly out of scope for v1).
--
-- FR-3.3 / 8.2: `Contained -> Resolved` requires at least one Response Action
-- recorded. The COUNT is enforced in the service layer inside the same
-- transaction as the transition (7.10) -- a CHECK constraint cannot reference
-- another table, and a trigger here would fire per-row on insert rather than at
-- the transition boundary.
-- ---------------------------------------------------------------------------
CREATE TABLE response_action (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id   uuid        NOT NULL REFERENCES incident (id) ON DELETE CASCADE,
    action_type   text        NOT NULL,
    description   text,
    outcome       text        NOT NULL,
    performed_by  uuid        NOT NULL REFERENCES app_user (id),
    performed_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT ck_response_action_type_not_blank
        CHECK (length(btrim(action_type)) > 0),
    CONSTRAINT ck_response_action_outcome_not_blank
        CHECK (length(btrim(outcome)) > 0)
);

COMMENT ON COLUMN response_action.action_type IS
    'FR-2.5 structured vocabulary (e.g. "Blocked sender domain", "Reset user credentials", "Isolated endpoint"). Constrained to a known set by the service layer so the Command pattern stays extensible without a migration per new action.';

-- ---------------------------------------------------------------------------
-- INCIDENT_COMMENT  (FR-1.4 reporter follow-up, FR-2.8 analyst request for
-- more information -- the shared, non-internal channel)
-- ---------------------------------------------------------------------------
CREATE TABLE incident_comment (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id   uuid        NOT NULL REFERENCES incident (id) ON DELETE CASCADE,
    author_id     uuid        NOT NULL REFERENCES app_user (id),
    comment       text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    -- 7.4: comments are reporter-facing and are the most likely place for
    -- incidental PII (names, email addresses of third parties in a phishing
    -- report), so they are flagged for the FR-5.3 redaction option.
    contains_pii  boolean     NOT NULL DEFAULT false,

    CONSTRAINT ck_incident_comment_not_blank CHECK (length(btrim(comment)) > 0)
);
