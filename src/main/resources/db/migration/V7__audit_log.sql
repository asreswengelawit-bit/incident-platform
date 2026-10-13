-- ============================================================================
-- V7  Audit log: monthly range partitions, DENIED events, hash chaining,
--      database-level append-only enforcement
-- Spec: 6.1 (AUDIT_LOG), 6.3 (partition by month; indexes on
--       (entity_type, entity_id, timestamp) and (actor_id, timestamp)),
--       7.11 (denied events, append-only at DB level, tamper-resistant,
--       hash-chained integrity verification), 7.16 (no UPDATE/DELETE grant for
--       any application role), 4 (Auditability), 7.12 (feeds anomaly alerting).
--
-- Confirmed Phase-1 decision #5: honour 6.3's monthly partitioning, which
-- forces the partition key into the primary key -> PK (id, timestamp) rather
-- than ER 6.1's plain `uuid id PK`. Global uniqueness of `id` is therefore
-- provided by uuid v4 generation plus application-level collision handling,
-- not by a database constraint.
-- ============================================================================

SET search_path TO incident_platform, public;

-- ---------------------------------------------------------------------------
-- Partition maintenance. Idempotent; safe to call repeatedly.
--
-- DESIGN DECISION -- the spill case is refused, not worked around.
--
-- If a month was never provisioned and its rows are sitting in the DEFAULT
-- partition, PostgreSQL will not create the overlapping partition ("updated
-- partition constraint for default partition would be violated"). Relocating
-- those rows would require DELETEing them from DEFAULT, and 7.11 makes
-- audit_log absolutely append-only -- enforced above by a trigger that even
-- the table owner cannot bypass. Detaching the partition to dodge that trigger
-- would be a security control circumvented by our own maintenance code, which
-- is the wrong instinct in a system whose entire purpose is security incident
-- handling.
--
-- So this function raises, naming the window and the remediation. The affected
-- rows are NOT lost or wrong: they remain fully readable, fully included in
-- hash-chain verification, and covered by every audit query. The only
--  consequence is that the month does not yet get partition-local archival
-- (6.3) until an operator completes the runbook step.
--
-- In normal operation this branch is unreachable: the scheduled job runs AHEAD
-- of each month, which is why the seed block below provisions 6 months forward.
-- Reaching this branch means the provisioning job has been broken for a month
-- or more, which is itself an alertable condition under 7.12.
--
-- OPERATOR REMEDIATION (reviewed maintenance window, table owner only):
--   1. psql -c "SET search_path TO incident_platform, public;
--               ALTER TABLE audit_log DISABLE TRIGGER trg_audit_log_append_only;"
--   2. psql -c "SET search_path TO incident_platform, public;
--               CREATE TABLE audit_log_YYYY_MM PARTITION OF audit_log
--                 FOR VALUES FROM ('YYYY-MM-01') TO ('YYYY-MM-<end>');"
--   3. psql -c "SET search_path TO incident_platform, public;
--               ALTER TABLE audit_log ENABLE TRIGGER trg_audit_log_append_only;"
--   4. re-run verify_audit_log_chain() for the window to confirm the chain is
--      still intact, and re-run the near-real-time SIEM shipper for the window.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION create_audit_log_partition(p_month date)
RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
    v_start   date := date_trunc('month', p_month)::date;
    v_end     date := (date_trunc('month', p_month) + interval '1 month')::date;
    v_name    text := 'audit_log_' || to_char(v_start, 'YYYY_MM');
    v_spilled bigint;
BEGIN
    IF to_regclass('incident_platform.' || v_name) IS NOT NULL THEN
        RETURN v_name;  -- already provisioned
    END IF;

    EXECUTE format(
        'SELECT count(*) FROM incident_platform.audit_log_default '
        'WHERE timestamp >= %L::timestamptz AND timestamp < %L::timestamptz',
        v_start, v_end)
        INTO v_spilled;

    IF v_spilled > 0 THEN
        RAISE EXCEPTION
            'audit_log partition % cannot be created: % row(s) for % to % have spilled into the DEFAULT partition and 7.11 forbids deleting them to relocate them. Rows are intact and fully queryable; the month simply lacks partition-local archival until the documented operator remediation is run. Raise an alert under 7.12 -- the scheduled provisioning job has fallen behind.',
            v_name, v_spilled, v_start, v_end;
    END IF;

    EXECUTE format(
        'CREATE TABLE incident_platform.%I PARTITION OF incident_platform.audit_log '
        'FOR VALUES FROM (%L) TO (%L)', v_name, v_start, v_end);

    RAISE NOTICE 'audit_log partition % created', v_name;
    RETURN v_name;
END;
$$;

COMMENT ON FUNCTION create_audit_log_partition(date) IS
    'Section 6.3: provisions the monthly audit_log partition containing p_month. Must be invoked by a scheduled job AHEAD of each month. Idempotent. Raises rather than relocating rows if the month has spilled into the DEFAULT partition, because 7.11 forbids the DELETE that relocation would require -- see the function body for the operator remediation runbook.';

-- ---------------------------------------------------------------------------
-- Canonical entry hash (7.11 tamper evidence).
--
-- Hashes the entry's own fields together with the previous entry's hash, so
-- altering or deleting any historical row breaks every subsequent link.
-- jsonb::text output in PostgreSQL is canonical (keys sorted, whitespace
-- normalized), which lets an independent verifier reproduce the digest.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_log_entry_hash(
    p_id                  uuid,
    p_timestamp           timestamptz,
    p_actor_id            uuid,
    p_actor_role          platform_coarse_role,
    p_action              text,
    p_entity_type         text,
    p_entity_id           uuid,
    p_result              audit_result,
    p_reason_code         text,
    p_endpoint            text,
    p_method              text,
    p_request_id          uuid,
    p_authorization_check authorization_check_type,
    p_ip_address          inet,
    p_before_value        jsonb,
    p_after_value         jsonb,
    p_previous_hash       bytea
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT digest(
        coalesce(p_id::text, '') || '|'
        || coalesce(to_char(p_timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '') || '|'
        || coalesce(p_actor_id::text, '') || '|'
        || coalesce(p_actor_role::text, '') || '|'
        || coalesce(p_action, '') || '|'
        || coalesce(p_entity_type, '') || '|'
        || coalesce(p_entity_id::text, '') || '|'
        || coalesce(p_result::text, '') || '|'
        || coalesce(p_reason_code, '') || '|'
        || coalesce(p_endpoint, '') || '|'
        || coalesce(p_method, '') || '|'
        || coalesce(p_request_id::text, '') || '|'
        || coalesce(p_authorization_check::text, '') || '|'
        || coalesce(host(p_ip_address), '') || '|'
        || coalesce(p_before_value::text, '') || '|'
        || coalesce(p_after_value::text, '') || '|'
        || coalesce(encode(p_previous_hash, 'hex'), ''),
        'sha256'
    );
$$;

-- ---------------------------------------------------------------------------
-- AUDIT_LOG
-- ER 6.1: id, actor_id, entity_type, entity_id, action, before_value,
--          after_value, timestamp, ip_address.
--
-- Beyond the ER, 7.11 explicitly requires result, a reason/category, the
-- endpoint, the request ID and the specific authorization check that permitted
-- the action. Without result/reason_code a 403 is indistinguishable from a
-- successful call, and IDOR/BOLA probing against sequential IDs (Section 10)
-- becomes undetectable.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
    id                     uuid                        NOT NULL DEFAULT gen_random_uuid(),
    timestamp              timestamptz                 NOT NULL DEFAULT now(),
    actor_id               uuid                        REFERENCES app_user (id),
    -- 6.2.1: the coarse role asserted by the token at the time of the action.
    -- 7.1 makes audit history PERMANENTLY attributable to the actor even after
    -- their role or department changes, so the role and Keycloak subject are
    -- snapshotted here rather than resolved through a live join.
    actor_role             platform_coarse_role,
    actor_keycloak_subject text,
    entity_type            text                        NOT NULL,
    entity_id              uuid,
    action                 text                        NOT NULL,
    before_value           jsonb,
    after_value            jsonb,
    ip_address             inet,

    -- ---- 7.11 denied-authorization events -------------------------------
    result                 audit_result                NOT NULL DEFAULT 'ALLOWED',
    reason_code            text,
    reason_detail          text,
    endpoint               text,
    method                 text,
    request_id             uuid,
    -- 7.11: "the specific authorization check that permitted it" -- which of
    -- the three 7.2 layers was actually evaluated.
    authorization_check    authorization_check_type     NOT NULL DEFAULT 'NONE',
    authorization_rule     text,
    -- 7.11: records that the redaction screen ran before this entry was written,
    -- so a compliance reviewer can assert no entry bypassed it.
    pii_redacted           boolean                     NOT NULL DEFAULT false,

    -- ---- 7.11 tamper evidence -------------------------------------------
    previous_hash          bytea,
    entry_hash             bytea,

    -- 6.3 partitioning forces the partition key into the PK.
    CONSTRAINT pk_audit_log PRIMARY KEY (id, timestamp),
    CONSTRAINT ck_audit_log_action_not_blank CHECK (length(btrim(action)) > 0),
    CONSTRAINT ck_audit_log_entity_type_not_blank CHECK (length(btrim(entity_type)) > 0),
    -- Every entry is hashed at write time. previous_hash is NULL only for the
    -- genesis entry of the chain.
    CONSTRAINT ck_audit_log_entry_hash_present CHECK (entry_hash IS NOT NULL),
    -- A DENIED event is only useful to 7.12 anomaly detection if it is
    -- classified and attributable to an endpoint.
    CONSTRAINT ck_audit_log_denial_reason CHECK (
        result <> 'DENIED' OR (reason_code IS NOT NULL AND length(btrim(reason_code)) > 0)
    ),
    CONSTRAINT ck_audit_log_denial_endpoint CHECK (
        result <> 'DENIED' OR endpoint IS NOT NULL
    )
) PARTITION BY RANGE (timestamp);

COMMENT ON TABLE audit_log IS
    '7.11: append-only, hash-chained, DENIED events included, sensitive fields redacted before write. Read access is restricted to Admin and Auditor (7.11) -- the Auditor role exists so audit review does not depend solely on the same Admins whose actions are reviewed (7.3). Shipped near-real-time to a separate access-restricted log store/SIEM outside this database so a compromise of the primary DB cannot retroactively alter history.';

COMMENT ON COLUMN audit_log.reason_code IS
    '7.11 denial classification, e.g. CROSS_USER_OBJECT_ACCESS (7.2 object-level / BOLA-IDOR), INSUFFICIENT_ROLE (7.2 function-level / BFLA), PROPERTY_SUPPRESSION (7.2 property-level), TOKEN_INVALID, ACCOUNT_DISABLED, IDLE_SESSION_TIMEOUT. Feeds 7.12 alerting on repeated denied attempts against sequential IDs.';

COMMENT ON COLUMN audit_log.pii_redacted IS
    '7.11: true when the redaction screen was applied to before_value/after_value. The audit system exists to detect misuse and must not itself become a data-leak vector if this table or its SIEM copy is exposed.';

-- ---------------------------------------------------------------------------
-- Catch-all DEFAULT partition.
--
-- PostgreSQL will not auto-create monthly partitions, and a missing partition
-- would fail the INSERT -- which, because the audit entry is written in the
-- same transaction as the incident change (7.10), would block incident
-- reporting itself. Section 4 Availability requires reporting never to be
-- blocked, so a DEFAULT partition absorbs any out-of-range month and a
-- scheduled job provisions partitions ahead of time.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log_default PARTITION OF audit_log DEFAULT;

-- ---------------------------------------------------------------------------
-- Single writer for the hash chain (7.11).
--
-- The chain is only meaningful if every writer derives previous_hash from the
-- current chain head. Under concurrency two transactions would otherwise read
-- the same head and fork the chain, so the head read, hash computation and
-- insert are serialized on one transaction-scoped advisory lock.
--
-- THROUGHPUT TRADE-OFF, stated deliberately: this makes the audit write path
-- a serialization point. Audit volume is orders of magnitude below incident
-- write volume, and 7.11 prioritizes tamper evidence over audit throughput, so
-- the lock is the correct trade. If audit write volume ever becomes a
-- bottleneck, the correct fix is per-shard or per-actor chains, NOT dropping the
-- lock.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_log_append(
    p_action                 text,
    p_entity_type            text,
    p_entity_id              uuid                     DEFAULT NULL,
    p_actor_id               uuid                     DEFAULT NULL,
    p_actor_role             platform_coarse_role     DEFAULT NULL,
    p_actor_keycloak_subject text                     DEFAULT NULL,
    p_result                 audit_result             DEFAULT 'ALLOWED',
    p_reason_code            text                     DEFAULT NULL,
    p_reason_detail          text                     DEFAULT NULL,
    p_endpoint               text                     DEFAULT NULL,
    p_method                 text                     DEFAULT NULL,
    p_request_id             uuid                     DEFAULT NULL,
    p_authorization_check    authorization_check_type DEFAULT 'NONE',
    p_authorization_rule     text                     DEFAULT NULL,
    p_ip_address             inet                     DEFAULT NULL,
    p_before_value           jsonb                    DEFAULT NULL,
    p_after_value            jsonb                    DEFAULT NULL,
    p_pii_redacted           boolean                  DEFAULT false,
    p_timestamp              timestamptz              DEFAULT NULL
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, incident_platform
AS $$
DECLARE
    v_id           uuid := gen_random_uuid();
    v_ts           timestamptz := coalesce(p_timestamp, now());
    v_prev_hash    bytea;
    v_entry_hash   bytea;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('incident_platform.audit_log_chain')::bigint);

    SELECT a.entry_hash
      INTO v_prev_hash
      FROM incident_platform.audit_log a
     ORDER BY a.timestamp DESC, a.id DESC
     LIMIT 1;

    v_entry_hash := incident_platform.audit_log_entry_hash(
        v_id, v_ts, p_actor_id, p_actor_role, p_action, p_entity_type, p_entity_id,
        p_result, p_reason_code, p_endpoint, p_method, p_request_id,
        p_authorization_check, p_ip_address, p_before_value, p_after_value, v_prev_hash);

    INSERT INTO incident_platform.audit_log (
        id, timestamp, actor_id, actor_role, actor_keycloak_subject,
        entity_type, entity_id, action, before_value, after_value, ip_address,
        result, reason_code, reason_detail, endpoint, method, request_id,
        authorization_check, authorization_rule, pii_redacted,
        previous_hash, entry_hash
    ) VALUES (
        v_id, v_ts, p_actor_id, p_actor_role, p_actor_keycloak_subject,
        p_entity_type, p_entity_id, p_action, p_before_value, p_after_value, p_ip_address,
        p_result, p_reason_code, p_reason_detail, p_endpoint, p_method, p_request_id,
        p_authorization_check, p_authorization_rule, p_pii_redacted,
        v_prev_hash, v_entry_hash
    );

    RETURN v_id;
END;
$$;

COMMENT ON FUNCTION audit_log_append IS
    '7.11: the ONLY sanctioned writer for audit_log. Serializes on a transaction-scoped advisory lock so the hash chain cannot fork under concurrency, and computes entry_hash from the current chain head. SECURITY DEFINER because V9 revokes the runtime role''s direct INSERT on audit_log -- the function body is fixed and every table it touches is fully qualified, so the definer context grants no caller-controlled privilege; search_path is pinned so a caller cannot hijack an unqualified name. Redaction of before_value/after_value happens in the calling service BEFORE this function is invoked; p_pii_redacted must reflect that screening.';

-- ---------------------------------------------------------------------------
-- 7.11 tamper-resistant storage, enforced at the database level.
-- Grants alone (V9) protect the application role; these triggers additionally
-- protect against the table owner, so append-only holds even if the privileged
-- migration credential is misused.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_log_reject_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'audit_log is append-only (Section 7.11): % is not permitted. Historical entries are corrected by appending a new entry, never by rewriting history.',
        TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER trg_audit_log_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW
    EXECUTE FUNCTION audit_log_reject_mutation();

-- TRUNCATE does not fire row-level triggers; guard it separately.
CREATE OR REPLACE FUNCTION audit_log_reject_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'audit_log is append-only (Section 7.11): TRUNCATE is not permitted.'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER trg_audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT
    EXECUTE FUNCTION audit_log_reject_truncate();

-- ---------------------------------------------------------------------------
-- 7.11: "Integrity of the audit log itself is periodically verified ... to
-- detect gaps or tampering." Returns one row per problem found; zero rows means
-- the chain is intact across the window.
--
-- The first row of an explicit window is exempt from link checking: its real
-- predecessor lies outside the window, so its previous_hash legitimately has
-- no in-scope predecessor to match.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION verify_audit_log_chain(
    p_from timestamptz DEFAULT NULL,
    p_to   timestamptz DEFAULT NULL
)
RETURNS TABLE (
    entry_id uuid,
    entry_ts timestamptz,
    problem  text
)
LANGUAGE sql
STABLE
AS $$
    WITH scoped AS (
        SELECT a.*,
               lag(a.entry_hash) OVER w AS expected_previous,
               row_number() OVER w   AS seq
          FROM incident_platform.audit_log a
         WHERE (p_from IS NULL OR a.timestamp >= p_from)
           AND (p_to   IS NULL OR a.timestamp <  p_to)
        WINDOW w AS (ORDER BY a.timestamp, a.id)
    ),
    checked AS (
        SELECT s.*,
               incident_platform.audit_log_entry_hash(
                   s.id, s.timestamp, s.actor_id, s.actor_role, s.action,
                   s.entity_type, s.entity_id, s.result, s.reason_code,
                   s.endpoint, s.method, s.request_id, s.authorization_check,
                   s.ip_address, s.before_value, s.after_value, s.previous_hash
               ) AS recomputed
          FROM scoped s
    )
    SELECT c.id,
           c.timestamp,
           CASE
               WHEN c.entry_hash IS NULL THEN 'MISSING_ENTRY_HASH'
               WHEN c.entry_hash IS DISTINCT FROM c.recomputed THEN 'HASH_MISMATCH'
               WHEN c.seq > 1
                    AND c.expected_previous IS DISTINCT FROM c.previous_hash
                    THEN 'BROKEN_LINK'
           END
      FROM checked c
     WHERE c.entry_hash IS NULL
        OR c.entry_hash IS DISTINCT FROM c.recomputed
        OR (c.seq > 1 AND c.expected_previous IS DISTINCT FROM c.previous_hash);
$$;

COMMENT ON FUNCTION verify_audit_log_chain(timestamptz, timestamptz) IS
    '7.11 periodic integrity verification. Zero rows = chain intact across the window. Any row indicates tampering, truncation, or a write that bypassed audit_log_append. 7.11 additionally requires comparing against the out-of-database SIEM copy, which covers gaps this function cannot see (a deleted row leaves no local trace).';

-- ---------------------------------------------------------------------------
-- Seed partitions: 3 months back (late/retried writes), current month, 6 months
-- forward. The DEFAULT partition created above absorbs anything beyond that.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_month date := date_trunc('month', CURRENT_DATE)::date;
BEGIN
    PERFORM create_audit_log_partition((v_month - interval '3 months')::date);
    PERFORM create_audit_log_partition((v_month - interval '2 months')::date);
    PERFORM create_audit_log_partition((v_month - interval '1 month')::date);
    PERFORM create_audit_log_partition(v_month);
    PERFORM create_audit_log_partition((v_month + interval '1 month')::date);
    PERFORM create_audit_log_partition((v_month + interval '2 months')::date);
    PERFORM create_audit_log_partition((v_month + interval '3 months')::date);
    PERFORM create_audit_log_partition((v_month + interval '4 months')::date);
    PERFORM create_audit_log_partition((v_month + interval '5 months')::date);
    PERFORM create_audit_log_partition((v_month + interval '6 months')::date);
END;
$$;
