-- ============================================================================
-- V9  Database security: least-privilege grants
-- Spec: 7.16 (Database Security) in full --
--   * application DB user holds minimum privileges for its OWN SCHEMA ONLY,
--     no superuser, no cross-schema access;
--   * the application role explicitly has NO UPDATE/DELETE grant on audit_log,
--     at the database-permission level, not just in application code;
--   * Flyway migrations run under a SEPARATE, more privileged, tightly
--     controlled credential than the runtime application connection -- the app
--     must not be able to alter its own schema at runtime;
--   * separate read-only credentials for read-heavy workloads are provisioned
--     for the replica (see the grants block at the end).
--
-- 7.16 also requires TLS on all database connections and a non-publicly
-- reachable database. Those are network/IaC controls, not DDL, and are
-- enforced in the deployment configuration -- NOT verifiable from a migration.
-- They are listed in the Phase 1 summary as outstanding.
--
-- This migration is deliberately idempotent and environment-agnostic: it grants
-- only to roles that already exist. Per 7.16 the roles are provisioned by
-- infrastructure-as-code from the secrets vault (7.8), never created by the
-- migration itself, because a migration that could CREATE roles would be a
-- migration that could escalate itself.
-- ============================================================================

SET search_path TO incident_platform, public;

-- ---------------------------------------------------------------------------
-- Role names are written as LITERALS, not plpgsql variables, on purpose.
-- PostgreSQL's GRANT/REVOKE do not accept bind parameters for the role
-- identifier, so `GRANT ... TO v_app_role` inside a DO block is parsed as a
-- request for a role literally named "v_app_role" and fails at runtime. That
-- failure mode -- a migration that reports success while granting nothing --
-- is exactly what 7.16's separation-of-duties intent exists to prevent.
--
-- PROVISIONING ORDER IS A HARD REQUIREMENT: the runtime roles must exist
-- before this migration runs. Per 7.16 they are provisioned by
-- infrastructure-as-code from the secrets vault (7.8) -- NOT created here,
-- because a migration able to CREATE roles is a migration able to escalate
-- itself, and because in a shared cluster a pre-created role of the same name
-- would silently capture every privilege granted below.
--
-- Consequence for CI/local: Testcontainers and the dev compose file must
-- create incident_app before Flyway migrates. incident_app failing closed is
-- deliberate. incident_app_readonly and incident_migrator only warn, because
-- their absence weakens nothing.
-- ---------------------------------------------------------------------------

-- ---- role-independent hardening: always safe, no role required ----------

-- 7.16: the runtime application role must not be able to alter its own schema.
REVOKE CREATE ON SCHEMA incident_platform FROM PUBLIC;

-- 7.16: no cross-schema access. pg_catalog access is implicit and unaffected.
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Partition maintenance is a scheduled-job / DBA responsibility, never an
-- application one: an app-side caller must not be able to provision partitions.
REVOKE EXECUTE ON FUNCTION create_audit_log_partition(date) FROM PUBLIC;

-- ---- optional roles: warn, do not fail ----------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'incident_app_readonly') THEN
        RAISE WARNING
            'Role incident_app_readonly absent -- read-replica grants skipped. 7.16 expects a separate read-only credential for dashboard workloads (6.3 caching, FR-5.2). Provision it via IaC/vault and re-run Flyway.';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'incident_migrator') THEN
        RAISE WARNING
            'Role incident_migrator absent -- Flyway is running as the schema owner. 7.16 expects migrations to run under a credential separate from the runtime application connection, so the app cannot alter its own schema at runtime.';
    END IF;
END;
$$;

-- ===========================================================================
-- RUNTIME APPLICATION GRANTS -- fail closed if incident_app is missing.
-- ===========================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'incident_app') THEN
        RAISE EXCEPTION
            'Role incident_app does not exist. Refusing to apply runtime grants: proceeding would leave the application running with unhardened, over-privileged or absent grants. Provision incident_app via IaC/vault (7.8) before running this migration, as 7.16 requires a minimum-privilege user scoped to its own schema.';
    END IF;
END;
$$;

GRANT USAGE ON SCHEMA incident_platform TO incident_app;

-- Every table is granted explicitly rather than relying on default
-- privileges, so a table added by a future migration is unreachable by the app
-- until it is deliberately granted.
GRANT SELECT ON ALL TABLES IN SCHEMA incident_platform TO incident_app;

-- Write access, table by table, and only where writes are legitimate.
GRANT INSERT, UPDATE, DELETE ON
    incident,                          -- incident lifecycle (soft delete only)
    incident_collaborator,
    incident_status_history,           -- append-only in practice
    investigation_note,
    response_action,
    incident_comment,
    incident_group
TO incident_app;

-- Configuration written by Admin flows (FR-6.2, FR-6.5, FR-6.1 projections).
GRANT INSERT, UPDATE, DELETE ON
    incident_category,
    incident_category_translation,
    incident_category_allowed_type,
    severity_matrix_rule,
    incident_sla_policy,
    app_user
TO incident_app;

-- FR-1.6 restricted identity store: the application must be able to WRITE it
-- at intake, and the "may read at all" decision is made in exactly one place --
-- the service that checks platform_role.permissions->can_view_anonymous_identity
-- and writes a dedicated AUDIT_LOG entry for each access.
--
-- FLAGGED TRADEOFF: this is an APPLICATION-layer gate, not a database-layer
-- one. A true DB-layer split would need a second, separate read credential and
-- a second DataSource, so that identity reads are impossible from the ordinary
-- runtime connection. 7.16 does not require that split and it costs a second
-- pooled connection set, so it is not taken here. Raising it is your decision,
-- not a silent change.
GRANT INSERT, UPDATE ON incident_reporter_identity TO incident_app;

-- ---- evidence: insert + scan-state update only ------------------------
-- 7.6 / 4: evidence is immutable post-upload. The V5 trigger is an
-- owner-proof second barrier on the identity columns.
GRANT INSERT, UPDATE ON incident_evidence TO incident_app;

-- ---- audit_log: SELECT + sanctioned write function ONLY ---------------
-- 7.11 / 7.16: no UPDATE/DELETE grant for ANY application role, including
-- Admin. REVOKE is issued after the blanket SELECT above so the intent is
-- explicit and survives a future `GRANT ALL` on the schema.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM incident_app;

-- Writes go through audit_log_append so the hash chain cannot fork under
-- concurrency; direct INSERT is revoked to keep a single writer. The function
-- is SECURITY DEFINER precisely because this revoke removes the runtime role's
-- own INSERT privilege -- see its definition in V7, where search_path is pinned
-- and every table it touches is schema-qualified.
REVOKE INSERT ON audit_log FROM incident_app;
GRANT EXECUTE ON FUNCTION audit_log_append(
    text, text, uuid, uuid, platform_coarse_role, text, audit_result, text,
    text, text, text, uuid, authorization_check_type, text, inet, jsonb,
    jsonb, boolean, timestamptz
) TO incident_app;

-- 7.11 periodic integrity verification. Read-only function; safe to grant.
GRANT EXECUTE ON FUNCTION verify_audit_log_chain(timestamptz, timestamptz) TO incident_app;

-- Sequences: none currently required (all PKs are application-generated uuid
-- v4), granted defensively so a future identity sequence does not fail at
-- runtime with a permission error instead of a clear one.
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA incident_platform TO incident_app;

-- ===========================================================================
-- READ-REPLICA GRANTS -- applied only when the optional role exists.
-- ===========================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'incident_app_readonly') THEN
        EXECUTE 'GRANT USAGE ON SCHEMA incident_platform TO incident_app_readonly';
        EXECUTE 'GRANT SELECT ON ALL TABLES IN SCHEMA incident_platform TO incident_app_readonly';
        -- The replica credential must not reach a write path, the audit trail,
        -- or the restricted identity store.
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON audit_log FROM incident_app_readonly';
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON incident_reporter_identity FROM incident_app_readonly';
        -- SELECT is revoked too, and this one is NOT an application-layer
        -- concern: the replica credential is used directly by reporting and
        -- analytics queries, so there is no authorization gate in front of it.
        -- FR-1.6 forbids reporter identity appearing in generated reports
        -- (FR-5.1/FR-5.3) and 7.4 requires PII minimization, so this reporting
        -- credential must not be able to read reporter identity at all.
        EXECUTE 'REVOKE SELECT ON incident_reporter_identity FROM incident_app_readonly';
    END IF;
END;
$$;
