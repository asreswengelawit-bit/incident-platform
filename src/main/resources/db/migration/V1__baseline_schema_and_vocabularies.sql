-- ============================================================================
-- V1  Baseline: dedicated schema + controlled vocabularies
-- Spec: 5.2 (Flyway, immutable numbered migrations, applied via explicit
--       reviewed CI/CD gate), 6.1 (ER model), 6.2 (3NF), 7.16 (application
--       DB user scoped to its own schema only, no cross-schema access).
--
-- Native PostgreSQL ENUM types are used for the two value sets the spec
-- fixes and never delegates to configuration:
--   * incident_status      -- FR-3.1 / Section 8.1 lifecycle
--   * incident_severity    -- Section 12 severity levels
-- Admin-configurable concerns (categories, severity MATRIX, SLA targets,
-- retention) are modelled as tables in V3, not as enums, per FR-6.2.
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS incident_platform;

-- Required by V7 for the audit-log hash chain (7.11 integrity verification).
-- Installed INTO the application schema rather than public, so that
-- audit_log_append -- which is SECURITY DEFINER with a pinned
-- search_path = pg_catalog, incident_platform -- can resolve digest() without
-- depending on `public` being on its search path.
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA incident_platform;

SET search_path TO incident_platform, public;

-- ---------------------------------------------------------------------------
-- Controlled vocabularies
-- ---------------------------------------------------------------------------

-- 6.2.1: Keycloak is the source of truth for identity and the COARSE role.
-- This enum is deliberately the exact vocabulary of the OIDC role claim so
-- that claim -> platform_role.name is a provable 1:1 mapping (7.9: token
-- claims are minimal -- role, org/department). Section 2 stakeholder table.
CREATE TYPE platform_coarse_role AS ENUM (
    'REPORTER',
    'ANALYST',
    'SECURITY_LEAD',
    'SECURITY_ADMIN',
    'AUDITOR',
    'SERVICE_ACCOUNT'
);

-- FR-3.1 status list. `ESCALATED` is deliberately absent: per FR-2.7 and
-- Section 8.1 escalation is a boolean/timestamped ATTRIBUTE on the incident,
-- not a lifecycle state. It must never be added to this enum.
-- Declaration order is Low-to-high lifecycle order; also the natural sort.
CREATE TYPE incident_status AS ENUM (
    'NEW',
    'TRIAGED',
    'ASSIGNED',
    'INVESTIGATING',
    'CONTAINED',
    'RESOLVED',
    'CLOSED',
    'REOPENED',
    'REJECTED'
);

-- Section 12. Declared ascending by risk so ORDER BY severity yields
-- Low -> Critical without a CASE expression.
CREATE TYPE incident_severity AS ENUM (
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL'
);

-- 5.4 synchronous REST ingestion from SIEM / email gateway, plus manual
-- web intake. Drives the Service Account path on POST /api/v1/incidents.
CREATE TYPE incident_source AS ENUM (
    'WEB_UI',
    'API_INGESTION',
    'SIEM',
    'EMAIL_GATEWAY'
);

-- 7.6: malware/AV scanning of every upload BEFORE it is persisted as
-- downloadable or made available. QUARANTINED is retained, not discarded --
-- a malicious attachment is itself an IOC (7.6).
CREATE TYPE evidence_scan_status AS ENUM (
    'PENDING',
    'SCANNING',
    'CLEAN',
    'QUARANTINED',
    'FAILED'
);

-- 7.11: denied-authorization events are logged too, not just successful
-- actions. Without this column, IDOR/BOLA probing is invisible.
CREATE TYPE audit_result AS ENUM (
    'ALLOWED',
    'DENIED'
);

-- 7.11: the audit entry must record "the specific authorization check that
-- permitted it" -- i.e. which of the three layers in 7.2 was evaluated.
CREATE TYPE authorization_check_type AS ENUM (
    'NONE',
    'FUNCTION_LEVEL',
    'OBJECT_LEVEL',
    'PROPERTY_LEVEL'
);

-- ---------------------------------------------------------------------------
-- Generic updated_at maintenance.
-- Applied to every mutable table so that administrative tooling writing via
-- SQL (not only JPA) still produces trustworthy timestamps for the audit trail
-- (Section 4 Auditability).
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;
