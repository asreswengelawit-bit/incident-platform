-- ============================================================================
-- V3  Classification & policy configuration
-- Spec: 6.1 (INCIDENT_CATEGORY), 3.2 FR-2.2 (severity matrix), 3.6 FR-6.2
--       (categories, severity matrix, SLA targets per severity), 3.6 FR-6.5 +
--       7.14 (retention policy per category, legal hold), 7.6 (MIME allow-list
--       per category, per-file and per-incident size/count limits), 4
--       (Localization: category labels in multiple languages), 6.2 (soft delete
--       over hard delete for audit-relevant data).
-- ============================================================================

SET search_path TO incident_platform, public;

-- ---------------------------------------------------------------------------
-- INCIDENT_CATEGORY
-- ER 6.1: uuid id PK, string name, text description, int default_sla_hours.
-- ---------------------------------------------------------------------------
CREATE TABLE incident_category (
    id                      uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    name                    text         NOT NULL,
    description             text,
    default_sla_hours       integer      NOT NULL DEFAULT 24,
    -- FR-6.5 / 7.14: configurable retention per category (spec cites a 3-7
    -- year range for compliance-relevant categories; 36 months is the default
    -- and is overridable per category).
    retention_months        integer      NOT NULL DEFAULT 36,
    -- FR-1.2: max file size and allowed types configurable by Admin.
    -- 25 MB default is the Section 4 example figure.
    max_evidence_size_bytes bigint       NOT NULL DEFAULT 26214400,
    max_evidence_files      integer      NOT NULL DEFAULT 20,
    is_active               boolean      NOT NULL DEFAULT true,
    created_at              timestamptz  NOT NULL DEFAULT now(),
    updated_at              timestamptz  NOT NULL DEFAULT now(),
    -- 6.2 soft delete.
    deleted_at              timestamptz,
    -- 7.10 optimistic locking: two admins editing the severity matrix/SLA
    -- config concurrently must not silently overwrite each other.
    version                 integer      NOT NULL DEFAULT 0,

    CONSTRAINT uq_incident_category_name UNIQUE (name),
    CONSTRAINT ck_incident_category_name_not_blank CHECK (length(btrim(name)) > 0),
    CONSTRAINT ck_incident_category_sla_hours CHECK (default_sla_hours > 0),
    CONSTRAINT ck_incident_category_retention_months CHECK (retention_months > 0),
    CONSTRAINT ck_incident_category_max_size CHECK (max_evidence_size_bytes > 0),
    CONSTRAINT ck_incident_category_max_files CHECK (max_evidence_files > 0),
    CONSTRAINT ck_incident_category_version CHECK (version >= 0)
);

CREATE TRIGGER trg_incident_category_updated_at
    BEFORE UPDATE ON incident_category
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- 4 Localization: "UI and category labels support multiple languages if org is
-- multinational." Kept as a side table so the canonical label is not diluted.
CREATE TABLE incident_category_translation (
    category_id  uuid    NOT NULL REFERENCES incident_category (id) ON DELETE CASCADE,
    locale       text    NOT NULL,
    name         text    NOT NULL,
    description  text,

    PRIMARY KEY (category_id, locale),
    CONSTRAINT ck_category_translation_locale
        CHECK (locale ~ '^[a-z]{2}(-[A-Z]{2})?$'),
    CONSTRAINT ck_category_translation_name_not_blank
        CHECK (length(btrim(name)) > 0)
);

-- 7.6: "Allow-list of accepted MIME types/extensions per category ... reject by
-- content-sniffed type, not just file extension." The detected/sniffed type is
-- compared against this list; the declared extension is stored here only as
-- additional signal and is never trusted on its own.
CREATE TABLE incident_category_allowed_type (
    category_id  uuid  NOT NULL REFERENCES incident_category (id) ON DELETE CASCADE,
    mime_type    text  NOT NULL,
    extension    text,

    PRIMARY KEY (category_id, mime_type),
    CONSTRAINT ck_category_allowed_type_mime_not_blank
        CHECK (length(btrim(mime_type)) > 0),
    CONSTRAINT ck_category_allowed_type_extension_normalized
        CHECK (extension IS NULL OR extension = lower(ltrim(extension, '.')))
);

-- ---------------------------------------------------------------------------
-- SEVERITY MATRIX (FR-2.2 "documented severity matrix (impact x likelihood)")
-- Strategy pattern in 5.5: the mapping impact x likelihood -> severity is a
-- swappable Admin-configurable rule set, not a hard-coded if-chain, so
-- FR-6.2 changes need no code change.
--
-- DELIBERATELY LEFT EMPTY -- see Phase 1 summary. Section 12 defines severity
-- DEFINITIONS and target response SLAs but does not define the impact x
-- likelihood grid or the cell->severity mapping. That is a stakeholder
-- decision, so no rows are invented here.
-- ---------------------------------------------------------------------------
CREATE TABLE severity_matrix_rule (
    id             uuid              PRIMARY KEY DEFAULT gen_random_uuid(),
    impact         smallint          NOT NULL,
    likelihood     smallint          NOT NULL,
    severity       incident_severity NOT NULL,
    justification  text,
    is_active      boolean           NOT NULL DEFAULT true,
    created_at     timestamptz       NOT NULL DEFAULT now(),
    updated_at     timestamptz       NOT NULL DEFAULT now(),

    CONSTRAINT uq_severity_matrix_rule_impact_likelihood UNIQUE (impact, likelihood),
    CONSTRAINT ck_severity_matrix_impact CHECK (impact BETWEEN 1 AND 5),
    CONSTRAINT ck_severity_matrix_likelihood CHECK (likelihood BETWEEN 1 AND 5)
);

CREATE TRIGGER trg_severity_matrix_rule_updated_at
    BEFORE UPDATE ON severity_matrix_rule
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- SLA POLICY (FR-6.2 "SLA targets per severity"; Section 4 checklist "SLA timers
-- and breach alerts configurable per severity"; 6.3 sla_due_at derivation)
--
-- category_id NULL = organization-wide default for that severity, overridden by
-- a category-specific row. Lets an Admin tune SLAs for a noisy category without
-- restating the other three severities.
--
-- resolution_sla_minutes is NULLABLE and intentionally unseeded: Section 12
-- specifies only a "Target Response SLA" (15 min / 1 h / 4 h / 1 business day).
-- Resolution targets are NOT defined by the document, so until stakeholders
-- supply them incident.sla_due_at stays NULL and 6.3's recalculation has no
-- resolution component. Inventing numbers here would be a silent deviation.
-- ---------------------------------------------------------------------------
CREATE TABLE incident_sla_policy (
    id                      uuid              PRIMARY KEY DEFAULT gen_random_uuid(),
    category_id             uuid              REFERENCES incident_category (id) ON DELETE CASCADE,
    severity                incident_severity NOT NULL,
    response_sla_minutes    integer           NOT NULL,
    resolution_sla_minutes  integer,
    business_hours_only     boolean           NOT NULL DEFAULT false,
    is_active               boolean           NOT NULL DEFAULT true,
    created_at              timestamptz       NOT NULL DEFAULT now(),
    updated_at              timestamptz       NOT NULL DEFAULT now(),

    CONSTRAINT ck_incident_sla_policy_response CHECK (response_sla_minutes > 0),
    CONSTRAINT ck_incident_sla_policy_resolution
        CHECK (resolution_sla_minutes IS NULL OR resolution_sla_minutes > 0)
);

-- At most one active policy per (category-or-default, severity). COALESCE maps
-- the NULL category (org-wide default) into the unique key space.
CREATE UNIQUE INDEX uq_incident_sla_policy_scope
    ON incident_sla_policy (
        COALESCE(category_id, '00000000-0000-0000-0000-000000000000'::uuid),
        severity
    )
    WHERE is_active;

CREATE TRIGGER trg_incident_sla_policy_updated_at
    BEFORE UPDATE ON incident_sla_policy
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
