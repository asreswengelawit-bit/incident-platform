-- ============================================================================
-- V2  Identity & coarse-role projection
-- Spec: 6.1 (USER, ROLE), 6.2 Option 2 (Keycloak authenticates, application
--       owns fine-grained authorization), 7.1 (account lifecycle, dormant
--       detection), 7.9 (claims re-validated against current user state),
--       7.2.1 (department-scoped visibility).
--
-- 6.2 Decision 2: Spring Security does NOT query these tables to re-derive the
-- coarse role -- it reads the validated token's role claim. These tables are a
-- PROJECTION synced from Keycloak (6.2 Decision 4), used only for the
-- fine-grained detail Keycloak does not model: department, led_departments,
-- and application-specific scoping rules.
-- ============================================================================

SET search_path TO incident_platform, public;

-- ---------------------------------------------------------------------------
-- ROLE
-- ER 6.1: uuid id PK, string name, json permissions.
-- `name` is typed as the Keycloak role vocabulary (6.2.1) rather than free
-- text so the OIDC role claim maps 1:1.
-- `permissions` carries exactly what 6.2.3 says it should: the fine-grained,
-- business-specific authorization detail Keycloak does not model -- including
-- `led_departments`, which resolves 7.2.1's "the department(s) they lead"
-- (plural) which a single USER.department column cannot express.
-- ---------------------------------------------------------------------------
CREATE TABLE platform_role (
    id           uuid                  PRIMARY KEY DEFAULT gen_random_uuid(),
    name         platform_coarse_role  NOT NULL,
    display_name text                  NOT NULL,
    permissions  jsonb                 NOT NULL DEFAULT '{}'::jsonb,
    created_at   timestamptz           NOT NULL DEFAULT now(),
    updated_at   timestamptz           NOT NULL DEFAULT now(),

    CONSTRAINT uq_platform_role_name UNIQUE (name),
    CONSTRAINT ck_platform_role_permissions_object
        CHECK (jsonb_typeof(permissions) = 'object')
);

COMMENT ON COLUMN platform_role.permissions IS
    'Fine-grained application authorization detail only (6.2.3): department scoping, led_departments, capability flags. NOT a second source of truth for the coarse role -- that lives in Keycloak (6.2.1).';

-- ---------------------------------------------------------------------------
-- USER
-- ER 6.1: uuid id PK, string full_name, string email, string department,
--          uuid role_id FK, boolean active, datetime created_at.
--
-- Named app_user because `user` is a reserved word in PostgreSQL.
--
-- PII flag (7.4): full_name, email and department are personal data and are
-- candidates for the redaction option in FR-5.3 exports and for eventual
-- data-subject requests. They are intentionally NOT individually flagged
-- inline; the redaction key list is maintained application-side per 7.11 and
-- 7.4, and audit_log.pii_redacted records whether screening was applied.
--
-- 7.1 account lifecycle: `active` plus disabled_at/disabled_reason support
-- automated deprovisioning from the HR/IdP feed and dormant-account
-- auto-disable; every such transition is written to AUDIT_LOG (V7).
-- last_login_at drives the 7.1 configurable inactivity (e.g. 90 day) check.
-- ---------------------------------------------------------------------------
CREATE TABLE app_user (
    id                uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    keycloak_subject  text         NOT NULL,
    full_name         text         NOT NULL,
    email             text         NOT NULL,
    department        text,
    role_id           uuid         NOT NULL REFERENCES platform_role (id),
    active            boolean      NOT NULL DEFAULT true,
    created_at        timestamptz  NOT NULL DEFAULT now(),
    updated_at        timestamptz  NOT NULL DEFAULT now(),
    last_login_at     timestamptz,
    disabled_at       timestamptz,
    disabled_reason   text,
    -- 6.2.4: role is synced from Keycloak, never independently editable here.
    -- role_synced_at records when this projection last matched the IdP claim so
    -- drift between the two systems is detectable (7.12 anomaly monitoring).
    role_synced_at    timestamptz,
    -- 7.10 optimistic locking, so two admins cannot silently clobber a
    -- concurrent permission change.
    version           integer      NOT NULL DEFAULT 0,

    CONSTRAINT uq_app_user_keycloak_subject UNIQUE (keycloak_subject),
    CONSTRAINT uq_app_user_email UNIQUE (email),
    CONSTRAINT ck_app_user_email_normalized CHECK (email = lower(email)),
    -- An account is active if and only if it has never been disabled:
    -- deactivation must always carry a reason and a timestamp (7.1).
    CONSTRAINT ck_app_user_active_disabled_consistent
        CHECK (active = (disabled_at IS NULL)),
    CONSTRAINT ck_app_user_disabled_reason
        CHECK (active OR disabled_reason IS NOT NULL),
    CONSTRAINT ck_app_user_version CHECK (version >= 0)
);

COMMENT ON COLUMN app_user.keycloak_subject IS
    'The OIDC `sub` claim. This table is a projection of Keycloak identity, not a competing identity store (6.2.1/6.2.4).';

COMMENT ON COLUMN app_user.department IS
    'Home department. 7.2.1: Analyst sees unassigned incidents within their OWN department; Security Lead sees incidents in the department(s) they lead, which are enumerated in platform_role.permissions->led_departments, not here.';

COMMENT ON COLUMN app_user.active IS
    '7.1: deprovisioned automatically from the HR/IdP feed, auto-disabled after configurable inactivity. Also re-authorization trigger -- 7.1 requires access to be re-evaluated against the CURRENT role and department on every request, not the historical one.';

CREATE TRIGGER trg_app_user_updated_at
    BEFORE UPDATE ON app_user
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
