-- ============================================================================
-- V14  Runtime grant: Admin capability management writes to platform_role
-- Spec: 6.2.3 (fine-grained permissions are application-owned and Admin-
--       configurable), FR-6.2 (categories, severity, SLA and role
--       configuration adjustable by Admin at runtime, no code change), 6.2.1
--       (the COARSE role stays Keycloak's -- see the scope note below),
--       7.2 function level, 7.11 (the resulting change is audited).
--
-- Why this migration exists
-- ------------------------
-- `POST /api/v1/admin/users` grants and revokes a single capability flag on a
-- role, which is a read-modify-write of `platform_role.permissions`. V9 granted
-- `incident_app` INSERT/UPDATE/DELETE on `app_user` (user lifecycle, department)
-- but deliberately did NOT include `platform_role`: at the time, the only writer
-- of role configuration was a migration, and the application had no legitimate
-- flow that needed to change it at runtime.
--
-- FR-6.2 requires the opposite. `V12` seeds `can_view_reporter_identity` false
-- for every role so it is never an implicit power, and Section 2's confirmed
-- decision requires the Security Administrator to grant it as a deliberate act.
-- With no UPDATE privilege, that grant is impossible without a direct database
-- edit -- so the endpoint would fail with `permission denied for table
-- platform_role` at runtime, and would fail in a way no unit test can catch,
-- because the store is mocked.
--
-- SCOPE -- this is deliberately UPDATE only, and only on one column's table.
-- ---------------------------------------------------------------------------
--   * No INSERT. Roles come from the 6.2.1 vocabulary. This endpoint does not
--     create roles; `PlatformRole.fromKeycloakRole` fails closed on an unknown
--     name, so a role added here could not be produced through the API anyway.
--   * No DELETE. Removing a role is not an admin operation in 6.2, and a
--     deletable role would break the FK from `app_user.role_id` anyway.
--   * No UPDATE on `app_user.role_id`. This is the load-bearing limit. 6.2.1
--     makes Keycloak the source of truth for the coarse role and `app_user.role_id`
--     a projection synced from it. The application can therefore change a user's
--     department and active flag, and a role's fine-grained capabilities, while
--     still being unable to move a user between roles on its own. If a future
--     flow needs that, it needs a Keycloak write-through and a fresh review of
--     this grant -- it must not arrive by widening this one.
--   * Column-level restriction is deliberately NOT used. `GRANT UPDATE
--     (permissions, updated_at) ON platform_role` would be tighter, but it does
--     not compose with the row lock the endpoint relies on, and it leaves a
--     future migration or reporting query needing another grant. The 6.2.3
--     tradeoff is the one V9 already accepted for the tables it does grant: the
--     runtime role can write the configuration it administers, and the
--     application layer decides which changes are legitimate.
--
-- `SELECT ... FOR UPDATE` needs both SELECT and UPDATE on the row, so this grant
-- also enables the lock that keeps two concurrent capability grants from losing
-- one another.
--
-- PROVISIONING ORDER: `incident_app` must exist before this runs, exactly as for
-- V9 -- it is provisioned by IaC from the vault (7.8), not created here. Fails
-- closed rather than warning: silently skipping this grant produces an endpoint
-- that returns 500 at runtime, which is harder to diagnose than a failed
-- migration.
--
-- Migrations are immutable, so this is a new migration rather than an edit to
-- V9. Re-running it is a no-op, so it is safe against a database that already
-- has the grant.
-- ============================================================================

SET search_path TO incident_platform, public;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'incident_app') THEN
        RAISE EXCEPTION
            'Role incident_app does not exist. Refusing to apply the platform_role write grant: the Admin capability-management endpoint (POST /api/v1/admin/users) would fail at runtime with permission denied. Provision incident_app via IaC/vault (7.8) before running this migration, as 7.16 requires a minimum-privilege runtime user.';
    END IF;
END;
$$;

-- UPDATE only. The absence of INSERT and DELETE is the 6.2.1 scope limit
-- described above, and is not an oversight to be tidied up later.
GRANT UPDATE ON incident_platform.platform_role TO incident_app;
