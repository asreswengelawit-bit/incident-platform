-- Provisions the database role the application connects as, before Flyway runs.
--
-- V9__database_security_grants.sql fails CLOSED if incident_app is absent, which
-- is the correct production behaviour: a schema that silently applied without
-- its grants would look migrated while running with PostgreSQL's default
-- privileges. This script reproduces what a deployment pipeline must do, and
-- doubles as the executable statement of that requirement.
--
-- The password is supplied by the test container, not committed.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'incident_app') THEN
        EXECUTE format('CREATE ROLE incident_app LOGIN PASSWORD %L', current_setting('incident.test_password', true));
    END IF;
END
$$;

-- audit_log_append is SECURITY DEFINER, so EXECUTE requires the function to be
-- called by a role that has been granted it. V9 does that; this only confirms
-- the login role can reach the schema at all.
GRANT CONNECT ON DATABASE incident_platform TO incident_app;
