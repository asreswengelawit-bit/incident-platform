-- ============================================================================
-- V13  Evidence upload capability
-- Spec: 3.1 FR-1.2 (a Reporter can upload evidence; max size and allowed types
--       configurable by Admin), Section 9 (`POST /incidents/{id}/evidence` --
--       Reporter (own), Analyst+), 7.2 function level, 7.6 (allow-list,
--       scanning, limits, immutability).
--
-- Why this migration exists: V10 seeded the REPORTER role with
-- `can_upload_evidence_on_own_incident`, and nothing ever read that key. The
-- 7.2 function-level gate is driven by `Capability`, so the upload endpoint had
-- no capability to test and no role could be granted or revoked the ability to
-- attach evidence at runtime -- FR-6.2 requires that it be Admin-configurable
-- without a code change.
--
-- The V10 key is NOT removed. `RolePermissions` accepts either spelling, so a
-- role that was granted the old key by a hand-edited grant before this
-- migration still uploads, and the seed below adds the canonical spelling
-- rather than renaming the flag under anyone.
--
-- Granting the function-level flag is not the same as granting the right to
-- attach anything, anywhere. 7.2.1 object level still decides which incidents
-- may be touched, and it is unchanged by this migration:
--
--   REPORTER        -> own submissions only (reporterDecision)
--   ANALYST         -> assigned, collaborator, or unassigned-in-department
--   SECURITY_LEAD   -> departments they lead
--   SECURITY_ADMIN  -> not granted. See below.
--   AUDITOR         -> not granted; read-only by role.
--   SERVICE_ACCOUNT -> granted, and refused at the object layer every time.
--
-- SECURITY_ADMIN is deliberately omitted, for the same reason it is absent from
-- the Section 8.2 transition matrix: it is a platform-configuration role, not an
-- incident operator. Admin still *reads* evidence organisation-wide through
-- 7.2.1, which is what the oversight and export duties actually need.
--
-- SERVICE_ACCOUNT is granted the flag even though it can never satisfy the
-- object-level check. Its `visibility_scope` is NONE, so `denyScope` refuses
-- every incident, and uploads are refused for the same reason reads are. The
-- grant is recorded so that the refusal -- if it ever happens -- is an
-- OBJECT_LEVEL denial of a permitted function, which is the useful 7.12 signal,
-- rather than a function-level refusal of an impossible role.
--
-- Migrations are immutable, so these are UPDATEs to the seeded rows rather than
-- edits to V10. `||` merges jsonb keys additively; the flags already present are
-- untouched. Everything here stays Admin-configurable at runtime (FR-6.2).
-- ============================================================================

SET search_path TO incident_platform, public;

-- FR-1.1/FR-1.2: intake. The Reporter already holds
-- `can_upload_evidence_on_own_incident` from V10; the canonical key is added so
-- that all evidence-writing roles read the same flag.
UPDATE platform_role SET permissions = permissions || '{
    "can_upload_evidence": true
}'::jsonb
 WHERE name = 'REPORTER';

-- Section 9 lists "Reporter (own), Analyst+" for the upload endpoint.
UPDATE platform_role SET permissions = permissions || '{
    "can_upload_evidence": true
}'::jsonb
 WHERE name = 'ANALYST';

-- Section 2: the Lead holds "all analyst rights plus" reassignment, escalation,
-- severity override and closure approval -- so also upload.
UPDATE platform_role SET permissions = permissions || '{
    "can_upload_evidence": true
}'::jsonb
 WHERE name = 'SECURITY_LEAD';

-- Section 7.7 / 5.1: the SIEM and email-gateway ingestion path forwards the
-- original message as .eml/.msg evidence, which is the single most common way
-- malicious content enters a report. Object level refuses it regardless.
UPDATE platform_role SET permissions = permissions || '{
    "can_upload_evidence": true
}'::jsonb
 WHERE name = 'SERVICE_ACCOUNT';
