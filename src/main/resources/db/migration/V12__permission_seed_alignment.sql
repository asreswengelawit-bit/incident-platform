-- ============================================================================
-- V12  Permission seed alignment
-- Spec: 2 ("Decision -- anonymous reporter identity"), 3.1 FR-1.1, 3.2 FR-2.4
--       (investigation notes), FR-1.4/FR-2.8 (comments), 7.2 function-level
--       capabilities, 6.2.3 (platform_role.permissions is the fine-grained
--       authority).
--
-- Two kinds of change, both to the *seed* only:
--
--   1. Keys this codebase now reads which V10's seed did not carry. Every flag
--      defaults to false when absent (RolePermissions), so a missing key is not
--      a latent bug -- it is a role that silently cannot perform the action.
--      These are granted below to the roles Section 2 assigns them to.
--
--   2. One REMOVAL: V10 seeded SECURITY_ADMIN with can_view_reporter_identity
--      true. Section 2's confirmed decision is the opposite -- "Default state:
--      granted to no one by default in a fresh deployment; the Security
--      Administrator explicitly grants it -- to themself, or to a low-privilege
--      account ... as a deliberate, audited action, rather than it being an
--      implicit power of the Admin role." The test fixtures (TestFixtures) already
--      model the decided behaviour; the seed did not, so a fresh deployment would
--      have contradicted the decision it is supposed to implement.
--
-- Migrations are immutable, so the removal is an UPDATE here rather than an edit
-- to V10. jsonb - keys on the same row are additive and order-independent, so
-- `||` merges without disturbing the flags already seeded.
--
-- Everything below remains Admin-configurable at runtime (FR-6.2); this is only
-- the starting position.
-- ============================================================================

SET search_path TO incident_platform, public;

-- ---------------------------------------------------------------------------
-- REPORTER -- FR-1.1 create a report, FR-1.4 follow up on their own report.
-- Section 2 defines the Reporter as "any authenticated user of the
-- organization", so this is not a privilege -- it is the intake path the
-- Platform exists to provide. A Reporter still cannot see anyone else's
-- incident: that is 7.2.1 object-level, and is not affected by any key here.
-- ---------------------------------------------------------------------------
UPDATE platform_role SET permissions = permissions || '{
    "can_create_incident": true,
    "can_comment": true
}'::jsonb
 WHERE name = 'REPORTER';

-- ---------------------------------------------------------------------------
-- ANALYST -- 8.2 places an Analyst in the New -> Triaged edge, and Section 2
-- gives the role "all reporter rights plus" investigation rights. `can_classify`
-- and `can_assign_self` were already seeded; `can_add_investigation_note` was
-- not, and FR-2.4 ("Analysts record investigation notes") requires it.
-- ---------------------------------------------------------------------------
UPDATE platform_role SET permissions = permissions || '{
    "can_create_incident": true,
    "can_comment": true,
    "can_add_investigation_note": true
}'::jsonb
 WHERE name = 'ANALYST';

-- ---------------------------------------------------------------------------
-- SECURITY_LEAD -- Section 2: "All analyst rights + reassign, escalate, override
-- severity, approve closure". V10 seeded the second half of that sentence and
-- omitted the first, which left the role unable to record a Response Action
-- (FR-2.5) or classify an incident at 8.2's New -> Triaged edge, and therefore
-- unable to triage at all. Recording actions is also a precondition of
-- FR-3.3's closure gate, so without it a Lead could approve closure of an
-- incident nobody in their role had been able to work.
-- ---------------------------------------------------------------------------
UPDATE platform_role SET permissions = permissions || '{
    "can_create_incident": true,
    "can_comment": true,
    "can_add_investigation_note": true,
    "can_record_response_action": true,
    "can_classify": true,
    "can_assign_self": true
}'::jsonb
 WHERE name = 'SECURITY_LEAD';

-- ---------------------------------------------------------------------------
-- SECURITY_ADMIN -- Section 2 is platform administration, not incident-workflow
-- execution. Section 8.2 is explicit that Admin is deliberately absent from the
-- transition matrix, and 7.3 requires Admin to hold no blanket override over the
-- maker-checker gates. So no incident-workflow capability is granted here, and
-- `can_view_reporter_identity` is explicitly withdrawn per the Section 2
-- decision quoted at the top of this file.
--
-- `can_comment` is granted because Section 2 makes this an ordinary user of the
-- organization for reporting purposes and FR-1.4/FR-2.8 comments are a
-- two-way channel; it confers no read access outside 7.2.1's ORGANIZATION scope,
-- which the role already has as a platform administrator.
-- ---------------------------------------------------------------------------
UPDATE platform_role
   SET permissions = (permissions - 'can_view_reporter_identity') || '{
    "can_create_incident": true,
    "can_comment": true,
    "can_view_reporter_identity": false
}'::jsonb
 WHERE name = 'SECURITY_ADMIN';

-- ---------------------------------------------------------------------------
-- AUDITOR -- unchanged, and stated explicitly so the omission is a decision.
-- Section 2: "Read-only access to incidents, audit logs, and reports; cannot
-- modify data." `read_only` is enforced as a blanket write refusal in
-- IncidentAccessGuard, so granting any write capability here would be inert
-- anyway; recording the denial in the seed makes the intent reviewable.
-- ---------------------------------------------------------------------------
UPDATE platform_role SET permissions = permissions || '{
    "can_create_incident": false,
    "can_comment": false,
    "can_add_investigation_note": false,
    "can_record_response_action": false
}'::jsonb
 WHERE name = 'AUDITOR';

-- ---------------------------------------------------------------------------
-- SERVICE_ACCOUNT -- Section 5.4's synchronous ingestion path. `can_create_
-- incident` is granted because Section 9 lists "Reporter, Service Account" for
-- POST /api/v1/incidents; the ingestion path additionally requires
-- `can_ingest_incidents` (already seeded), so a Service Account granted one
-- without the other still cannot post.
--
-- No read capability is granted. VisibilityScope.NONE already means the role can
-- never read an incident back, which is what stops ingestion from becoming a
-- covert organisation-wide read channel.
-- ---------------------------------------------------------------------------
UPDATE platform_role SET permissions = permissions || '{
    "can_create_incident": true
}'::jsonb
 WHERE name = 'SERVICE_ACCOUNT';
