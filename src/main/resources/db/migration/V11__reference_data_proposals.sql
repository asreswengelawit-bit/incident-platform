-- ============================================================================
-- V11  Reference data: severity matrix, incident categories, resolution SLAs
-- Spec: 12.2 (impact x likelihood grid -- "this is the exact grid to seed into
--       severity_matrix_rule (16 rows, one per cell)"), FR-6.2 (default seed
--       categories, each with a starting default_sla_hours "approximating the
--       severity table in Section 12.3 for that category's typical severity"),
--       12.3 (per-severity target resolution SLA), 12 (Section 12 status note:
--       "default proposal, not yet stakeholder-confirmed ... a reasonable
--       industry-standard starting point so Phase 2+ isn't blocked ... confirm
--       or adjust the actual numbers with stakeholders before production").
--
-- SUPER-SEDES the "deliberately left empty" comments in V3 and V10, which were
-- written against an earlier draft of the document in which Section 12 defined
-- categories, the grid and resolution SLAs as absent/stakeholder content. The
-- current document version 1.0 (2026-09-23) specifies all three explicitly.
--
-- Every row is commented as a PROPOSAL, not a stakeholder-confirmed value:
-- Admin can change all of it thereafter through the FR-6.2 configuration
-- endpoints, which is exactly what Section 12's status note asks for. No code
-- change is required to adjust a number.
--
-- Confirmed decision (Phase 1 review): impact and likelihood are encoded as
-- 1-4 ranks, 1 = MOST severe (SeveRE<->Confirmed corner of the 12.2 table) and
-- 4 = LEAST (Minor/Unlikely), matching the document's table layout so
-- "escalate one step" means incrementing/decrementing by one. The V3
-- CHECK constraints (BETWEEN 1 AND 5) are widened because 12.1 defines exactly
-- four levels per axis; a five-level extension is not part of the document.
-- ============================================================================

SET search_path TO incident_platform, public;

-- ---------------------------------------------------------------------------
-- 1. Widen the matrix rank columns from 1..5 to 1..4 (Section 12.1 defines
--    exactly four impact and four likelihood levels). V3's CHECKs are replaced,
--    not edited in place -- migrations are immutable.
-- ---------------------------------------------------------------------------
ALTER TABLE severity_matrix_rule
    DROP CONSTRAINT ck_severity_matrix_impact,
    DROP CONSTRAINT ck_severity_matrix_likelihood;

ALTER TABLE severity_matrix_rule
    ADD CONSTRAINT ck_severity_matrix_impact
        CHECK (impact BETWEEN 1 AND 4),
    ADD CONSTRAINT ck_severity_matrix_likelihood
        CHECK (likelihood BETWEEN 1 AND 4);

COMMENT ON COLUMN severity_matrix_rule.impact IS
    'Section 12.1. 1..4 rank, 1 = Severe, 2 = Major, 3 = Moderate, 4 = Minor. Confirmed Phase-1 decision; maps 1:1 to the 12.2 grid rows.';
COMMENT ON COLUMN severity_matrix_rule.likelihood IS
    'Section 12.1. 1..4 rank, 1 = Confirmed, 2 = Likely, 3 = Possible, 4 = Unlikely. Confirmed Phase-1 decision; maps 1:1 to the 12.2 grid columns.';

-- ---------------------------------------------------------------------------
-- 2. Severity matrix -- Section 12.2, all 16 cells. Proposal values.
-- ---------------------------------------------------------------------------
INSERT INTO severity_matrix_rule (impact, likelihood, severity, justification) VALUES
    -- Severe (impact 1) row
    (1, 1, 'CRITICAL', '12.2: Severe x Confirmed -> Critical'),
    (1, 2, 'CRITICAL', '12.2: Severe x Likely -> Critical'),
    (1, 3, 'HIGH',     '12.2: Severe x Possible -> High'),
    (1, 4, 'MEDIUM',   '12.2: Severe x Unlikely -> Medium'),
    -- Major (impact 2) row
    (2, 1, 'CRITICAL', '12.2: Major x Confirmed -> Critical'),
    (2, 2, 'HIGH',     '12.2: Major x Likely -> High'),
    (2, 3, 'HIGH',     '12.2: Major x Possible -> High'),
    (2, 4, 'MEDIUM',   '12.2: Major x Unlikely -> Medium'),
    -- Moderate (impact 3) row
    (3, 1, 'HIGH',     '12.2: Moderate x Confirmed -> High'),
    (3, 2, 'MEDIUM',   '12.2: Moderate x Likely -> Medium'),
    (3, 3, 'MEDIUM',   '12.2: Moderate x Possible -> Medium'),
    (3, 4, 'LOW',      '12.2: Moderate x Unlikely -> Low'),
    -- Minor (impact 4) row
    (4, 1, 'MEDIUM',   '12.2: Minor x Confirmed -> Medium'),
    (4, 2, 'LOW',      '12.2: Minor x Likely -> Low'),
    (4, 3, 'LOW',      '12.2: Minor x Possible -> Low'),
    (4, 4, 'LOW',      '12.2: Minor x Unlikely -> Low')
ON CONFLICT (impact, likelihood) DO NOTHING;

COMMENT ON TABLE severity_matrix_rule IS
    'Section 12.2 -- 16 proposal cells seeded by V11. PROPOSAL status: values are industry-standard starting points, not stakeholder-confirmed. Admin-adjustable via the FR-6.2 configuration endpoints.';

-- ---------------------------------------------------------------------------
-- 3. Default incident categories -- FR-6.2 "Default seed categories
--    (Admin-editable/extensible thereafter, not fixed)": Phishing, Malware,
--    Unauthorized Access, Password/Account Compromise, Data Leakage, Lost or
--    Stolen Device, Suspicious Network Activity, Social Engineering,
--    Denial-of-Service Attack, Policy Violation.
--
--    default_sla_hours "approximating the severity table in Section 12.3 for
--    that category's typical severity" -- PROPOSAL typical-severity assignment
--    and the corresponding Section 12.3 response SLA in hours (rounded up to
--    a whole hour for the 15-minute Critical response).
--
--    Per-category MIME allow-lists (incident_category_allowed_type, 7.6) are
--    deliberately left EMPTY: the document specifies the seven example types in
--    Section 7.6 but never a per-category mapping, so seeding one would invent
--    stakeholder content. Effects on the upload path are a decision for Phase 4.
-- ---------------------------------------------------------------------------
INSERT INTO incident_category (name, description, default_sla_hours) VALUES
    ('Phishing',
     'Reports of fraudulent emails/messages attempting to steal credentials or install malware (Section 12.3 Medium example). Proposal: typical severity Medium -> 4h response.',
     4),
    ('Malware',
     'Virus, ransomware or other malicious software on a system (Section 12.3 Critical example). Proposal: typical severity High -> 1h response.',
     1),
    ('Unauthorized Access',
     'Unexpected access to an account, system or network resource. Proposal: typical severity High -> 1h response.',
     1),
    ('Password/Account Compromise',
     'Evidence a password or account has been compromised (Section 12.3 High example). Proposal: typical severity High -> 1h response.',
     1),
    ('Data Leakage',
     'Sensitive data disclosed outside authorised channels. Proposal: typical severity High -> 1h response.',
     1),
    ('Lost or Stolen Device',
     'Lost/stolen laptop, phone or media (Section 12.3 Low example). Proposal: typical severity Medium -> 4h response.',
     4),
    ('Suspicious Network Activity',
     'Unusual network behaviour possibly indicating a compromise. Proposal: typical severity Medium -> 4h response.',
     4),
    ('Social Engineering',
     'Attack relying on human interaction to deceive (vishing, smishing, impersonation). Proposal: typical severity Medium -> 4h response.',
     4),
    ('Denial-of-Service Attack',
     'Availability incident -- service overloaded/unresponsive (Section 12.3 Critical example). Proposal: typical severity Critical -> 15 min response, rounded up to 1h for the integer column.',
     1),
    ('Policy Violation',
     'Breach of an internal security policy with no immediate confidentiality/integrity impact. Proposal: typical severity Low -> 1 business day response.',
     24)
ON CONFLICT (name) DO NOTHING;

COMMENT ON TABLE incident_category IS
    'FR-6.2 -- 10 default seed categories from V11, PROPOSAL typical-severity/default_sla_hours assignments. Admin-extensible and -editable thereafter; severity of any given incident is still computed per-incident from the 12.2 matrix, never fixed by category.';

-- ---------------------------------------------------------------------------
-- 4. Resolution SLAs -- Section 12.3 "Target Resolution SLA": Critical 4 hours,
--    High 1 business day (24h), Medium 3 business days, Low 10 business days.
--    V10 seeded the response column only; these UPDATE the same four rows.
--
--    Encoding note (flagged, proposal): for the two business-day targets the
--    column stores the calendar-day equivalent in minutes (3 * 24h = 4320,
--    10 * 24h = 14400) and marks business_hours_only = true. The document
--    defines no working-hours calendar (start/end time, holidays), which is
--    what computation of a business-hours deadline needs; sla_due_at
--    derivation in the service layer (Phase 3) will treat a business-hours
--    row as requiring calendar-day counting until an Admin-configured calendar
--    exists. The numbers are proposals per Section 12's status note.
-- ---------------------------------------------------------------------------
UPDATE incident_sla_policy
   SET resolution_sla_minutes = 240,
       business_hours_only    = false
 WHERE severity = 'CRITICAL' AND category_id IS NULL;

UPDATE incident_sla_policy
   SET resolution_sla_minutes = 1440,
       business_hours_only    = false
 WHERE severity = 'HIGH' AND category_id IS NULL;

UPDATE incident_sla_policy
   SET resolution_sla_minutes = 4320,
       business_hours_only    = true
 WHERE severity = 'MEDIUM' AND category_id IS NULL;

UPDATE incident_sla_policy
   SET resolution_sla_minutes = 14400,
       business_hours_only    = true
 WHERE severity = 'LOW' AND category_id IS NULL;