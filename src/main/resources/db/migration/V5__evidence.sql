-- ============================================================================
-- V5  Evidence metadata
-- Spec: 6.1 (INCIDENT_EVIDENCE), 6.2 (sha256_hash supports chain of custody),
--       7.6 (expanded file upload security), 4 Integrity (evidence immutable
--       once uploaded, hash stored at upload and verified on access).
--
-- The database holds METADATA ONLY. Bytes live in a private object-storage
-- bucket (7.6): the browser never talks to object storage directly, the only
-- path to a file is an authorization-checked download endpoint that issues a
-- short-lived signed URL or streams the object itself.
-- ============================================================================

SET search_path TO incident_platform, public;

CREATE TABLE incident_evidence (
    id                     uuid                PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id            uuid                NOT NULL REFERENCES incident (id) ON DELETE CASCADE,
    file_name              text                NOT NULL,
    -- Object-storage key, never a public URL. The bucket has no public read
    -- access at all (7.6).
    storage_path           text                NOT NULL,
    -- Chain of custody. Lowercase hex, verified on EVERY download to detect
    -- tampering or storage corruption.
    sha256_hash            text                NOT NULL,
    uploaded_by            uuid                NOT NULL REFERENCES app_user (id),
    uploaded_at            timestamptz         NOT NULL DEFAULT now(),
    size_bytes             bigint              NOT NULL,

    -- 7.6: reject by content-SNIFFED type, not just the file extension.
    -- `declared_content_type` is client-supplied and untrusted;
    -- `detected_content_type` is what the sniffer determined and is what the
    -- 7.6 allow-list check must be made against.
    declared_content_type  text,
    detected_content_type  text,

    -- 7.6: malware/AV scanning BEFORE the object is persisted as downloadable.
    -- QUARANTINED rows are retained, not discarded, and Admin/Security Lead are
    -- alerted -- a malicious attachment is itself an IOC worth investigating.
    scan_status            evidence_scan_status NOT NULL DEFAULT 'PENDING',
    scanned_at             timestamptz,
    scanner_engine         text,
    scanner_signature      text,
    quarantine_reason      text,

    chain_of_custody_note  text,
    -- 6.2 soft delete. 7.6: deletion from object storage is controlled by the
    -- retention/legal-hold process only (7.14) -- never by a client endpoint.
    deleted_at             timestamptz,

    CONSTRAINT uq_incident_evidence_storage_path UNIQUE (storage_path),
    CONSTRAINT ck_incident_evidence_file_name_not_blank
        CHECK (length(btrim(file_name)) > 0),
    -- 64 lowercase hex characters.
    CONSTRAINT ck_incident_evidence_sha256_format
        CHECK (sha256_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_incident_evidence_size_positive CHECK (size_bytes > 0),
    -- A file may only be QUARANTINED for a stated reason, and may never be
    -- QUARANTINED without one.
    CONSTRAINT ck_incident_evidence_quarantine_reason CHECK (
        (scan_status = 'QUARANTINED') = (quarantine_reason IS NOT NULL)
    ),
    -- A scan verdict requires a completion timestamp and a named engine, so
    -- "CLEAN" can never be asserted without provenance.
    CONSTRAINT ck_incident_evidence_scanned_attribution CHECK (
        scan_status = 'PENDING' OR scan_status = 'SCANNING'
        OR (scanned_at IS NOT NULL AND scanner_engine IS NOT NULL)
    )
);

COMMENT ON COLUMN incident_evidence.detected_content_type IS
    'Content-sniffed type. 7.6 requires rejection on the sniffed type, not the extension -- declared_content_type is client-supplied and must never be the basis of an allow-list decision.';

COMMENT ON COLUMN incident_evidence.scan_status IS
    '7.6: PENDING/SCANNING files are not downloadable; CLEAN files are downloadable after object-level authorization; QUARANTINED/FAILED files are retained as IOCs and alerted to Admin/Security Lead, never silently discarded.';

-- ---------------------------------------------------------------------------
-- 7.6 / 4 Integrity: evidence is immutable post-upload. Enforced at the
-- database level rather than relying on the service layer alone, so chain of
-- custody cannot be rewritten by any application code path.
-- Scan-state columns remain mutable because they are written by the scanner as
-- part of the upload pipeline.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION incident_evidence_enforce_immutability()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.file_name IS DISTINCT FROM OLD.file_name
       OR NEW.storage_path IS DISTINCT FROM OLD.storage_path
       OR NEW.sha256_hash IS DISTINCT FROM OLD.sha256_hash
       OR NEW.uploaded_by IS DISTINCT FROM OLD.uploaded_by
       OR NEW.uploaded_at IS DISTINCT FROM OLD.uploaded_at
       OR NEW.incident_id IS DISTINCT FROM OLD.incident_id THEN
        RAISE EXCEPTION
            'incident_evidence is immutable post-upload (Section 7.6 / 6.2 chain of custody): % cannot be altered after insertion',
            TG_OP
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_incident_evidence_immutable
    BEFORE UPDATE ON incident_evidence
    FOR EACH ROW
    EXECUTE FUNCTION incident_evidence_enforce_immutability();
