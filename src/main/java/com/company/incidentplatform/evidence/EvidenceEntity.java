package com.company.incidentplatform.evidence;

import com.company.incidentplatform.identity.AppUserEntity;
import com.company.incidentplatform.incident.IncidentEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * INCIDENT_EVIDENCE (Section 6.1, FR-1.2, 7.6).
 *
 * <p>Metadata only. The bytes live in a private storage bucket; this row is the
 * chain-of-custody record, and {@link #getSha256Hash()} is the part that has to
 * be trustworthy forever -- Section 4's Integrity requirement and 7.6 both make
 * the hash the thing that is re-verified on every download.
 *
 * <p>Immutability of the identifying columns is enforced by a database trigger in
 * {@code V5__evidence.sql}, not only by this class being free of setters. That is
 * deliberate: a service-layer convention is one refactor, or one native query,
 * away from being bypassed, and the columns a trigger protects are the columns
 * whose alteration would silently rewrite custody history. Scan-state columns are
 * the exception and are deliberately mutable, because they are written by the
 * scanner after insertion.
 */
@Entity
@Table(name = "incident_evidence")
public class EvidenceEntity {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "incident_id", nullable = false)
    private IncidentEntity incident;

    /**
     * The display name as supplied by the uploader, sanitised. It is a label, not
     * a path: the storage key is generated, and no component of this value ever
     * reaches the filesystem.
     */
    @Column(name = "file_name", nullable = false)
    private String fileName;

    @Column(name = "storage_path", nullable = false)
    private String storagePath;

    @Column(name = "sha256_hash", nullable = false)
    private String sha256Hash;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "uploaded_by", nullable = false)
    private AppUserEntity uploadedBy;

    @Column(name = "uploaded_at", nullable = false)
    private OffsetDateTime uploadedAt;

    @Column(name = "size_bytes", nullable = false)
    private long sizeBytes;

    /** Client-supplied and untrusted. Recorded for forensics, never trusted for a decision. */
    @Column(name = "declared_content_type")
    private String declaredContentType;

    /** 7.6: the sniffed type, and the only thing an allow-list decision may use. */
    @Column(name = "detected_content_type")
    private String detectedContentType;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.NAMED_ENUM)
    @Column(name = "scan_status", nullable = false)
    private EvidenceScanStatus scanStatus;

    @Column(name = "scanned_at")
    private OffsetDateTime scannedAt;

    @Column(name = "scanner_engine")
    private String scannerEngine;

    @Column(name = "scanner_signature")
    private String scannerSignature;

    @Column(name = "quarantine_reason")
    private String quarantineReason;

    @Column(name = "chain_of_custody_note")
    private String chainOfCustodyNote;

    @Column(name = "deleted_at")
    private OffsetDateTime deletedAt;

    protected EvidenceEntity() {
    }

    public EvidenceEntity(
            UUID id,
            IncidentEntity incident,
            String fileName,
            String storagePath,
            String sha256Hash,
            AppUserEntity uploadedBy,
            OffsetDateTime uploadedAt,
            long sizeBytes,
            String declaredContentType,
            String detectedContentType,
            String chainOfCustodyNote) {

        this.id = id;
        this.incident = incident;
        this.fileName = fileName;
        this.storagePath = storagePath;
        this.sha256Hash = sha256Hash;
        this.uploadedBy = uploadedBy;
        this.uploadedAt = uploadedAt;
        this.sizeBytes = sizeBytes;
        this.declaredContentType = declaredContentType;
        this.detectedContentType = detectedContentType;
        this.scanStatus = EvidenceScanStatus.PENDING;
        this.chainOfCustodyNote = chainOfCustodyNote;
    }

    /**
     * Records a scanner verdict.
     *
     * <p>The only mutation this entity permits, and it cannot touch anything the
     * {@code V5} trigger protects. {@code scannedAt} and {@code engine} are
     * mandatory for a terminal verdict rather than optional metadata: 7.6's
     * "CLEAN" claim is only meaningful if there is a name to hold accountable for
     * having made it, and {@code V5} enforces the same pairing in a check
     * constraint for the same reason.
     */
    public void recordScanVerdict(
            EvidenceScanStatus status,
            OffsetDateTime scannedAt,
            String engine,
            String signature,
            String quarantineReason) {

        this.scanStatus = status;
        this.scannedAt = scannedAt;
        this.scannerEngine = engine;
        this.scannerSignature = signature;
        this.quarantineReason = quarantineReason;
    }

    public UUID getId() {
        return id;
    }

    public IncidentEntity getIncident() {
        return incident;
    }

    public String getFileName() {
        return fileName;
    }

    public String getStoragePath() {
        return storagePath;
    }

    public String getSha256Hash() {
        return sha256Hash;
    }

    public AppUserEntity getUploadedBy() {
        return uploadedBy;
    }

    public OffsetDateTime getUploadedAt() {
        return uploadedAt;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public String getDeclaredContentType() {
        return declaredContentType;
    }

    public String getDetectedContentType() {
        return detectedContentType;
    }

    public EvidenceScanStatus getScanStatus() {
        return scanStatus;
    }

    public OffsetDateTime getScannedAt() {
        return scannedAt;
    }

    public String getScannerEngine() {
        return scannerEngine;
    }

    public String getScannerSignature() {
        return scannerSignature;
    }

    public String getQuarantineReason() {
        return quarantineReason;
    }

    public String getChainOfCustodyNote() {
        return chainOfCustodyNote;
    }

    public OffsetDateTime getDeletedAt() {
        return deletedAt;
    }

    public boolean isDeleted() {
        return deletedAt != null;
    }

    public boolean isDownloadable() {
        return !isDeleted() && scanStatus.isDownloadable();
    }
}
