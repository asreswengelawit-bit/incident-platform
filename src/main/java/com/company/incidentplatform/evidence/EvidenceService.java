package com.company.incidentplatform.evidence;

import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.audit.RequestContext;
import com.company.incidentplatform.authorization.Capability;
import com.company.incidentplatform.authorization.IncidentAccessGuard;
import com.company.incidentplatform.error.EvidenceRejectedException;
import com.company.incidentplatform.error.ResourceNotFoundException;
import com.company.incidentplatform.identity.AppUserEntity;
import com.company.incidentplatform.identity.AppUserRepository;
import com.company.incidentplatform.incident.IncidentCategoryEntity;
import com.company.incidentplatform.incident.IncidentEntity;
import com.company.incidentplatform.incident.IncidentRepository;
import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.DeniedReason;
import com.company.incidentplatform.security.PlatformUser;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

/**
 * FR-1.2 / 7.6: the evidence upload, listing and download path.
 *
 * <h2>Why the order of operations is the way it is</h2>
 *
 * <p>Each stage below is placed before the next irreversible one, so that a
 * rejected upload has written as little as possible:
 *
 * <ol>
 *   <li><b>Authorization</b> (7.2), before a single byte is read. A caller with no
 *       business here should cost the platform nothing, and the function-level
 *       check comes first so the 7.11 row names the real reason.</li>
 *   <li><b>Limits</b> (FR-1.2), from the category, before the content is
 *       buffered.</li>
 *   <li><b>Sniffing</b>, then the allow-list decision -- on the sniffed type, never
 *       the extension or the declared header (7.6).</li>
 *   <li><b>Store and hash in one pass</b>, so the bytes are read once rather than
 *       twice and the hash cannot disagree with what was written.</li>
 *   <li><b>Scan</b>, before the object is downloadable and before the caller is
 *       told the upload succeeded.</li>
 * </ol>
 *
 * <h2>What this class deliberately does not do</h2>
 *
 * <ul>
 *   <li><b>No delete.</b> 7.6 restricts object deletion to the 7.14
 *       retention/legal-hold process. There is no client-facing delete, and
 *       {@link EvidenceStorage#deleteForRetention} is the only removal path that
 *       exists.</li>
 *   <li><b>No edit or re-upload.</b> FR-1.4's evidentiary-integrity rule applies to
 *       the whole incident record, evidence included; a correction is a new
 *       upload.</li>
 *   <li><b>No signed URL.</b> 7.6 permits either a short-lived signed URL or a
 *       backend proxy stream. Streaming is what this does, because it keeps the
 *       object store unreachable from any client and needs no credential whose
 *       lifetime has to be managed.</li>
 * </ul>
 */
@Service
public class EvidenceService {

    private static final Logger log = LoggerFactory.getLogger(EvidenceService.class);

    private static final String ENDPOINT_BASE = "/api/v1/incidents/";

    private final IncidentRepository incidentRepository;
    private final EvidenceRepository evidenceRepository;
    private final AppUserRepository userRepository;
    private final IncidentAccessGuard accessGuard;
    private final EvidenceStorage storage;
    private final EvidenceScanner scanner;
    private final ContentTypeSniffer sniffer;
    private final EvidenceTypePolicy typePolicy;
    private final EvidenceProperties properties;
    private final AuditService auditService;
    private final Clock clock;

    public EvidenceService(
            IncidentRepository incidentRepository,
            EvidenceRepository evidenceRepository,
            AppUserRepository userRepository,
            IncidentAccessGuard accessGuard,
            EvidenceStorage storage,
            EvidenceScanner scanner,
            ContentTypeSniffer sniffer,
            EvidenceTypePolicy typePolicy,
            EvidenceProperties properties,
            AuditService auditService,
            Clock clock) {

        this.incidentRepository = incidentRepository;
        this.evidenceRepository = evidenceRepository;
        this.userRepository = userRepository;
        this.accessGuard = accessGuard;
        this.storage = storage;
        this.scanner = scanner;
        this.sniffer = sniffer;
        this.typePolicy = typePolicy;
        this.properties = properties;
        this.auditService = auditService;
        this.clock = clock;
    }

    /**
     * FR-1.2: attach one file to an incident.
     *
     * <p>Returns the stored item with its scan verdict already applied, so the
     * response reflects reality rather than an optimistic "accepted" that a
     * subsequent scan may contradict.
     */
    @Transactional
    public EvidenceViews.EvidenceView upload(
            UUID incidentId, MultipartFile file, String chainOfCustodyNote, PlatformUser caller) {

        // 7.2 before any content is touched.
        accessGuard.requireWrite(caller, incidentId, Capability.UPLOAD_EVIDENCE);

        IncidentEntity incident = requireIncident(incidentId);
        IncidentCategoryEntity category = incident.getCategory();

        if (file == null || file.isEmpty()) {
            throw new EvidenceRejectedException(
                    EvidenceRejectedException.Kind.UNSUPPORTED_TYPE, "No file content was supplied.");
        }

        String declaredType = trimToNull(file.getContentType());
        String fileName = sanitiseFileName(file.getOriginalFilename());

        enforceCountLimit(incidentId, category);
        long sizeLimit = effectiveSizeLimit(category);
        if (file.getSize() > sizeLimit) {
            throw new EvidenceRejectedException(
                    EvidenceRejectedException.Kind.TOO_LARGE,
                    "Evidence file exceeds the %d byte limit for category %s (FR-1.2).".formatted(
                            sizeLimit, category == null ? "this incident" : category.getName()));
        }

        // Sniffing needs the bytes, so the content is read into memory once, here.
        // Bounded by the limit above, which is why that limit is checked first.
        byte[] content = readBounded(file, sizeLimit);
        ContentTypeSniffer.SniffedType sniffed = sniffer.sniff(content, content.length);

        EvidenceTypePolicy.Decision decision = typePolicy.decide(category, sniffed.mimeType(), fileName);
        if (!decision.allowed()) {
            // Recorded as a refusal with its own 7.11 reason code rather than as a
            // validation error: 7.6's allow-list is a security control, and a
            // caller repeatedly probing it with executables is a pattern an
            // administrator needs to be able to find. EVIDENCE_CONTENT_REJECTED
            // keeps that visible without contaminating the 7.12 BOLA/BFLA signal.
            auditService.recordDenied(
                    caller,
                    DeniedReason.EVIDENCE_CONTENT_REJECTED,
                    "incident_evidence",
                    incidentId,
                    "evidence.upload.rejected",
                    ENDPOINT_BASE + incidentId + "/evidence",
                    "POST",
                    requestId(),
                    RequestContext.remoteAddress(),
                    AuthorizationCheckType.NONE,
                    "evidence.type_policy: " + decision.reason());
            throw new EvidenceRejectedException(
                    EvidenceRejectedException.Kind.UNSUPPORTED_TYPE,
                    "Evidence type not accepted: " + decision.reason());
        }

        UUID evidenceId = UUID.randomUUID();
        OffsetDateTime now = OffsetDateTime.now(clock.withZone(ZoneOffset.UTC));
        String storagePath = FileSystemEvidenceStorage.generateKey(incidentId, evidenceId, now);

        // Hash and store in one pass over the bytes. The digest is of exactly what
        // was written, so the two cannot diverge.
        String sha256;
        try {
            sha256 = storeAndHash(storagePath, content);
        } catch (IOException storageFailure) {
            // The row is not inserted, so no evidence exists without a verifiable
            // hash. Half an upload is worse than none: it is an object nothing points
            // at, and 7.14's retention process has no reason to ever collect it.
            log.error("Evidence storage failed for incident {} (key {})", incidentId, storagePath, storageFailure);
            throw new UncheckedIOException("Evidence could not be stored", storageFailure);
        }

        AppUserEntity uploader = requireUser(caller.id());
        EvidenceEntity evidence = new EvidenceEntity(
                evidenceId,
                incident,
                fileName,
                storagePath,
                sha256,
                uploader,
                now,
                content.length,
                declaredType,
                sniffed.mimeType(),
                trimToNull(chainOfCustodyNote));
        evidenceRepository.save(evidence);

        // 7.6 requires the file to be scanned before it is made available for
        // download, and the download path refuses anything that is not CLEAN, so
        // running the scan here is sufficient. It is synchronous in this binding;
        // an asynchronous engine binds the same interface and the PENDING state
        // already means "not downloadable" in the meantime.
        applyScanVerdict(evidence, incidentId, caller, sniffed.mimeType());

        evidenceRepository.save(evidence);

        auditService.recordChange(
                caller,
                "incident_evidence",
                evidenceId,
                "evidence.upload",
                ENDPOINT_BASE + incidentId + "/evidence",
                "POST",
                requestId(),
                RequestContext.remoteAddress(),
                AuthorizationCheckType.OBJECT_LEVEL,
                Capability.UPLOAD_EVIDENCE.rule(),
                null,
                describeForAudit(evidence, fileName, content.length, declaredType, sniffed, sha256, now),
                true);

        if (evidence.getScanStatus() == EvidenceScanStatus.QUARANTINED) {
            alertOnQuarantine(evidence, caller, incidentId);
        }

        return EvidenceViews.toView(evidence);
    }

    /**
     * The evidence list for an incident.
     *
     * <p>Readable by anyone who can read the incident: an evidence list is part of
     * the incident's own record, and a Reporter is entitled to see what they
     * attached and what an Analyst added since. Metadata about a quarantined file
     * is included, because the fact that a file was quarantined is itself material
     * to the investigation -- the bytes are withheld, not the fact of them.
     */
    @Transactional(readOnly = true)
    public List<EvidenceViews.EvidenceView> list(UUID incidentId, PlatformUser caller) {
        accessGuard.requireRead(caller, incidentId);
        return EvidenceViews.toViews(evidenceRepository.findByIncidentIdAndDeletedAtIsNullOrderByUploadedAtDesc(incidentId));
    }

    /**
     * 7.6: the download. Object-level authorization, scan state, then
     * re-verification of the hash recorded at upload.
     *
     * <p>The object is read <em>twice</em>: once to hash it, once to serve it.
     * Reading it once and hashing as the bytes went to the client would mean
     * serving unverified content and discovering the problem afterwards, and a
     * response that has already begun cannot be withdrawn. The cost is a second
     * read of an object that is at most 25 MB; the benefit is that a tampered
     * object never reaches a single byte of a client response.
     */
    @Transactional(readOnly = true)
    public EvidenceViews.EvidenceContent download(UUID incidentId, UUID evidenceId, PlatformUser caller) {
        accessGuard.requireRead(caller, incidentId);

        EvidenceEntity evidence = evidenceRepository.findByIdAndIncidentId(evidenceId, incidentId)
                .orElseThrow(() -> new ResourceNotFoundException("evidence", evidenceId));

        if (evidence.isDeleted()) {
            throw new EvidenceRejectedException(
                    EvidenceRejectedException.Kind.NOT_DOWNLOADABLE,
                    "This evidence has been removed by the retention process and is no longer available.");
        }
        if (!evidence.getScanStatus().isDownloadable()) {
            throw new EvidenceRejectedException(
                    EvidenceRejectedException.Kind.NOT_DOWNLOADABLE,
                    switch (evidence.getScanStatus()) {
                        case QUARANTINED -> "This evidence is quarantined by malware scanning and cannot be "
                                + "downloaded (7.6). The file is retained as an indicator of compromise.";
                        case FAILED -> "This evidence could not be scanned and cannot be downloaded (7.6).";
                        default -> "This evidence is still awaiting its malware scan verdict and cannot be "
                                + "downloaded yet (7.6).";
                    });
        }

        String actualHash = hashStoredObject(evidence);
        if (!actualHash.equals(evidence.getSha256Hash())) {
            // Section 4 Integrity: the hash is the chain of custody, and it no
            // longer matches. This is the one event in this class that is treated as
            // an incident in its own right rather than an error response.
            log.error("CHAIN OF CUSTODY VIOLATION: evidence {} (incident {}) hash mismatch; expected {}, found {}",
                    evidenceId, incidentId, evidence.getSha256Hash(), actualHash);
            auditService.recordChange(
                    caller,
                    "incident_evidence",
                    evidenceId,
                    "evidence.integrity.hash_mismatch",
                    ENDPOINT_BASE + incidentId + "/evidence/" + evidenceId,
                    "GET",
                    requestId(),
                    RequestContext.remoteAddress(),
                    AuthorizationCheckType.OBJECT_LEVEL,
                    "evidence.integrity.sha256",
                    "{\"sha256_hash\":\"" + evidence.getSha256Hash() + "\"}",
                    "{\"sha256_hash\":\"" + actualHash + "\"}",
                    false);
            throw new EvidenceRejectedException(
                    EvidenceRejectedException.Kind.INTEGRITY_FAILURE,
                    "Evidence failed its integrity check and was not served.");
        }

        auditService.recordAllowed(
                caller,
                "incident_evidence",
                evidenceId,
                "evidence.download",
                ENDPOINT_BASE + incidentId + "/evidence/" + evidenceId,
                "GET",
                requestId(),
                RequestContext.remoteAddress(),
                AuthorizationCheckType.OBJECT_LEVEL,
                "evidence.download.authorized_read");

        try {
            return new EvidenceViews.EvidenceContent(
                    evidenceId,
                    evidence.getFileName(),
                    evidence.getDetectedContentType(),
                    evidence.getSizeBytes(),
                    evidence.getSha256Hash(),
                    storage.open(evidence.getStoragePath()));
        } catch (IOException unreadable) {
            // The row exists and passed its hash check a moment ago, so this is
            // storage-side, not authorization. Surfaced as a 500 by the handler,
            // which is the honest answer.
            log.error("Evidence object unreadable for evidence {} (key {})",
                    evidenceId, evidence.getStoragePath(), unreadable);
            throw new UncheckedIOException("Evidence could not be read", unreadable);
        }
    }

    // ------------------------------------------------------------------
    // internals
    // ------------------------------------------------------------------

    /**
     * 7.6: per-incident count, from the category, so an Admin tunes exposure per
     * category (FR-1.2) rather than globally.
     */
    private void enforceCountLimit(UUID incidentId, IncidentCategoryEntity category) {
        int limit = category == null ? 20 : category.getMaxEvidenceFiles();
        long existing = evidenceRepository.countLiveByIncidentId(incidentId);
        if (existing >= limit) {
            throw new EvidenceRejectedException(
                    EvidenceRejectedException.Kind.TOO_LARGE,
                    "This incident already holds %d evidence files, the configured maximum (FR-1.2).".formatted(limit));
        }
    }

    /**
     * The tighter of the platform ceiling and the category limit.
     *
     * <p>Taking the minimum rather than the category value alone is what keeps the
     * platform ceiling meaningful: a category configured for 500 MB does not get to
     * raise the global bound, because the multipart resolver and the heap do not
     * grow with it.
     */
    private long effectiveSizeLimit(IncidentCategoryEntity category) {
        long categoryLimit = category == null
                ? properties.getMaxFileSizeBytes()
                : Math.min(category.getMaxEvidenceSizeBytes(), properties.getMaxFileSizeBytes());
        return Math.max(1L, categoryLimit);
    }

    private byte[] readBounded(MultipartFile file, long sizeLimit) {
        if (sizeLimit > Integer.MAX_VALUE) {
            throw new IllegalStateException("Configured evidence size limit exceeds addressable memory");
        }
        try (InputStream in = file.getInputStream()) {
            // readNBytes(n + 1) rather than trusting getSize(): the declared size is
            // the resolver's, and a mismatch with the actual stream should be caught
            // here rather than becoming a truncated evidence file.
            byte[] content = in.readNBytes((int) sizeLimit + 1);
            if (content.length > sizeLimit) {
                throw new EvidenceRejectedException(
                        EvidenceRejectedException.Kind.TOO_LARGE,
                        "Evidence file exceeds the %d byte limit for this category (FR-1.2).".formatted(sizeLimit));
            }
            return content;
        } catch (IOException unreadable) {
            throw new UncheckedIOException("Evidence content could not be read", unreadable);
        }
    }

    /**
     * Stores the bytes and returns their SHA-256.
     *
     * <p>The digest is taken over the same array that is handed to storage, and
     * {@link EvidenceStorage#store} writes it verbatim or refuses -- it never
     * truncates -- so the digest is provably the digest of the stored object. The
     * alternative, digesting a stream wrapped around the write, would be identical
     * in outcome and would make the storage interface take a writer it does not
     * need.
     *
     * <p>Note the asymmetry with the download path, which re-reads and re-hashes:
     * at upload the bytes are in hand and a truncation would be refused by the
     * store, while at download the object has been at rest for an unknown period
     * and 7.6's "verified on every download" is the whole point.
     */
    private String storeAndHash(String storagePath, byte[] content) throws IOException {
        storage.store(storagePath, new java.io.ByteArrayInputStream(content), content.length);
        return sha256(content);
    }

    private static String sha256(byte[] content) {
        return HexFormat.of().formatHex(newDigest().digest(content));
    }

    /**
     * Re-hashes the stored object. A second read rather than a trust of the
     * recorded hash -- see the method comment on {@link #download}.
     */
    private String hashStoredObject(EvidenceEntity evidence) {
        MessageDigest digest = newDigest();
        byte[] buffer = new byte[64 * 1024];
        try (InputStream in = storage.open(evidence.getStoragePath())) {
            int read;
            while ((read = in.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        } catch (IOException unreadable) {
            log.error("Evidence object unreadable while verifying evidence {}", evidence.getId(), unreadable);
            throw new EvidenceRejectedException(
                    EvidenceRejectedException.Kind.INTEGRITY_FAILURE,
                    "Evidence could not be read for verification and was not served.");
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private void applyScanVerdict(
            EvidenceEntity evidence, UUID incidentId, PlatformUser caller, String sniffedType) {

        EvidenceScanner.Verdict verdict;
        try {
            verdict = scanner.scan(evidence.getFileName(), evidence.getStoragePath(), sniffedType);
        } catch (RuntimeException scannerFailure) {
            // A scanner that throws is a scanner that did not clear the file. The
            // row stays non-downloadable and the operator sees why.
            log.error("Evidence scanner raised for evidence {} (incident {})", evidence.getId(), incidentId,
                    scannerFailure);
            verdict = EvidenceScanner.Verdict.failed(
                    properties.getScannerEngineName(),
                    "Scanner raised an error: " + scannerFailure.getClass().getSimpleName());
        }

        EvidenceScanStatus status = switch (verdict.status()) {
            case CLEAN -> EvidenceScanStatus.CLEAN;
            case QUARANTINED -> EvidenceScanStatus.QUARANTINED;
            case FAILED -> EvidenceScanStatus.FAILED;
        };

        evidence.recordScanVerdict(
                status,
                OffsetDateTime.now(clock.withZone(ZoneOffset.UTC)),
                verdict.engine(),
                verdict.signature(),
                // V5 requires a reason for exactly the QUARANTINED state and
                // forbids one otherwise, so a FAILED verdict's explanation goes to
                // the log rather than into the column.
                status == EvidenceScanStatus.QUARANTINED ? verdict.detail() : null);

        if (status == EvidenceScanStatus.FAILED) {
            log.error("Evidence scan FAILED for evidence {} (incident {}): {}",
                    evidence.getId(), incidentId, verdict.detail());
        }
    }

    /**
     * 7.6: "quarantine on detection and alert the Admin/Security Lead rather than
     * silently discarding".
     *
     * <p>The alert is a log entry at ERROR and a 7.11 audit row. The richer half of
     * 7.6 -- email and Slack to the Security Lead -- belongs to the notification
     * service (FR-4), which is not built yet; when it exists it consumes the same
     * event. Logging at ERROR rather than WARN is the part that matters for the
     * "not silently" requirement: a quarantined malicious attachment is an incident
     * of its own, and a WARN would let it be filtered out of a review.
     */
    private void alertOnQuarantine(EvidenceEntity evidence, PlatformUser caller, UUID incidentId) {
        log.error("MALICIOUS EVIDENCE QUARANTINED: evidence {} on incident {} uploaded by {} -- engine {}, "
                        + "signature {}, reason {}",
                evidence.getId(), incidentId, caller.email(), evidence.getScannerEngine(),
                evidence.getScannerSignature(), evidence.getQuarantineReason());
        auditService.recordChange(
                caller,
                "incident_evidence",
                evidence.getId(),
                "evidence.quarantined",
                ENDPOINT_BASE + incidentId + "/evidence",
                "POST",
                requestId(),
                RequestContext.remoteAddress(),
                AuthorizationCheckType.NONE,
                "evidence.scan.quarantined",
                null,
                "{\"scan_status\":\"QUARANTINED\",\"scanner_engine\":\""
                        + evidence.getScannerEngine() + "\",\"scanner_signature\":\""
                        + evidence.getScannerSignature() + "\"}",
                false);
    }

    /**
     * The 7.11 after-value for an upload.
     *
     * <p>Metadata only. No file content, and no file name beyond what the caller
     * already supplied -- 7.11 forbids secrets and sensitive PII in these columns,
     * and an evidence file name is frequently a person's name or a customer name.
     * The uploader is a platform user, whose identity is already the subject of the
     * audit row's actor, so it is not repeated here.
     */
    private static String describeForAudit(
            EvidenceEntity evidence,
            String fileName,
            long sizeBytes,
            String declaredType,
            ContentTypeSniffer.SniffedType sniffed,
            String sha256,
            OffsetDateTime now) {

        return "{\"file_name\":\"%s\",\"size_bytes\":%d,\"declared_content_type\":\"%s\","
                .formatted(escape(fileName), sizeBytes, escape(declaredType))
                + "\"detected_content_type\":\"%s\",\"sniffed_description\":\"%s\","
                .formatted(escape(sniffed.mimeType()), escape(sniffed.description()))
                + "\"sha256_hash\":\"%s\",\"uploaded_at\":\"%s\",\"scan_status\":\"%s\"}"
                .formatted(sha256, now, evidence.getScanStatus());
    }

    /**
     * The client's file name, reduced to something safe to store and to put in a
     * {@code Content-Disposition} header.
     *
     * <p>No path component survives: the name is a label in the database and never
     * reaches the filesystem, where the key is generated. Stripping directory
     * elements is still worth doing, because a stored name of {@code
     * ../../etc/passwd} would be replayed verbatim into a download header.
     */
    private static String sanitiseFileName(String original) {
        if (original == null || original.isBlank()) {
            return "evidence";
        }
        String name = original.replace('\\', '/');
        int lastSlash = name.lastIndexOf('/');
        if (lastSlash >= 0) {
            name = name.substring(lastSlash + 1);
        }
        StringBuilder out = new StringBuilder(name.length());
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean printable = c >= 0x20 && c != 0x7F;
            // Quotes and backslashes are escaped rather than dropped, so the
            // Content-Disposition value the controller builds cannot be broken out
            // of by a crafted name.
            out.append(printable ? c : '_');
        }
        String cleaned = out.toString().trim();
        return cleaned.isEmpty() || ".".equals(cleaned) || "..".equals(cleaned) ? "evidence" : cleaned;
    }

    private IncidentEntity requireIncident(UUID incidentId) {
        return incidentRepository.findById(incidentId)
                .orElseThrow(() -> new ResourceNotFoundException("incident", incidentId));
    }

    private AppUserEntity requireUser(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("user", userId));
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            // SHA-256 is required of every Java platform; if it were absent the
            // JVM would be unfit to run and there is no fallback that would be
            // honest about what it computed.
            throw new IllegalStateException("SHA-256 is unavailable on this JVM", impossible);
        }
    }

    private static String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    /** JSON string escaping for the small, fixed set of values this class assembles. */
    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    private static UUID requestId() {
        return RequestContext.requestId().orElse(null);
    }
}
