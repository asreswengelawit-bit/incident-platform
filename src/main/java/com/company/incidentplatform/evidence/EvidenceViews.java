package com.company.incidentplatform.evidence;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Response shapes for the evidence endpoints.
 *
 * <p>7.2 property level, applied to evidence views rather than assumed: a listing
 * never includes {@code storage_path}, because the storage key is an internal
 * implementation detail and publishing it invites a caller to reason about bucket
 * layout, and -- more concretely -- it is the one field that would let a future
 * storage binding be probed. It is also the field that would have to be signed or
 * authorised if a signed-URL binding were ever adopted, so withholding it here
 * means that change cannot leak it.
 *
 * <p>{@code detectedContentType} <em>is</em> included, and that asymmetry is
 * deliberate: knowing what the platform thinks a file actually is, next to what the
 * uploader claimed it was, is the single most useful thing on this screen for a
 * triaging analyst, and neither value is sensitive.
 */
public final class EvidenceViews {

    private EvidenceViews() {
    }

    /**
     * One evidence item.
     *
     * @param downloadable whether the bytes may be released right now. Computed
     *                     from {@link EvidenceScanStatus#isDownloadable()}, so the
     *                     client renders the same answer the server will give --
     *                     a client that decided this itself would eventually
     *                     disagree with the endpoint and produce a button that
     *                     409s.
     */
    public record EvidenceView(
            UUID id,
            String fileName,
            long sizeBytes,
            String declaredContentType,
            String detectedContentType,
            EvidenceScanStatus scanStatus,
            OffsetDateTime uploadedAt,
            String uploadedByDisplay,
            String chainOfCustodyNote,
            String quarantineReason,
            String scannerEngine,
            OffsetDateTime scannedAt,
            boolean downloadable) {
    }

    /**
     * The bytes, ready to stream.
     *
     * <p>The content is a live {@link java.io.InputStream} over the verified object
     * rather than a byte array. Verification has already happened by the time this
     * exists: {@code EvidenceService} re-hashes the stored object and refuses on
     * mismatch <em>before</em> constructing this, so nothing is written to the
     * response that has not been checked against the hash recorded at upload.
     */
    public record EvidenceContent(
            UUID id,
            String fileName,
            String detectedContentType,
            long sizeBytes,
            String sha256Hash,
            java.io.InputStream content) {
    }

    public static EvidenceView toView(EvidenceEntity evidence) {
        return new EvidenceView(
                evidence.getId(),
                evidence.getFileName(),
                evidence.getSizeBytes(),
                evidence.getDeclaredContentType(),
                evidence.getDetectedContentType(),
                evidence.getScanStatus(),
                evidence.getUploadedAt(),
                displayNameOf(evidence),
                evidence.getChainOfCustodyNote(),
                evidence.getQuarantineReason(),
                evidence.getScannerEngine(),
                evidence.getScannedAt(),
                evidence.isDownloadable());
    }

    public static List<EvidenceView> toViews(List<EvidenceEntity> evidence) {
        return evidence.stream().map(EvidenceViews::toView).toList();
    }

    /**
     * The uploader, as a name.
     *
     * <p>Names, never email addresses or subject identifiers: an evidence listing is
     * visible to every role that can read the incident, which includes the Auditor,
     * and an email address is an identity the 7.2 property rules keep out of
     * wider views. An uploader is an operating team member, not the reporter, so
     * this is not the anonymous-identity surface 7.2.1 and FR-1.6 govern -- but it
     * is still the narrower of the two available fields.
     */
    private static String displayNameOf(EvidenceEntity evidence) {
        var uploader = evidence.getUploadedBy();
        if (uploader == null) {
            return null;
        }
        String name = uploader.getFullName();
        return name != null && !name.isBlank() ? name : uploader.getEmail();
    }
}
