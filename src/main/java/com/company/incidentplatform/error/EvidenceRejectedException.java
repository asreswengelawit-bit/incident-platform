package com.company.incidentplatform.error;

/**
 * 7.6 refused an evidence upload or download.
 *
 * <p>Split from {@link ConflictException} because the four situations are not the
 * same answer to a client and each needs a distinct status for the frontend to
 * react usefully:
 *
 * <ul>
 *   <li>{@link Kind#UNSUPPORTED_TYPE} -- 415. The bytes are not an accepted
 *       evidence type. Retrying with the same file will fail again, but retrying
 *       with a different file will not.</li>
 *   <li>{@link Kind#TOO_LARGE} -- 413. The per-file or per-incident limit was hit
 *       (FR-1.2).</li>
 *   <li>{@link Kind#NOT_DOWNLOADABLE} -- 409. The caller is authorized, the file
 *       exists, and it is quarantined or awaiting a scan verdict. Deliberately not
 *       a 403: permission is not the obstacle, and telling the caller otherwise
 *       sends an administrator to fix the wrong control. Deliberately not a 404
 *       either -- the caller is entitled to know the file is held, since they can
 *       already see it listed.</li>
 *   <li>{@link Kind#INTEGRITY_FAILURE} -- 409. The SHA-256 of the stored object no
 *       longer matches the hash recorded at upload. Nothing is served; this is a
 *       chain-of-custody incident (7.6, Section 4 Integrity), and the response
 *       body deliberately says nothing beyond the fact.</li>
 * </ul>
 *
 * <p>The message is safe to return: it is written here, in the application, from
 * the policy's own reasoning. No file content, no sniffed bytes, and no internal
 * path ever reach it.
 */
public class EvidenceRejectedException extends RuntimeException {

    public enum Kind {
        UNSUPPORTED_TYPE,
        TOO_LARGE,
        NOT_DOWNLOADABLE,
        INTEGRITY_FAILURE
    }

    private final Kind kind;

    public EvidenceRejectedException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public Kind getKind() {
        return kind;
    }
}
