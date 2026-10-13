package com.company.incidentplatform.evidence;

/**
 * Section 7.6 scan state, mirroring the {@code evidence_scan_status} enum in
 * {@code V1__baseline_schema_and_vocabularies.sql} and the column defaults and
 * check constraints in {@code V5__evidence.sql}.
 *
 * <p>The states exist because "was this file scanned?" cannot be answered by a
 * boolean. {@link #PENDING} and {@link #SCANNING} are the difference between a
 * file that is still being examined and one nobody has looked at yet, and both
 * are <em>undownloadable</em>: 7.6 requires scanning "before it is persisted or
 * made available for download", so a file whose scan has not completed is not
 * yet releasable, and collapsing PENDING into CLEAN on a schema that only had
 * two states is how unscanned uploads get served.
 *
 * <p>{@link #QUARANTINED} and {@link #FAILED} are both retained rather than
 * discarded -- 7.6 is explicit that a malicious attachment is itself an indicator
 * worth investigating, so deleting it would destroy the evidence of the attempt.
 * {@code V5} enforces the pairing of QUARANTINED with a stated reason and of
 * every terminal state with a named engine and a completion time.
 */
public enum EvidenceScanStatus {

    /** Row exists, bytes are stored, no verdict yet. Not downloadable. */
    PENDING,

    /** A scanner has claimed the file and is working on it. Not downloadable. */
    SCANNING,

    /** Scanned and cleared. The only state from which bytes may be released. */
    CLEAN,

    /** Detected as malicious or as active content. Retained, alerted, never served. */
    QUARANTINED,

    /** The scanner itself failed -- an unreachable engine, a timeout, a corrupt object. */
    FAILED;

    /**
     * The single predicate 7.6's download rule depends on.
     *
     * <p>Written as an explicit "only CLEAN" rather than "not
     * QUARANTINED/FAILED", so that a new enum constant added later is
     * undownloadable by default instead of inheriting access.
     */
    public boolean isDownloadable() {
        return this == CLEAN;
    }

    public boolean isTerminal() {
        return this == CLEAN || this == QUARANTINED || this == FAILED;
    }
}
