package com.company.incidentplatform.evidence;

/**
 * 7.6: "Malware/AV scanning of every upload before it is persisted or made
 * downloadable; quarantine on detection and alert the Admin/Security Lead rather
 * than silently discarding."
 *
 * <p>Two halves of that sentence are separate concerns and are separated here.
 * The interface is the <em>scanner</em>. The alerting half is
 * {@link EvidenceService}'s job, because it is the only place that knows the
 * incident, the uploader and the audit context -- a scanner that tried to notify
 * would be a component with opinions about who to email.
 *
 * <p>Implementations must be conservative in one specific way: an error while
 * scanning is a {@link Verdict#failed} outcome, never a {@link Verdict#clean} one.
 * A scanner that cannot reach its engine has not established that a file is safe,
 * and reporting "clean" would let an outage of the AV service turn into an open
 * distribution channel for whatever was uploaded during it.
 */
public interface EvidenceScanner {

    /**
     * @param fileName    sanitised display name, for engine reporting only
     * @param storagePath key of the stored object
     * @param contentType the sniffed type, so an engine can be told what it is
     *                    looking at
     */
    Verdict scan(String fileName, String storagePath, String contentType);

    /**
     * A scan outcome.
     *
     * <p>{@code signature} is the engine's own identification of what it found
     * ("Win.Test.EICAR_HDB-1", "Heuristics.OfficeMacro"), not a free-text
     * comment: it is stored in {@code scanner_signature} and is what an
     * investigator matches against threat intelligence.
     *
     * <p>{@code detail} is the human-readable reason, stored in
     * {@code quarantine_reason} -- which {@code V5} requires to be present exactly
     * when the status is QUARANTINED.
     */
    record Verdict(Status status, String engine, String signature, String detail) {

        public enum Status {
            CLEAN,
            QUARANTINED,
            FAILED
        }

        public static Verdict clean(String engine) {
            return new Verdict(Status.CLEAN, engine, null, null);
        }

        public static Verdict quarantined(String engine, String signature, String detail) {
            return new Verdict(Status.QUARANTINED, engine, signature, detail);
        }

        public static Verdict failed(String engine, String detail) {
            return new Verdict(Status.FAILED, engine, null, detail);
        }
    }
}
