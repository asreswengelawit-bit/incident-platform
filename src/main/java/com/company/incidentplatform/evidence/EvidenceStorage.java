package com.company.incidentplatform.evidence;

import java.io.IOException;
import java.io.InputStream;

/**
 * The private object store behind 7.6.
 *
 * <p>An interface rather than a concrete filesystem, because 5.1 puts evidence in
 * object storage and 7.6 describes the production bucket's properties (no public
 * read, minimum-privilege service account, provider-managed encryption keys).
 * Those are properties of a <em>deployment</em>, not of this interface, so the
 * local implementation exists to keep the rest of the code honest and testable
 * while the S3 binding is written.
 *
 * <h2>Why there is no {@code delete}</h2>
 *
 * <p>7.6: "Deletion from object storage is controlled -- only triggered by the
 * retention/legal-hold process (Section 7.14), never by a direct client-facing
 * delete endpoint, and deletion events are audited."
 *
 * <p>An ordinary {@code delete(String)} on a store that evidence flows through
 * would eventually be wired to something. It is named
 * {@link #deleteForRetention} instead, which states in the type what it is
 * allowed to be used for, and takes the reason so the retention process cannot
 * delete without producing the audit row 7.6 requires. No method here is reachable
 * from a controller.
 *
 * <h2>No delete, but also no overwrite</h2>
 *
 * <p>{@link #store} refuses a path that already holds an object. Evidence is
 * immutable (7.6), and a write-once store cannot express an accidental overwrite
 * even if some future caller gets the arguments wrong.
 */
public interface EvidenceStorage {

    /**
     * Writes {@code content} to {@code storagePath} and returns the number of bytes
     * written.
     *
     * <p>Reads at most {@code byteLimit} bytes and fails rather than truncating: a
     * silently truncated evidence file is worse than a rejected one, because its
     * hash would be recorded as authoritative for content that is not what was
     * uploaded.
     *
     * <p>Implementations must make the write atomic from a reader's point of view:
     * a partially written object must never be readable, or a download concurrent
     * with an upload would fail its SHA-256 check for a reason that has nothing to
     * do with tampering.
     */
    long store(String storagePath, InputStream content, long byteLimit) throws IOException;

    /**
     * Opens the object for reading. The caller closes it.
     *
     * <p>Opened rather than copied to a byte array so a 25 MB download does not
     * become 25 MB of heap, and so the evidence bytes exist in exactly one place.
     */
    InputStream open(String storagePath) throws IOException;

    boolean exists(String storagePath);

    /** 7.14 only. Never reachable from a client-facing endpoint. */
    void deleteForRetention(String storagePath, String reason) throws IOException;
}
