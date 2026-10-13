package com.company.incidentplatform.audit;

import com.company.incidentplatform.authorization.Capability;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * 7.2 property level / Section 9 -- what an audit-log query returns.
 *
 * <p>7.2 requires response DTOs to be role-specific, and the audit log is the
 * case where that matters most: it is the one resource where the full record and
 * the safe record differ by a field, and where the full record is more sensitive
 * than the thing being audited. {@link AuditLogEntry} is never serialized
 * directly.
 *
 * <h2>The FR-1.6 problem this class exists to solve</h2>
 *
 * <p>An audit row for creating an anonymous report carries {@code actor_id} =
 * the whistleblower's user id, because {@code AuditService} attributes every
 * entry to its authenticated actor and 7.1 requires audit history to stay
 * permanently attributable even after the actor's role changes. Both requirements
 * are correct, and together they mean the audit log contains a direct answer to
 * "who reported this anonymously?".
 *
 * <p>FR-1.6 requires that true identity "is accessible only to a specifically
 * authorized role ... and that access itself is a distinct, separately-audited
 * action (its own {@code AUDIT_LOG} entry -- 'identity of anonymous report #X
 * viewed by Y')". An audit-log browser that returned {@code actorId}
 * unconditionally would therefore be a way to learn a protected identity while
 * generating <em>no</em> identity-access entry -- the disclosure happens, the
 * accountability record for it does not. That is the failure mode FR-1.6's clause
 * is written against, and building the read endpoint without addressing it would
 * create the hole rather than close it.
 *
 * <p>So {@code actorId} on an anonymous reporter's row is withheld by default and
 * surfaced only to a caller holding {@code can_view_reporter_identity}, and the
 * service writes the FR-1.6 entry when it does surface one. Withholding rather
 * than deleting is deliberate: the value stays in the table, where 7.1's
 * attribution requirement and a properly-authorised reviewer can still reach it.
 */
public final class AuditLogViews {

    /** Shown in place of a withheld {@code actorId}, so the omission is visible rather than blank. */
    public static final String WITHHELD_ACTOR_LABEL = "[withheld: anonymous reporter (FR-1.6)]";

    private AuditLogViews() {
    }

    /**
     * @param actorIdWithheld true when {@code actorId} was suppressed under FR-1.6;
     *                        the field is null exactly when this is true
     */
    public record AuditEntryView(
            UUID id,
            Instant timestamp,
            UUID actorId,
            String actorIdLabel,
            String actorRole,
            String entityType,
            UUID entityId,
            String action,
            String result,
            String reasonCode,
            String reasonDetail,
            String endpoint,
            String method,
            UUID requestId,
            String authorizationCheck,
            String authorizationRule,
            String ipAddress,
            String beforeValue,
            String afterValue,
            boolean piiRedacted,
            String entryHash,
            String previousHash,
            boolean actorIdWithheld) {
    }

    /**
     * Builds one row's view.
     *
     * @param suppressActor whether FR-1.6 withholds this row's actor
     */
    static AuditEntryView toView(AuditLogEntry entry, boolean suppressActor) {
        return new AuditEntryView(
                entry.id(),
                entry.timestamp(),
                suppressActor ? null : entry.actorId(),
                suppressActor ? WITHHELD_ACTOR_LABEL : null,
                entry.actorRole(),
                entry.entityType(),
                entry.entityId(),
                entry.action(),
                entry.result(),
                entry.reasonCode(),
                entry.reasonDetail(),
                entry.endpoint(),
                entry.method(),
                entry.requestId(),
                entry.authorizationCheck(),
                entry.authorizationRule(),
                entry.ipAddress(),
                entry.beforeValue(),
                entry.afterValue(),
                entry.piiRedacted(),
                entry.entryHash(),
                entry.previousHash(),
                suppressActor);
    }

    /** 7.11 chain verification result for a window. */
    public record ChainVerificationView(
            boolean intact,
            Instant from,
            Instant to,
            int problemsFound,
            boolean truncated,
            List<AuditLogQueryRepository.ChainProblem> problems) {
    }

    /**
     * 7.11 grants audit-log read to Admin and Auditor, and {@code can_view_audit_log}
     * carries that in {@code V10}. The enforcement point is deliberately
     * {@link Capability#VIEW_AUDIT_LOG} against the caller's current permissions, not
     * a role comparison here: FR-6.2 requires an Admin to be able to grant or revoke
     * the capability at runtime, and a hard-coded role list would silently override
     * that. This class therefore holds no role knowledge at all.
     */
}
