package com.company.incidentplatform.audit;

import java.time.Instant;
import java.util.UUID;

/**
 * One row of {@code audit_log}, as read.
 *
 * <p>A plain carrier rather than a JPA entity, and deliberately so. 7.11 and 7.16
 * make the table append-only at the database level -- the runtime role holds no
 * {@code UPDATE}/{@code DELETE} grant and triggers reject mutation outright -- so
 * there is nothing for an ORM to write through. Mapping it as an entity would
 * suggest a mutability that the database will refuse, and {@code @Version}
 * optimistic locking would imply an update path that must not exist.
 *
 * <p>{@code previousHash} and {@code entryHash} are carried as hex because they
 * are chain evidence: 7.11 asks for tamper detection, and a reviewer comparing
 * two entries needs the actual values, not a boolean.
 *
 * <p>There is deliberately no {@code anonymousReporterActor} flag here. Whether a
 * row's actor is a protected anonymous reporter is a fact about the <em>incident</em>,
 * not about the row, and the service resolves it from the incident table for the
 * page in hand. Putting the flag on the record would invite a future caller to
 * read a value that is always false and conclude nobody needs protecting.
 *
 * <p>{@code actorKeycloakSubject} is projected but never surfaced in the API view.
 * The {@code app_user} id and the email are what an investigator needs to attribute
 * an action, and the raw OIDC {@code sub} is a third identifier for the same person
 * that buys them nothing while surviving account deletion and re-creation. It stays
 * on the record because the row is a faithful projection of the table, not because
 * it should be handed out.
 */
public record AuditLogEntry(
        UUID id,
        Instant timestamp,
        UUID actorId,
        String actorRole,
        String actorKeycloakSubject,
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
        String previousHash,
        String entryHash) {
}
