package com.company.incidentplatform.incident;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * The shapes the investigation endpoints return.
 *
 * <p>Kept separate from the entities for the same reason {@code IncidentViews}
 * exists: 7.2 property-level authorization is only reliable when the restricted
 * value is reachable through a type the unauthorized caller never receives.
 * A comment view is deliberately <em>not</em> gated -- it is the shared channel
 * -- whereas the note view is only ever built for a caller that passed the
 * {@code can_add_investigation_note} / {@code can_view_investigation_notes}
 * checks, and the note list is never assembled for anyone else.
 */
public final class InvestigationViews {

    private InvestigationViews() {
    }

    /**
     * FR-2.4. Includes the author because a note is only useful as an
     * investigation record if it is attributable.
     */
    public record NoteView(
            UUID id,
            String authorDisplayName,
            String note,
            OffsetDateTime createdAt,
            boolean containsPii) {
    }

    /**
     * FR-2.5. The type is returned as its code alongside the stored text, so a
     * client can key off the command without parsing a human-readable label.
     */
    public record ActionView(
            UUID id,
            String actionType,
            String actionTypeCode,
            String description,
            String outcome,
            String performedByDisplayName,
            OffsetDateTime performedAt) {
    }

    /**
     * FR-1.4 / FR-2.8. {@code authorIsReporter} is included because a Reporter
     * reading the thread needs to tell their own messages from a reply, and
     * comparing UUIDs client-side would mean serialising a user directory into
     * the SPA.
     */
    public record CommentView(
            UUID id,
            String authorDisplayName,
            String comment,
            OffsetDateTime createdAt,
            boolean containsPii,
            boolean authorIsIncidentReporter) {
    }
}
