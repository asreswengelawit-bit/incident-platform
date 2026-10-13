package com.company.incidentplatform.authorization;

import java.util.List;
import java.util.UUID;

/**
 * The data a view is built from, and the shape returned to clients.
 *
 * <p>Exists so the property-level rules of 7.2.3 can be implemented and tested
 * without the full incident aggregate (which Phase 3 assembles). Keeping the
 * view as a distinct type rather than a serialised entity is the enforcement
 * mechanism for property-level authorization: 7.2.3 requires that a field be
 * <em>unavailable</em> to a role, and a field is only reliably unavailable if
 * the code path that would have read it does not exist for that role.
 *
 * <p>Serialising the entity and letting the SPA hide fields is the pattern this
 * exists to prevent -- the data still leaves the server over the wire and is
 * trivially recovered from devtools.
 */
public final class IncidentViews {

    private IncidentViews() {
    }

    /** Everything a Reporter, Analyst, Lead, Admin, or Auditor may see. */
    public record BaseView(
            UUID id,
            String referenceNumber,
            String title,
            String description,
            String categoryName,
            String severity,
            String status,
            boolean escalated,
            String affectedSystem,
            String affectedDepartment,
            boolean anonymous,
            boolean containsPii,
            String reportedAt,
            String occurredAt,
            String resolvedAt,
            UUID reporterId,
            String reporterDisplayName,
            String reporterEmail,
            UUID assigneeId,
            String assigneeDisplayName,
            UUID groupId,
            List<UUID> collaboratorUserIds) {
    }

    /**
     * Adds investigation notes, response actions, and the timeline, which
     * 7.2.3 gates behind {@code can_view_investigation_notes}.
     */
    public record InvestigationView(
            BaseView base,
            List<String> notes,
            List<String> actions,
            List<TimelineEntry> timeline) {

        public record TimelineEntry(String fromStatus, String toStatus, String changedBy, String changedAt, String reason) {
        }
    }

    /**
     * FR-1.6 anonymous reporting. {@code reporterDisplayName} and
     * {@code reporterEmail} are replaced with a placeholder unless the caller
     * holds {@code can_view_reporter_identity}, which is granted to no one by
     * default. The placeholder is deliberate and constant so that the response
     * shape does not vary with authorization, which would itself be a signal.
     */
    public record ReporterIdentityView(
            UUID reporterId,
            String reporterDisplayName,
            String reporterEmail,
            String reporterDepartment,
            boolean identityWithheld,
            String withheldNotice) {
    }
}
