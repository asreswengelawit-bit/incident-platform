package com.company.incidentplatform.incident;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

/**
 * Section 8.2 status change request.
 *
 * <p>The shape encodes the decision that FR-2.2 and 12.2 make about <em>how</em>
 * severity is set, and keeping both routes in one record lets the service refuse
 * the ambiguous combination rather than silently preferring one:
 *
 * <ul>
 *   <li><b>{@code New -> Triaged}</b> is "Analyst classifies", and 8.2 requires
 *       "Impact/Likelihood provided in the same request". So {@code impact} and
 *       {@code likelihood} are the inputs, and severity is <em>computed</em> from
 *       the configured matrix. Sending {@code severity} here is rejected:
 *       accepting it would make severity choosable, which is exactly what 12.2
 *       says must not happen ("the resulting Severity is computed from this
 *       table, not chosen directly").</li>
 *   <li><b>Every other transition</b> may carry {@code severity} only as an
 *       override, which requires {@code can_override_severity} and a reason --
 *       the rationale being analyst-only under 7.2 property-level
 *       authorization, and attributable under 7.3.</li>
 * </ul>
 */
public record ChangeStatusRequest(
        @NotNull(message = "Target status is required")
        IncidentStatus status,

        // FR-2.2 / 12.1 ranks, 1..4. Required for New -> Triaged.
        Integer impact,

        Integer likelihood,

        // Severity override. Requires can_override_severity + reason, and is
        // rejected outright on New -> Triaged.
        IncidentSeverity severity,

        // Required for Triaged -> Assigned
        UUID assigneeId,

        // Required for Triaged -> Rejected, Resolved/Closed -> Reopened, and for
        // any severity override
        String reason,

        // Required for Contained -> Resolved (FR-3.3)
        String resolutionSummary) {
}
