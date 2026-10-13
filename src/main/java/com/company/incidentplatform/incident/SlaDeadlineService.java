package com.company.incidentplatform.incident;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Section 6.3 / 12.3 -- derivation of the denormalized {@code sla_due_at} and
 * {@code sla_response_due_at} timestamps on {@code incident}.
 *
 * <p>6.3 explains why the deadline is stored rather than computed per read: SLA
 * breach dashboard queries would otherwise re-join and re-calculate on every
 * request, on the same transactional path incident reporting uses. It also fixes
 * the precedence this class implements:
 *
 * <blockquote>Where the two disagree, the more specific severity-level target
 * here takes precedence over the category-level default.</blockquote>
 *
 * <p>Concretely, for a given (category, severity): a category-specific policy row
 * wins; otherwise the organisation-wide row for that severity; otherwise the
 * category's {@code default_sla_hours}. The last fallback is what keeps a
 * deployment with no policy rows at all from having no deadlines.
 *
 * <p>Business-hours arithmetic is deliberately not implemented. The document
 * defines no working-hours calendar -- no start/end time, no holiday list -- and
 * inventing one would silently produce deadlines no stakeholder agreed to, on
 * the two Low/Medium targets V11 marked {@code business_hours_only}. Rows so
 * marked are counted in calendar time, which is the conservative direction for a
 * Medium target and the flagged behaviour recorded in
 * {@code V11__reference_data_proposals.sql}.
 */
@Service
public class SlaDeadlineService {

    private final IncidentSlaPolicyRepository policies;

    public SlaDeadlineService(IncidentSlaPolicyRepository policies) {
        this.policies = policies;
    }

    /**
     * Computes both deadlines for an incident.
     *
     * <p>Called at intake and again on every classification or category change;
     * 6.3 requires that recalculation be audited, which the caller does, since
     * only it knows the actor and the before/after values.
     */
    @Transactional(readOnly = true)
    public Deadlines compute(IncidentCategoryEntity category, IncidentSeverity severity, OffsetDateTime from) {
        if (from == null) {
            throw new IllegalArgumentException("SLA deadlines require a base timestamp");
        }

        // No severity yet (FR-1.1: self-assessed severity is optional) means no
        // severity-level target exists, so the category default is all there is.
        if (severity == null) {
            return new Deadlines(
                    from.plusHours(category.getDefaultSlaHours()),
                    from.plusHours(category.getDefaultSlaHours()),
                    null,
                    true,
                    "category.default_sla_hours");
        }

        Optional<IncidentSlaPolicyEntity> policy = resolvePolicy(category, severity);
        if (policy.isEmpty()) {
            return new Deadlines(
                    from.plusHours(category.getDefaultSlaHours()),
                    from.plusHours(category.getDefaultSlaHours()),
                    null,
                    true,
                    "category.default_sla_hours");
        }

        IncidentSlaPolicyEntity effective = policy.get();
        OffsetDateTime responseDue = from.plusMinutes(effective.getResponseSlaMinutes());

        // A NULL resolution target leaves the resolution deadline unset rather
        // than borrowing the response one: they measure different things, and
        // FR-3.3's closure gate is about recorded Response Actions, not a timer.
        OffsetDateTime resolutionDue = effective.getResolutionSlaMinutes() == null
                ? null
                : from.plusMinutes(effective.getResolutionSlaMinutes());

        return new Deadlines(
                responseDue,
                resolutionDue,
                effective.getCategoryId() == null ? null : effective.getCategoryId(),
                effective.isBusinessHoursOnly(),
                "sla_policy." + effective.getSeverity().name().toLowerCase(java.util.Locale.ROOT)
                        + (effective.getCategoryId() == null ? ".org_default" : ".category"));
    }

    private Optional<IncidentSlaPolicyEntity> resolvePolicy(
            IncidentCategoryEntity category, IncidentSeverity severity) {
        return policies.findByCategoryIdAndSeverityAndIsActiveTrue(category.getId(), severity)
                .or(() -> policies.findByCategoryIdIsNullAndSeverityAndIsActiveTrue(severity));
    }

    /**
     * @param responseDue      {@code incident.sla_response_due_at}
     * @param resolutionDue    {@code incident.sla_due_at}; null when no resolution
     *                         target is configured for the effective severity
     * @param businessHoursOnly whether the effective row is marked business-hours;
     *                         recorded, and counted as calendar time (see class
     *                         javadoc)
     * @param rule             the configuration key the deadlines came from, for
     *                         the 7.11 audit row
     */
    public record Deadlines(
            OffsetDateTime responseDue,
            OffsetDateTime resolutionDue,
            UUID sourceCategoryId,
            boolean businessHoursOnly,
            String rule) {
    }
}
