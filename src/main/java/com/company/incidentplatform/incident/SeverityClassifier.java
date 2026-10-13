package com.company.incidentplatform.incident;

import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * FR-2.2 / Section 12.2 -- classification as a lookup, not a hard-coded table.
 *
 * <p>Section 12.2: "An Analyst selects Impact and Likelihood at classification;
 * the resulting Severity is computed from this table, not chosen directly --
 * this keeps severity assignment consistent across analysts and auditable (the
 * audit log records the Impact/Likelihood inputs, not just the resulting
 * Severity)." Section 5.5 names the pattern: the mapping is a swappable rule, so
 * an FR-6.2 matrix change is data, not a deployment.
 *
 * <p>The returned {@link Classification} carries the inputs alongside the result
 * for exactly that audit reason -- a trail holding only "HIGH" cannot show
 * whether the Analyst judged the impact Severe and the likelihood Unlikely, or
 * Moderate and Confirmed, and 7.11 asks for the former.
 */
@Service
public class SeverityClassifier {

    private final SeverityMatrixRepository matrix;

    public SeverityClassifier(SeverityMatrixRepository matrix) {
        this.matrix = matrix;
    }

    /**
     * Computes severity from the configured matrix.
     *
     * <p>Fails closed when the cell is absent or deactivated. The alternatives
     * are worse: defaulting to MEDIUM would let a half-configured matrix
     * understate incidents silently, and refusing to classify at all would
     * block triage entirely. Rejecting the single request that needs the missing
     * cell keeps the failure attributable to the configuration gap that caused
     * it, and leaves every already-classified incident unaffected.
     */
    @Transactional(readOnly = true)
    public Classification classify(ImpactLevel impact, LikelihoodLevel likelihood) {
        if (impact == null || likelihood == null) {
            throw new IllegalArgumentException(
                    "Impact and likelihood are both required to classify an incident (FR-2.2, Section 12.2)");
        }

        Optional<SeverityMatrixRuleEntity> cell = matrix.findByImpactAndLikelihoodAndIsActiveTrue(
                (short) impact.rank(), (short) likelihood.rank());

        SeverityMatrixRuleEntity rule = cell.orElseThrow(() -> new IllegalStateException(
                "No active severity_matrix_rule for impact=" + impact.rank()
                        + " likelihood=" + likelihood.rank()
                        + " (Section 12.2 defines 16 cells). The severity matrix is incomplete or the cell is "
                        + "deactivated; an Admin must configure it before this incident can be classified."));

        return new Classification(impact, likelihood, rule.getSeverity(), rule.getJustification());
    }

    /**
     * One classification decision: the two inputs, the resulting severity, and
     * the rule text that produced it.
     *
     * <p>{@code rule} is what 7.11's audit row cites, in place of a severity
     * string that would otherwise be unattributable -- "matrix.1x3" identifies
     * the exact cell, so a later reviewer can see the grid as it stood when the
     * incident was classified rather than as it stands now.
     */
    public record Classification(
            ImpactLevel impact,
            LikelihoodLevel likelihood,
            IncidentSeverity severity,
            String justification) {

        /** Stable, filterable rule identifier for the 7.11 audit trail. */
        public String rule() {
            return "severity_matrix." + impact.rank() + "x" + likelihood.rank();
        }
    }
}
