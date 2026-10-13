package com.company.incidentplatform.incident;

/**
 * Section 12.1 impact levels, and the {@code severity_matrix_rule.impact} rank
 * they map to.
 *
 * <p>Rank encoding is the confirmed Phase-1 decision recorded in
 * {@code V11__reference_data_proposals.sql}: {@code 1} is the most severe
 * (Severe) and {@code 4} the least (Minor), matching the row order of the
 * document's 12.2 table. Encoding the rank on the enum rather than storing a
 * bare integer means an out-of-range impact cannot be persisted through this
 * path, and "one step more severe" is a decrement rather than an arithmetic
 * expression a caller has to get right.
 */
public enum ImpactLevel {

    SEVERE(1, "Business-critical systems down, large-scale data breach, or safety/legal exposure"),
    MAJOR(2, "Significant single-system compromise or data exposure, contained blast radius"),
    MODERATE(3, "Limited operational disruption or exposure, one user/system affected"),
    MINOR(4, "Negligible operational impact, policy-level concern only");

    private final int rank;
    private final String definition;

    ImpactLevel(int rank, String definition) {
        this.rank = rank;
        this.definition = definition;
    }

    /** 1..4, matching {@code severity_matrix_rule.impact}. */
    public int rank() {
        return rank;
    }

    /** Section 12.1 wording, surfaced to the Analyst choosing the impact. */
    public String definition() {
        return definition;
    }

    /**
     * Resolves a client-supplied rank. Fails closed: an unrecognised value is an
     * error, not a default. Defaulting an unknown impact to MODERATE would let
     * a malformed client request quietly understate a Critical incident's blast
     * radius, and the resulting severity is computed, not chosen -- so a wrong
     * rank produces a wrong severity that still looks plausible downstream.
     */
    public static ImpactLevel fromRank(Integer rank) {
        if (rank == null) {
            throw new IllegalArgumentException("Impact rank is required (Section 12.1: 1..4)");
        }
        for (ImpactLevel level : values()) {
            if (level.rank == rank) {
                return level;
            }
        }
        throw new IllegalArgumentException("Impact rank must be 1..4 (Section 12.1); received " + rank);
    }
}
