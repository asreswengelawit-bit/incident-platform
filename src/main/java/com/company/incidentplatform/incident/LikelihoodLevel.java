package com.company.incidentplatform.incident;

/**
 * Section 12.1 likelihood levels, and the {@code severity_matrix_rule.likelihood}
 * rank they map to.
 *
 * <p>Same confirmed rank encoding as {@link ImpactLevel}: 1 = Confirmed, 4 =
 * Unlikely, following the column order of the 12.2 table.
 */
public enum LikelihoodLevel {

    CONFIRMED(1, "Actively occurring or verified to have occurred"),
    LIKELY(2, "Strong indicators, not yet fully confirmed"),
    POSSIBLE(3, "Plausible but unconfirmed, requires investigation to establish"),
    UNLIKELY(4, "Weak/circumstantial indicators, probable false positive");

    private final int rank;
    private final String definition;

    LikelihoodLevel(int rank, String definition) {
        this.rank = rank;
        this.definition = definition;
    }

    /** 1..4, matching {@code severity_matrix_rule.likelihood}. */
    public int rank() {
        return rank;
    }

    /** Section 12.1 wording, surfaced to the Analyst choosing the likelihood. */
    public String definition() {
        return definition;
    }

    /** Fails closed for the same reason as {@link ImpactLevel#fromRank}. */
    public static LikelihoodLevel fromRank(Integer rank) {
        if (rank == null) {
            throw new IllegalArgumentException("Likelihood rank is required (Section 12.1: 1..4)");
        }
        for (LikelihoodLevel level : values()) {
            if (level.rank == rank) {
                return level;
            }
        }
        throw new IllegalArgumentException("Likelihood rank must be 1..4 (Section 12.1); received " + rank);
    }
}
