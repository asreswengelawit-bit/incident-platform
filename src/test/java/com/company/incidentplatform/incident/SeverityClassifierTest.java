package com.company.incidentplatform.incident;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * FR-2.2 / Section 12.2 -- severity is computed, not chosen.
 *
 * <p>The property under test is 12.2's: "the resulting Severity is computed from
 * this table, not chosen directly". A classifier that could be talked into
 * returning a caller's preferred severity would still produce plausible incident
 * data, so the tests check both directions -- the right cell produces the right
 * severity, and no input can reach around the table.
 */
class SeverityClassifierTest {

    private final SeverityMatrixRepository matrix = mock(SeverityMatrixRepository.class);
    private final SeverityClassifier classifier = new SeverityClassifier(matrix);

    private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-01-15T09:00:00Z");

    private void cellReturns(ImpactLevel impact, LikelihoodLevel likelihood, IncidentSeverity severity) {
        when(matrix.findByImpactAndLikelihoodAndIsActiveTrue(
                (short) impact.rank(), (short) likelihood.rank()))
                .thenReturn(Optional.of(cell(impact, likelihood, severity)));
    }

    private static SeverityMatrixRuleEntity cell(
            ImpactLevel impact, LikelihoodLevel likelihood, IncidentSeverity severity) {
        return new SeverityMatrixRuleEntity(
                UUID.randomUUID(), (short) impact.rank(), (short) likelihood.rank(), severity,
                "Test cell", true, NOW, NOW);
    }

    @Nested
    @DisplayName("Section 12.2 matrix lookup")
    class MatrixLookup {

        @Test
        @DisplayName("a configured cell yields the configured severity")
        void classifiesFromTheMatrix() {
            cellReturns(ImpactLevel.MINOR, LikelihoodLevel.POSSIBLE, IncidentSeverity.LOW);

            var classification = classifier.classify(ImpactLevel.MINOR, LikelihoodLevel.POSSIBLE);

            assertThat(classification.severity()).isEqualTo(IncidentSeverity.LOW);
        }

        @Test
        @DisplayName("the audit rule names the exact cell, so a later matrix edit is distinguishable")
        void ruleIdentifiesTheCell() {
            cellReturns(ImpactLevel.SEVERE, LikelihoodLevel.LIKELY, IncidentSeverity.HIGH);

            assertThat(classifier.classify(ImpactLevel.SEVERE, LikelihoodLevel.LIKELY).rule())
                    .isEqualTo("severity_matrix.1x2");
        }

        @Test
        @DisplayName("the two inputs travel with the result, because 12.2 makes them the auditable artifact")
        void carriesItsInputs() {
            cellReturns(ImpactLevel.MODERATE, LikelihoodLevel.CONFIRMED, IncidentSeverity.MEDIUM);

            var classification = classifier.classify(ImpactLevel.MODERATE, LikelihoodLevel.CONFIRMED);

            assertThat(classification.impact()).isEqualTo(ImpactLevel.MODERATE);
            assertThat(classification.likelihood()).isEqualTo(LikelihoodLevel.CONFIRMED);
            assertThat(classification.justification()).isEqualTo("Test cell");
        }

        @Test
        @DisplayName("the query is made on the rank, so the 1..4 encoding is what the matrix is keyed on")
        void queriesByRank() {
            cellReturns(ImpactLevel.SEVERE, LikelihoodLevel.CONFIRMED, IncidentSeverity.CRITICAL);

            classifier.classify(ImpactLevel.SEVERE, LikelihoodLevel.CONFIRMED);

            verify(matrix).findByImpactAndLikelihoodAndIsActiveTrue((short) 1, (short) 1);
        }
    }

    @Nested
    @DisplayName("12.1 ranks are 1..4 with 1 most severe")
    class Ranks {

        @ParameterizedTest(name = "impact rank {0} is {1}")
        @CsvSource({
                "SEVERE, 1",
                "MAJOR, 2",
                "MODERATE, 3",
                "MINOR, 4"
        })
        void impactRanks(ImpactLevel level, int expected) {
            assertThat(level.rank()).isEqualTo(expected);
        }

        @ParameterizedTest(name = "likelihood rank {0} is {1}")
        @CsvSource({
                "CONFIRMED, 1",
                "LIKELY, 2",
                "POSSIBLE, 3",
                "UNLIKELY, 4"
        })
        void likelihoodRanks(LikelihoodLevel level, int expected) {
            assertThat(level.rank()).isEqualTo(expected);
        }

        @Test
        @DisplayName("rank round-trips, so a stored rank decodes to the same level")
        void ranksRoundTrip() {
            for (ImpactLevel impact : ImpactLevel.values()) {
                assertThat(ImpactLevel.fromRank(impact.rank())).isEqualTo(impact);
            }
            for (LikelihoodLevel likelihood : LikelihoodLevel.values()) {
                assertThat(LikelihoodLevel.fromRank(likelihood.rank())).isEqualTo(likelihood);
            }
        }
    }

    @Nested
    @DisplayName("fails closed rather than guessing")
    class FailsClosed {

        @Test
        @DisplayName("a missing or deactivated cell is refused, not defaulted to MEDIUM")
        void missingCellThrows() {
            when(matrix.findByImpactAndLikelihoodAndIsActiveTrue((short) 2, (short) 2))
                    .thenReturn(Optional.empty());

            assertThatThrownBy(() -> classifier.classify(ImpactLevel.MODERATE, LikelihoodLevel.LIKELY))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("severity_matrix_rule");
        }

        @Test
        @DisplayName("either input missing is refused before the matrix is consulted")
        void missingInputThrows() {
            assertThatThrownBy(() -> classifier.classify(null, LikelihoodLevel.LIKELY))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("required");

            assertThatThrownBy(() -> classifier.classify(ImpactLevel.MODERATE, null))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
