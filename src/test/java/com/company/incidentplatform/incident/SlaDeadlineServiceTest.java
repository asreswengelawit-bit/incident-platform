package com.company.incidentplatform.incident;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Section 6.3 / 12.3 -- SLA deadline derivation and the precedence between the
 * three sources.
 *
 * <p>6.3 fixes the rule: "Where the two disagree, the more specific
 * severity-level target here takes precedence over the category-level default."
 * That precedence is the thing worth pinning down, because a silent inversion
 * would not fail visibly -- every incident would still have a deadline, just the
 * wrong one, and the breach reports would be confidently false.
 */
class SlaDeadlineServiceTest {

    private final IncidentSlaPolicyRepository policies = mock(IncidentSlaPolicyRepository.class);
    private final SlaDeadlineService deadlines = new SlaDeadlineService(policies);

    private static final UUID CATEGORY = UUID.fromString("00000000-0000-0000-0000-0000000000c9");
    private static final OffsetDateTime FROM = OffsetDateTime.parse("2026-03-01T10:00:00Z");

    private IncidentCategoryEntity category(int defaultSlaHours) {
        return new IncidentCategoryEntity(
                CATEGORY, "Malware", "Malware and ransomware", defaultSlaHours,
                84, 10_485_760L, 5, true, FROM, FROM);
    }

    private IncidentSlaPolicyEntity policy(
            UUID categoryId, IncidentSeverity severity, int responseMinutes, Integer resolutionMinutes) {
        return new IncidentSlaPolicyEntity(
                UUID.randomUUID(), categoryId, severity, responseMinutes, resolutionMinutes,
                false, true, FROM, FROM);
    }

    @Nested
    @DisplayName("6.3 precedence: category policy, then organisation policy, then the category default")
    class Precedence {

        @Test
        @DisplayName("a category-specific policy wins over the organisation-wide policy")
        void categoryPolicyWins() {
            when(policies.findByCategoryIdAndSeverityAndIsActiveTrue(CATEGORY, IncidentSeverity.HIGH))
                    .thenReturn(Optional.of(
                            policy(CATEGORY, IncidentSeverity.HIGH, 30, 240)));

            var result = deadlines.compute(category(72), IncidentSeverity.HIGH, FROM);

            assertThat(result.responseDue()).isEqualTo(FROM.plusMinutes(30));
            assertThat(result.resolutionDue()).isEqualTo(FROM.plusMinutes(240));
            assertThat(result.sourceCategoryId()).isEqualTo(CATEGORY);
            assertThat(result.rule()).isEqualTo("sla_policy.high.category");
        }

        @Test
        @DisplayName("with no category row, the organisation-wide row for that severity applies")
        void fallsBackToOrganisationPolicy() {
            when(policies.findByCategoryIdAndSeverityAndIsActiveTrue(CATEGORY, IncidentSeverity.LOW))
                    .thenReturn(Optional.empty());
            when(policies.findByCategoryIdIsNullAndSeverityAndIsActiveTrue(IncidentSeverity.LOW))
                    .thenReturn(Optional.of(
                            policy(null, IncidentSeverity.LOW, 1440, null)));

            var result = deadlines.compute(category(72), IncidentSeverity.LOW, FROM);

            assertThat(result.responseDue()).isEqualTo(FROM.plusMinutes(1440));
            // A NULL resolution target leaves the deadline unset rather than
            // borrowing the response one: they measure different things, and a
            // resolution deadline that silently equals the response deadline is a
            // breach report nobody can trust.
            assertThat(result.resolutionDue()).isNull();
            assertThat(result.rule()).isEqualTo("sla_policy.low.org_default");
        }

        @Test
        @DisplayName("with no policy rows at all, the category default still produces a deadline")
        void fallsBackToCategoryDefault() {
            when(policies.findByCategoryIdAndSeverityAndIsActiveTrue(CATEGORY, IncidentSeverity.CRITICAL))
                    .thenReturn(Optional.empty());
            when(policies.findByCategoryIdIsNullAndSeverityAndIsActiveTrue(IncidentSeverity.CRITICAL))
                    .thenReturn(Optional.empty());

            var result = deadlines.compute(category(24), IncidentSeverity.CRITICAL, FROM);

            assertThat(result.responseDue()).isEqualTo(FROM.plusHours(24));
            assertThat(result.resolutionDue()).isEqualTo(FROM.plusHours(24));
            assertThat(result.rule()).isEqualTo("category.default_sla_hours");
        }
    }

    @Nested
    @DisplayName("intake before classification")
    class Unclassified {

        @Test
        @DisplayName("no severity means no severity-level target exists, so the category default applies")
        void severityOptionalAtIntake() {
            var result = deadlines.compute(category(48), null, FROM);

            assertThat(result.responseDue()).isEqualTo(FROM.plusHours(48));
            assertThat(result.resolutionDue()).isEqualTo(FROM.plusHours(48));
            assertThat(result.rule()).isEqualTo("category.default_sla_hours");
        }
    }

    @Nested
    @DisplayName("recalculation inputs")
    class Inputs {

        @Test
        @DisplayName("a missing base timestamp is refused rather than defaulted to now")
        void requiresBaseTimestamp() {
            assertThatThrownBy(() -> deadlines.compute(category(24), IncidentSeverity.HIGH, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("base timestamp");
        }
    }
}
