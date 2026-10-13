package com.company.incidentplatform.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Section 9.1 -- pagination and sort rules for the audit-log list.
 *
 * <p>These are the 7.5 input-validation controls for an endpoint whose backing table
 * is partitioned, append-only, and the highest-cardinality in the schema. Each rule
 * exists because the alternative is a query an authorized caller can shape into a
 * denial of service or a data exfiltration, and "the caller is an Admin" is not a
 * mitigation -- an Admin account that is compromised should not be able to take the
 * audit trail offline or mine it wholesale.
 */
class AuditLogQueryTest {

    private static final Instant BASE = Instant.parse("2026-03-01T00:00:00Z");

    @Nested
    @DisplayName("9.1 page size is clamped, not rejected")
    class PageSize {

        @Test
        @DisplayName("an oversized request becomes the maximum rather than an error")
        void clampsAboveMaximum() {
            assertThat(AuditLogQuery.clampPageSize(100_000)).isEqualTo(AuditLogQuery.MAX_PAGE_SIZE);
        }

        @Test
        @DisplayName("a zero or negative request becomes 1, so LIMIT is never non-positive")
        void clampsToAtLeastOne() {
            // LIMIT 0 would return an empty page indistinguishable from
            // "no entries match", and a negative LIMIT is a database error -- a 500
            // for a malformed request.
            assertThat(AuditLogQuery.clampPageSize(0)).isEqualTo(1);
            assertThat(AuditLogQuery.clampPageSize(-5)).isEqualTo(1);
        }

        @Test
        @DisplayName("a valid size passes through unchanged")
        void keepsValidSize() {
            assertThat(AuditLogQuery.clampPageSize(50)).isEqualTo(50);
        }
    }

    @Nested
    @DisplayName("9.1 sort is restricted to an allow-list")
    class Sort {

        @Test
        @DisplayName("an absent sort field defaults to timestamp, the indexed chain order")
        void defaultsToTimestamp() {
            assertThat(new AuditLogQuery(null, null, null, null, null, null, null, null)
                    .validatedSortBy(null)).isEqualTo("timestamp");
            assertThat(new AuditLogQuery(null, null, null, null, null, null, null, null)
                    .validatedSortBy("  ")).isEqualTo("timestamp");
        }

        @ParameterizedTest(name = "rejects sort field ''{0}''")
        @ValueSource(strings = {"before_value", "actor_role", "ip_address", "entry_hash", "id"})
        @DisplayName("an un-indexed or unknown column is rejected outright")
        void rejectsNonAllowListed(String candidate) {
            // Rejected rather than clamped: an unrecognised sort key has no safe
            // interpretation, so silently substituting a different column would
            // return a plausible, correctly-shaped, wrongly-ordered result set.
            // before_value/actor_role are the dangerous cases -- both are real
            // columns, so a missing allow-list entry would look like it worked.
            assertThatThrownBy(() -> new AuditLogQuery(null, null, null, null, null, null, null, null)
                    .validatedSortBy(candidate))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Invalid sort field");
        }

        @ParameterizedTest(name = "injection attempt ''{0}'' is rejected")
        @ValueSource(strings = {
            "timestamp; DROP TABLE audit_log",
            "timestamp, (SELECT 1)",
            "1",
            "(SELECT null)"
        })
        @DisplayName("a SQL fragment in the sort field cannot reach the statement")
        void rejectsInjectionAttempts(String candidate) {
            assertThatThrownBy(() -> new AuditLogQuery(null, null, null, null, null, null, null, null)
                    .validatedSortBy(candidate))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("the direction defaults to DESC and only honours ASC")
        void validatesDirection() {
            AuditLogQuery query = new AuditLogQuery(null, null, null, null, null, null, null, null);
            assertThat(query.validatedDirection(null)).isEqualTo(AuditLogQuery.SortDirection.DESC);
            assertThat(query.validatedDirection("nonsense")).isEqualTo(AuditLogQuery.SortDirection.DESC);
            // DESC is the default because the newest entry is almost always the one
            // being looked for; a reviewer chasing an incident works backwards.
            assertThat(query.validatedDirection("ASC")).isEqualTo(AuditLogQuery.SortDirection.ASC);
            assertThat(query.validatedDirection("asc")).isEqualTo(AuditLogQuery.SortDirection.ASC);
        }
    }

    @Nested
    @DisplayName("the date range is half-open and bounded")
    class Range {

        @Test
        @DisplayName("an absent bound imposes no constraint")
        void allowsAbsentBounds() {
            new AuditLogQuery(null, null, null, null, null, null, null, null).validateRange();
            new AuditLogQuery(null, null, null, null, null, null, BASE, null).validateRange();
            new AuditLogQuery(null, null, null, null, null, null, null, BASE).validateRange();
        }

        @Test
        @DisplayName("a reversed range is rejected rather than mirrored")
        void rejectsReversedRange() {
            // Swapping silently would return a well-formed page answering a different
            // question than the caller asked, which is worse than a 400.
            assertThatThrownBy(() -> new AuditLogQuery(
                            null, null, null, null, null, null, BASE.plusSeconds(60), BASE)
                    .validateRange())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("strictly after");
        }

        @Test
        @DisplayName("an empty range is rejected, because half-open excludes the endpoint")
        void rejectsEmptyRange() {
            assertThatThrownBy(() -> new AuditLogQuery(
                            null, null, null, null, null, null, BASE, BASE)
                    .validateRange())
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("a range at the maximum width is accepted")
        void acceptsRangeAtMaximum() {
            new AuditLogQuery(null, null, null, null, null, null, BASE,
                    BASE.plusSeconds((long) AuditLogQuery.MAX_RANGE_DAYS * 86400)).validateRange();
        }

        @Test
        @DisplayName("an over-wide range is rejected instead of scanning every partition")
        void rejectsOverWideRange() {
            // Without this, from=1970&to=2100 asks the partitioned table to touch
            // every partition ever created, on a request parameter.
            assertThatThrownBy(() -> new AuditLogQuery(
                            null, null, null, null, null, null, BASE,
                            BASE.plusSeconds((long) (AuditLogQuery.MAX_RANGE_DAYS + 1) * 86400))
                    .validateRange())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must not exceed");
        }
    }

    @Nested
    @DisplayName("the sort field reaches SQL only through a fixed mapping")
    class ColumnMapping {

        @Test
        @DisplayName("allow-listed fields map to constant column expressions")
        void mapsAllowListedFields() {
            assertThat(AuditLogQueryRepository.columnFor("timestamp")).isEqualTo("a.timestamp");
            assertThat(AuditLogQueryRepository.columnFor("action")).isEqualTo("a.action");
        }

        @Test
        @DisplayName("anything else is refused at the mapping, not just at validation")
        void refusesUnmappedField() {
            // Defence in depth. validatedSortBy is the intended gate; this is the
            // last point before string concatenation into the statement, so a future
            // caller that skips the gate still cannot inject.
            assertThatThrownBy(() -> AuditLogQueryRepository.columnFor("a.timestamp; DROP TABLE x"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("not allow-listed");
        }
    }

    @Test
    @DisplayName("a query carries only the filter set Section 9 documents")
    void filterSetIsClosed() {
        // Guards against a free-text search being added: an audit log is the single
        // most attractive target for LIKE-based probing, and 7.7's API inventory
        // exists so undocumented query shapes cannot appear.
        assertThat(AuditLogQuery.ALLOWED_SORT_FIELDS).containsExactlyInAnyOrder("timestamp", "action");
        assertThat(AuditLogQuery.MAX_PAGE_SIZE).isEqualTo(100);
    }

    @Test
    @DisplayName("the query record is immutable, so a filter cannot be swapped mid-flight")
    void queryIsImmutable() {
        UUID actor = UUID.randomUUID();
        AuditLogQuery query = new AuditLogQuery(null, null, null, null, actor, null, null, null);
        assertThat(query.actorId()).isEqualTo(actor);
        assertThat(query.action()).isNull();
    }
}
