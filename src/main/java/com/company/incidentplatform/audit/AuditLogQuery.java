package com.company.incidentplatform.audit;

import java.time.Instant;
import java.util.UUID;

/**
 * FR-6.3 -- the filter set for {@code GET /api/v1/audit-logs}.
 *
 * <p>Every field is optional; a null field means "no constraint on this
 * dimension". Fields are a closed set on purpose. 7.7's API-inventory rule exists
 * so that undocumented query shapes cannot appear, and a free-text "search" box
 * over an audit log is the single most attractive target for the sort of probing
 * 7.12 alerts on: an attacker who can submit arbitrary SQL fragments or wildcards
 * gets a database to reason about.
 *
 * <p>The date range is half-open, {@code [from, to)}, which is what makes
 * consecutive windows tile without double-counting a boundary entry -- the
 * property that lets 7.11's periodic chain verification run over successive
 * months and still cover every entry exactly once.
 */
public record AuditLogQuery(
        String result,
        String action,
        String entityType,
        UUID entityId,
        UUID actorId,
        UUID requestId,
        Instant from,
        Instant to) {

    /**
     * 9.1 filter limits: "Filter values ... capped at a reasonable count (e.g.
     * 50) per request". The audit log's filters are single-valued, so the cap that
     * applies is on the <em>width</em> of the range rather than on a list length.
     *
     * <p>Without it, {@code from} far in the past and {@code to} far in the
     * future would ask the partitioned table to scan every partition ever
     * created, which is a denial-of-service primitive available to any Admin or
     * Auditor -- and both of those roles are, by design, heavily privileged, so
     * the query is not attacker-controlled in the usual sense. It is still
     * unbounded work initiated from a request parameter.
     */
    public static final int MAX_RANGE_DAYS = 366;

    /** 9.1: sort is restricted to an allow-list of indexed columns. */
    public static final java.util.Set<String> ALLOWED_SORT_FIELDS = java.util.Set.of("timestamp", "action");

    /** 9.1 hard maximum, identical to the incident list so the two behave alike. */
    public static final int MAX_PAGE_SIZE = 100;

    public static final int DEFAULT_PAGE_SIZE = 25;

    /**
     * 9.1: the sort field is allow-listed rather than passed through. An
     * unvalidated sort key here is not merely a slow query -- the audit log is the
     * highest-cardinality table in the schema and is partitioned by month, so an
     * arbitrary sort forces a sort of every partition in the window.
     */
    public String validatedSortBy(String requested) {
        if (requested == null || requested.isBlank()) {
            return "timestamp";
        }
        String candidate = requested.trim();
        if (!ALLOWED_SORT_FIELDS.contains(candidate)) {
            throw new IllegalArgumentException(
                    "Invalid sort field '" + requested + "'. Allowed sort fields: "
                            + new java.util.TreeSet<>(ALLOWED_SORT_FIELDS));
        }
        return candidate;
    }

    public SortDirection validatedDirection(String requested) {
        return "ASC".equalsIgnoreCase(requested) ? SortDirection.ASC : SortDirection.DESC;
    }

    /** Clamps rather than rejects, per 9.1: {@code pageSize=10000000} becomes 100. */
    public static int clampPageSize(int requested) {
        return Math.min(Math.max(1, requested), MAX_PAGE_SIZE);
    }

    /**
     * Rejects a range wider than {@link #MAX_RANGE_DAYS}, and a reversed one.
     *
     * <p>Reversed ranges are rejected rather than silently swapped: a caller
     * asking for {@code from} after {@code to} has made a mistake, and quietly
     * returning the mirror image would hand them a result set that looks valid and
     * answers a different question than the one they asked.
     */
    public void validateRange() {
        if (from == null || to == null) {
            return;
        }
        if (!to.isAfter(from)) {
            throw new IllegalArgumentException(
                    "'to' must be strictly after 'from'; the range is half-open [from, to)");
        }
        long days = java.time.Duration.between(from, to).toDays();
        if (days > MAX_RANGE_DAYS) {
            throw new IllegalArgumentException(
                    "Audit log range must not exceed " + MAX_RANGE_DAYS + " days (requested " + days
                            + "). Narrow the window and issue successive queries.");
        }
    }

    public enum SortDirection {
        ASC,
        DESC
    }
}
