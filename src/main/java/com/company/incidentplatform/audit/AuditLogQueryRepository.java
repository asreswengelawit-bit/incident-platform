package com.company.incidentplatform.audit;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/**
 * Section 7.11 / FR-6.3 -- the audit log <em>read</em> path.
 *
 * <p>Mirrors {@link AuditService}, which is the only sanctioned writer. Reads are
 * a plain {@link JdbcTemplate} projection rather than a JPA repository because
 * {@code audit_log} is monthly-partitioned and append-only (6.3, 7.11): there is
 * no entity lifecycle to map, and an ORM would add a change-detection pass over
 * the highest-cardinality table in the schema for no benefit.
 *
 * <h2>Every value is bound, never concatenated</h2>
 *
 * <p>The {@code WHERE} clause is assembled from fragments that are constants in
 * this file, and each caller-supplied value is bound as a JDBC parameter. The sort
 * column and direction are the only caller-influenced <em>SQL text</em>, and both
 * are resolved through {@link AuditLogQuery#validatedSortBy} /
 * {@link #validatedDirection} against fixed allow-lists before they reach the
 * statement -- so no request parameter can become SQL. 7.5 requires
 * parameterization, and an audit-log endpoint that concatenates a filter value
 * would be a particularly bad instance of the problem: the table is the one place
 * an attacker would most want to read the schema.
 */
@Repository
public class AuditLogQueryRepository {

    /**
     * Columns projected in a fixed order. Hashes are rendered as hex here so the
     * bytea values are directly comparable by a reviewer.
     */
    private static final String SELECT_COLUMNS = """
            SELECT a.id,
                   a.timestamp,
                   a.actor_id,
                   a.actor_role,
                   a.actor_keycloak_subject,
                   a.entity_type,
                   a.entity_id,
                   a.action,
                   a.result,
                   a.reason_code,
                   a.reason_detail,
                   a.endpoint,
                   a.method,
                   a.request_id,
                   a.authorization_check,
                   a.authorization_rule,
                   host(a.ip_address) AS ip_address,
                   a.before_value::text AS before_value,
                   a.after_value::text AS after_value,
                   a.pii_redacted,
                   encode(a.previous_hash, 'hex') AS previous_hash,
                   encode(a.entry_hash, 'hex') AS entry_hash
              FROM incident_platform.audit_log a
            """;

    private static final RowMapper<AuditLogEntry> MAPPER = new AuditLogRowMapper();

    private final JdbcTemplate jdbc;

    public AuditLogQueryRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * FR-6.3: one page of audit entries matching {@code query}.
     *
     * <p>The page and the total are two statements sharing one predicate, rather
     * than a {@code count(*) OVER ()} window column. A window column looks tidier
     * and is genuinely cheaper on a flat table, but it still makes PostgreSQL
     * materialise every row in the window before discarding all but the requested
     * page -- which is the entire cost on a table partitioned by month with an
     * index on {@code (actor_id, timestamp)}. Two statements on one shared
     * predicate keeps the expensive part to the page itself.
     *
     * <p>The cost of two statements is that they can disagree if a row is appended
     * between them, and this table gains a row on every request including this
     * one. That is accepted deliberately: the total is used for pagination and a
     * transient one-row discrepancy makes a final page look non-empty, which is
     * far less misleading than reporting a total that does not match a page the
     * caller is already holding.
     */
    public Page find(AuditLogQuery query, String sortBy, AuditLogQuery.SortDirection direction, int page, int pageSize) {

        StringBuilder where = new StringBuilder();
        List<Object> args = new ArrayList<>();

        // The shared predicate goes in once and is reused by both the page and the
        // count, which is what guarantees they agree.
        appendFilters(where, args, query);

        long offset = (long) page * pageSize;

        String sql = SELECT_COLUMNS + where
                + " ORDER BY " + columnFor(sortBy) + " " + direction.name()
                + ", a.id " + direction.name()
                + " LIMIT ? OFFSET ?";

        List<Object> pageArgs = new ArrayList<>(args);
        pageArgs.add(pageSize);
        pageArgs.add(offset);

        List<AuditLogEntry> entries = jdbc.query(sql, MAPPER, pageArgs.toArray());
        long total = countMatching(where, args);

        return new Page(entries, total);
    }

    /**
     * Counts with the same predicate. Kept as its own statement rather than a
     * window column because {@code count(*) OVER ()} still materialises the whole
     * window's rows in the server before discarding all but the requested page,
     * which is the expensive part on a partitioned table.
     */
    private long countMatching(StringBuilder where, List<Object> args) {
        String sql = "SELECT count(*) FROM incident_platform.audit_log a" + where;
        Long count = jdbc.queryForObject(sql, Long.class, args.toArray());
        return count == null ? 0L : count;
    }

    private static void appendFilters(StringBuilder where, List<Object> args, AuditLogQuery query) {
        List<String> clauses = new ArrayList<>();

        if (query.result() != null && !query.result().isBlank()) {
            clauses.add("a.result = ?::incident_platform.audit_result");
            args.add(query.result().trim());
        }
        if (query.action() != null && !query.action().isBlank()) {
            clauses.add("a.action = ?");
            args.add(query.action().trim());
        }
        if (query.entityType() != null && !query.entityType().isBlank()) {
            clauses.add("a.entity_type = ?");
            args.add(query.entityType().trim());
        }
        if (query.entityId() != null) {
            clauses.add("a.entity_id = ?");
            args.add(query.entityId());
        }
        if (query.actorId() != null) {
            clauses.add("a.actor_id = ?");
            args.add(query.actorId());
        }
        if (query.requestId() != null) {
            clauses.add("a.request_id = ?");
            args.add(query.requestId());
        }
        // Half-open [from, to) -- see AuditLogQuery.
        if (query.from() != null) {
            clauses.add("a.timestamp >= ?");
            args.add(Timestamp.from(query.from()));
        }
        if (query.to() != null) {
            clauses.add("a.timestamp < ?");
            args.add(Timestamp.from(query.to()));
        }

        if (!clauses.isEmpty()) {
            where.append(" WHERE ").append(String.join(" AND ", clauses));
        }
    }

    /**
     * Maps an allow-listed field name to a fixed column expression. There is no
     * path from a request parameter to this method's return value except through
     * {@link AuditLogQuery#ALLOWED_SORT_FIELDS}.
     */
    static String columnFor(String validatedSortField) {
        return switch (validatedSortField) {
            case "action" -> "a.action";
            case "timestamp" -> "a.timestamp";
            default -> throw new IllegalArgumentException("Sort field not allow-listed: " + validatedSortField);
        };
    }

    /**
     * FR-1.6: which of the given actors are the reporter of an anonymous incident,
     * and therefore protected identities.
     *
     * <p>Returns the protected <em>actor</em> ids, not a map of incident id to
     * reporter id. That is the whole point of the method's shape: the reporter id
     * is never selected, so it never enters application memory, and the only thing
     * that crosses the boundary is the yes/no answer "is this actor protected?".
     * A version that returned the reporter id and let the service compare would put
     * the very value FR-1.6 restricts into a field on a service object, one careless
     * log statement away from a response body.
     *
     * <p>The predicate is deliberately coarser than "is this row's actor the
     * reporter of <em>this</em> incident". A user who reported incident A
     * anonymously and incident B normally is protected, and every one of their rows
     * is suppressed, including rows unrelated to A. Over-redaction is the correct
     * direction: FR-1.6 protects the <em>identity</em>, and a row that displays a
     * protected id discloses that identity whatever the row is about. The
     * counterpart of this choice is that the log for such a user looks thinner than
     * it is, which is why {@code actorIdWithheld} is in the response -- a reader can
     * see that a value was removed rather than concluding none existed.
     *
     * <p>Bounded by the page's own actor ids, so this is a single indexed lookup of
     * at most {@code pageSize} probes regardless of incident-table size. An empty
     * set is the common case and means no redaction applies.
     */
    public Set<UUID> protectedReporterIds(List<UUID> candidateActorIds) {
        if (candidateActorIds == null || candidateActorIds.isEmpty()) {
            return Set.of();
        }
        // Reads incident.reporter_id, NOT incident_reporter_identity. The latter is
        // the restricted FR-1.6 store and the runtime role has no SELECT on it at all
        // (V9 grants INSERT, UPDATE only) -- so the one place the check is made is a
        // boolean aggregate over the ordinary incident projection, and it never
        // depends on a grant this code does not hold.
        String sql = """
                SELECT DISTINCT i.reporter_id
                  FROM incident_platform.incident i
                 WHERE i.anonymous
                   AND i.reporter_id IS NOT NULL
                   AND i.reporter_id IN (%s)
                """.formatted(placeholders(candidateActorIds.size()));

        return new LinkedHashSet<>(jdbc.query(
                sql,
                (rs, rowNum) -> rs.getObject(1, UUID.class),
                candidateActorIds.toArray()));
    }

    /**
     * 7.11: verifies the hash chain over a window via the SQL function, which is
     * the only implementation of the recomputation -- duplicating the digest
     * composition in Java would be a second thing to keep in step with V7.
     *
     * <p>Returns problems rather than a boolean so a reviewer is told <em>which</em>
     * entries failed and how.
     */
    public List<ChainProblem> verifyChain(Instant from, Instant to) {
        String sql = """
                SELECT v.entry_id, v.entry_ts, v.problem
                  FROM incident_platform.verify_audit_log_chain(?, ?) v
                 ORDER BY v.entry_ts
                 LIMIT 100
                """;
        return jdbc.query(
                sql,
                (rs, rowNum) -> new ChainProblem(
                        rs.getObject("entry_id", UUID.class),
                        rs.getTimestamp("entry_ts") == null
                                ? null
                                : rs.getTimestamp("entry_ts").toInstant(),
                        rs.getString("problem")),
                Timestamp.from(from),
                Timestamp.from(to));
    }

    /**
     * FR-1.6: the anonymous incidents this actor reported.
     *
     * <p>Returns incident ids only, and that is safe to hand to the audit writer:
     * an incident id is not protected -- the whole platform exposes them in URLs --
     * whereas the reporter id is. The association is used solely to name the
     * incident in the FR-1.6 entry ("identity of anonymous report #X viewed by
     * Y"), and is only ever requested for an actor who has already been shown the
     * identity, so it cannot be used to obtain one.
     */
    public Set<UUID> anonymousIncidentIdsReportedBy(UUID actorId) {
        if (actorId == null) {
            return Set.of();
        }
        return new LinkedHashSet<>(jdbc.query(
                """
                SELECT i.id
                  FROM incident_platform.incident i
                 WHERE i.anonymous
                   AND i.reporter_id = ?
                """,
                (rs, rowNum) -> rs.getObject(1, UUID.class),
                actorId));
    }

    private static String placeholders(int count) {
        return String.join(",", java.util.Collections.nCopies(count, "?"));
    }

    /** A page of entries plus the total matching the same predicate. */
    public record Page(List<AuditLogEntry> entries, long total) {
    }

    /** 7.11: one entry that failed verification, and how. */
    public record ChainProblem(UUID entryId, Instant timestamp, String problem) {
    }

    private static final class AuditLogRowMapper implements RowMapper<AuditLogEntry> {

        @Override
        public AuditLogEntry mapRow(ResultSet rs, int rowNum) throws SQLException {
            return new AuditLogEntry(
                    rs.getObject("id", UUID.class),
                    instant(rs, "timestamp"),
                    rs.getObject("actor_id", UUID.class),
                    rs.getString("actor_role"),
                    rs.getString("actor_keycloak_subject"),
                    rs.getString("entity_type"),
                    rs.getObject("entity_id", UUID.class),
                    rs.getString("action"),
                    rs.getString("result"),
                    rs.getString("reason_code"),
                    rs.getString("reason_detail"),
                    rs.getString("endpoint"),
                    rs.getString("method"),
                    rs.getObject("request_id", UUID.class),
                    rs.getString("authorization_check"),
                    rs.getString("authorization_rule"),
                    rs.getString("ip_address"),
                    rs.getString("before_value"),
                    rs.getString("after_value"),
                    rs.getBoolean("pii_redacted"),
                    rs.getString("previous_hash"),
                    rs.getString("entry_hash"));
        }

        private static Instant instant(ResultSet rs, String column) throws SQLException {
            Timestamp ts = rs.getTimestamp(column);
            return ts == null ? null : ts.toInstant();
        }
    }
}
