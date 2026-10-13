package com.company.incidentplatform.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Section 7.11 / FR-6.3 -- proves the audit-log READ path against a real PostgreSQL
 * with the real migrations applied.
 *
 * <p>{@link AuditLogServiceTest} asserts the service's decisions with a mocked
 * repository. Everything below that line is untested there, and it is the part that
 * can be wrong in a way that only a database reveals: whether a filter binds to the
 * right column, whether the half-open range excludes the right boundary, whether the
 * sort expression is a real column, whether the hex hash projection works on a
 * {@code bytea}, and whether {@code verify_audit_log_chain} is callable with the
 * signature the repository assumes. A wrong column name or a mismatched function
 * signature compiles perfectly.
 *
 * <p>Two environment facts shape the setup, both consequences of this harness
 * connecting as the container's {@code POSTGRES_USER} rather than as
 * {@code incident_app}:
 *
 * <ul>
 *   <li>{@code audit_log.actor_id} foreign-keys {@code app_user(id)}, and no
 *       migration seeds users, so every actor and reporter referenced here is
 *       inserted first. Writing audit rows with an actor id that does not exist
 *       fails the insert, and {@link AuditService} deliberately swallows audit-write
 *       failures -- so the symptom would be a silently empty table, not an error.</li>
 *   <li>Resetting needs the trigger suspended. {@code audit_log} is append-only by
 *       trigger as well as by grant, so {@code TRUNCATE} raises even for the
 *       superuser. The disable/re-enable sequence used below is the one V7's own
 *       header documents as the sanctioned emergency procedure; it is confined to
 *       this throwaway container and re-enabled in the same statement chain.</li>
 * </ul>
 *
 * <p>Tagged {@code integration} because it needs a Docker engine. Run with
 * {@code ./gradlew integrationTest}.
 */
@Tag("integration")
@ExtendWith(SpringExtension.class)
@Testcontainers
@SpringBootTest(properties = {
        "spring.jpa.hibernate.ddl-auto=none",
        "incident-platform.user-state-cache-ttl=0s",
        "incident-platform.identity.dormancy.enabled=false"
})
class AuditLogReadIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine")
            .withDatabaseName("incident_platform")
            .withUsername("postgres")
            .withPassword("postgres")
            .withInitScript("db/test/01-create-runtime-role.sql");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",
                () -> POSTGRES.getJdbcUrl() + "?currentSchema=incident_platform");
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @org.springframework.test.context.bean.override.mockito.MockitoBean
    private org.springframework.security.oauth2.jwt.JwtDecoder jwtDecoder;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private AuditService audit;

    @Autowired
    private AuditLogQueryRepository repository;

    private static final UUID WHISTLEBLOWER = UUID.fromString("00000000-0000-0000-0000-0000000000a1");
    private static final UUID ANALYST = UUID.fromString("00000000-0000-0000-0000-0000000000b2");
    private static final UUID NORMAL_REPORTER = UUID.fromString("00000000-0000-0000-0000-0000000000a3");
    private static final UUID ANONYMOUS_INCIDENT = UUID.fromString("00000000-0000-0000-0000-0000000000c1");
    private static final UUID NORMAL_INCIDENT = UUID.fromString("00000000-0000-0000-0000-0000000000c2");

    /** The window every timestamp below falls inside, so range filtering is exact. */
    private static final Instant WINDOW_START = Instant.parse("2026-03-01T00:00:00Z");
    private static final Instant WINDOW_END = Instant.parse("2026-03-02T00:00:00Z");

    @BeforeEach
    void reset() {
        jdbc.execute("ALTER TABLE incident_platform.audit_log DISABLE TRIGGER trg_audit_log_append_only");
        jdbc.execute("ALTER TABLE incident_platform.audit_log DISABLE TRIGGER trg_audit_log_no_truncate");
        try {
            jdbc.execute("TRUNCATE incident_platform.audit_log");
            jdbc.execute("TRUNCATE incident_platform.incident CASCADE");
            jdbc.execute("DELETE FROM incident_platform.app_user WHERE keycloak_subject LIKE 'it-%'");
        } finally {
            jdbc.execute("ALTER TABLE incident_platform.audit_log ENABLE TRIGGER trg_audit_log_append_only");
            jdbc.execute("ALTER TABLE incident_platform.audit_log ENABLE TRIGGER trg_audit_log_no_truncate");
        }

        insertUser(WHISTLEBLOWER, "it-whistleblower");
        insertUser(ANALYST, "it-analyst");
        insertUser(NORMAL_REPORTER, "it-normal-reporter");
    }

    /**
     * {@code app_user.role_id} and {@code incident.category_id} are foreign keys with
     * no seeded rows, and the categories are inserted by V11, so both are resolved
     * from the reference data rather than hard-coded.
     */
    private void insertUser(UUID id, String subject) {
        jdbc.update(
                "INSERT INTO incident_platform.app_user (id, keycloak_subject, full_name, email, role_id) "
                        + "VALUES (?, ?, ?, ?, (SELECT id FROM incident_platform.platform_role "
                        + "WHERE name = 'REPORTER'))",
                id, subject, subject, subject + "@example.test");
    }

    private void insertIncident(UUID id, UUID reporterId, boolean anonymous) {
        jdbc.update(
                "INSERT INTO incident_platform.incident "
                        + "(id, title, description, category_id, reporter_id, anonymous, occurred_at) "
                        + "VALUES (?, ?, ?, (SELECT id FROM incident_platform.incident_category LIMIT 1), "
                        + "?, ?, now())",
                id, "title-" + id, "description-" + id, reporterId, anonymous);
    }

    /** Writes one entry at a chosen instant, through the sanctioned writer. */
    private void writeEntry(
            UUID actorId, String entityType, UUID entityId, String action,
            String result, Instant at, String requestId) {
        jdbc.queryForObject(
                """
                SELECT incident_platform.audit_log_append(
                    p_action      => ?,
                    p_entity_type => ?,
                    p_entity_id   => ?::uuid,
                    p_actor_id    => ?::uuid,
                    p_result      => ?::incident_platform.audit_result,
                    p_reason_code => 'TEST_DENIAL',
                    p_request_id  => ?::uuid,
                    p_endpoint    => '/api/v1/incidents',
                    p_method      => 'POST',
                    p_after_value => '{"anonymous":true}'::jsonb,
                    p_timestamp   => ?::timestamptz
                )
                """,
                UUID.class,
                action, entityType, entityId, actorId, result, requestId, Timestamp.from(at));
    }

    @Test
    @DisplayName("a page returns the entries, with hashes rendered as hex")
    void readsAPage() {
        UUID requestId = UUID.randomUUID();
        writeEntry(WHISTLEBLOWER, "incident", ANONYMOUS_INCIDENT, "incident.create",
                "ALLOWED", Instant.parse("2026-03-01T10:00:00Z"), requestId.toString());

        AuditLogQueryRepository.Page page = repository.find(
                new AuditLogQuery(null, null, null, null, null, null, null, null),
                "timestamp", AuditLogQuery.SortDirection.DESC, 0, 25);

        assertThat(page.total()).isEqualTo(1);
        AuditLogEntry entry = page.entries().get(0);
        assertThat(entry.actorId()).isEqualTo(WHISTLEBLOWER);
        assertThat(entry.action()).isEqualTo("incident.create");
        assertThat(entry.requestId()).isEqualTo(requestId);
        // encode(..., 'hex') is what makes the chain evidence comparable; a raw
        // bytea would not survive JSON serialisation usefully.
        assertThat(entry.entryHash()).isNotNull().matches("[0-9a-f]+");
        assertThat(entry.ipAddress()).isNull();
    }

    @Test
    @DisplayName("each filter binds to its own column and does not leak into the others")
    void filtersBindIndependently() {
        writeEntry(WHISTLEBLOWER, "incident", ANONYMOUS_INCIDENT, "incident.create",
                "ALLOWED", Instant.parse("2026-03-01T10:00:00Z"), UUID.randomUUID().toString());
        writeEntry(ANALYST, "incident", NORMAL_INCIDENT, "incident.assign",
                "ALLOWED", Instant.parse("2026-03-01T11:00:00Z"), UUID.randomUUID().toString());
        writeEntry(ANALYST, "evidence", NORMAL_INCIDENT, "evidence.upload",
                "DENIED", Instant.parse("2026-03-01T12:00:00Z"), UUID.randomUUID().toString());

        assertThat(totalFor(new AuditLogQuery("ALLOWED", null, null, null, null, null, null, null)))
                .as("result filter").isEqualTo(2);
        assertThat(totalFor(new AuditLogQuery(null, "incident.assign", null, null, null, null, null, null)))
                .as("action filter").isEqualTo(1);
        assertThat(totalFor(new AuditLogQuery(null, null, "evidence", null, null, null, null, null)))
                .as("entity_type filter").isEqualTo(1);
        assertThat(totalFor(new AuditLogQuery(null, null, null, ANONYMOUS_INCIDENT, null, null, null, null)))
                .as("entity_id filter").isEqualTo(1);
        assertThat(totalFor(new AuditLogQuery(null, null, null, null, ANALYST, null, null, null)))
                .as("actor_id filter").isEqualTo(2);
    }

    @Test
    @DisplayName("the range is half-open, so consecutive windows neither overlap nor gap")
    void rangeIsHalfOpen() {
        writeEntry(ANALYST, "incident", NORMAL_INCIDENT, "a", "ALLOWED",
                Instant.parse("2026-03-01T10:00:00Z"), UUID.randomUUID().toString());
        writeEntry(ANALYST, "incident", NORMAL_INCIDENT, "b", "ALLOWED",
                Instant.parse("2026-03-01T11:00:00Z"), UUID.randomUUID().toString());
        writeEntry(ANALYST, "incident", NORMAL_INCIDENT, "c", "ALLOWED",
                Instant.parse("2026-03-01T12:00:00Z"), UUID.randomUUID().toString());

        // This is the property that lets the periodic 7.11 chain verification tile
        // successive months and still cover every entry exactly once.
        assertThat(totalFor(new AuditLogQuery(
                null, null, null, null, null, null, WINDOW_START, WINDOW_END)))
                .isEqualTo(3);
        assertThat(totalFor(new AuditLogQuery(
                null, null, null, null, null, null,
                WINDOW_START, Instant.parse("2026-03-01T11:00:00Z"))))
                .as("upper bound is exclusive").isEqualTo(1);
        assertThat(totalFor(new AuditLogQuery(
                null, null, null, null, null, null, WINDOW_END, Instant.parse("2026-03-03T00:00:00Z"))))
                .isEqualTo(0);
    }

    @Test
    @DisplayName("pagination returns a consistent total and respects the ordering")
    void paginatesConsistently() {
        for (int i = 0; i < 5; i++) {
            writeEntry(ANALYST, "incident", NORMAL_INCIDENT, "action-" + i, "ALLOWED",
                    WINDOW_START.plusSeconds(i * 60L), UUID.randomUUID().toString());
        }

        AuditLogQuery all = new AuditLogQuery(null, null, null, null, null, null, WINDOW_START, WINDOW_END);
        AuditLogQueryRepository.Page first =
                repository.find(all, "timestamp", AuditLogQuery.SortDirection.DESC, 0, 2);
        AuditLogQueryRepository.Page second =
                repository.find(all, "timestamp", AuditLogQuery.SortDirection.DESC, 1, 2);

        assertThat(first.total()).as("both pages see the same total").isEqualTo(5);
        assertThat(second.total()).isEqualTo(5);
        assertThat(first.entries()).extracting(AuditLogEntry::action)
                .containsExactly("action-4", "action-3");
        assertThat(second.entries()).extracting(AuditLogEntry::action)
                .containsExactly("action-2", "action-1");

        AuditLogQueryRepository.Page ascending =
                repository.find(all, "timestamp", AuditLogQuery.SortDirection.ASC, 0, 2);
        assertThat(ascending.entries()).extracting(AuditLogEntry::action)
                .containsExactly("action-0", "action-1");
    }

    @Test
    @DisplayName("sorting by action uses the action index rather than a full sort")
    void sortsByAction() {
        writeEntry(ANALYST, "incident", NORMAL_INCIDENT, "zebra", "ALLOWED",
                WINDOW_START, UUID.randomUUID().toString());
        writeEntry(ANALYST, "incident", NORMAL_INCIDENT, "alpha", "ALLOWED",
                WINDOW_START.plusSeconds(60), UUID.randomUUID().toString());

        AuditLogQuery all = new AuditLogQuery(null, null, null, null, null, null, WINDOW_START, WINDOW_END);
        // Deliberately inserted newest-first in time but alphabetically ascending by
        // action, so an ignored sort field would produce the wrong order.
        assertThat(repository.find(all, "action", AuditLogQuery.SortDirection.ASC, 0, 10)
                .entries()).extracting(AuditLogEntry::action)
                .containsExactly("alpha", "zebra");
    }

    @Test
    @DisplayName("FR-1.6: the anonymous reporter is identified, a normal reporter is not")
    void identifiesProtectedReporters() {
        insertIncident(ANONYMOUS_INCIDENT, WHISTLEBLOWER, true);
        insertIncident(NORMAL_INCIDENT, NORMAL_REPORTER, false);

        // Only the anonymous reporter's id is returned. A normal reporter of an
        // equally confidential-looking incident is not a protected identity.
        assertThat(repository.protectedReporterIds(List.of(WHISTLEBLOWER, NORMAL_REPORTER, ANALYST)))
                .containsExactly(WHISTLEBLOWER);
        assertThat(repository.protectedReporterIds(List.of()))
                .isEmpty();
        assertThat(repository.protectedReporterIds(List.of(NORMAL_REPORTER)))
                .isEmpty();
    }

    @Test
    @DisplayName("FR-1.6: the reporter's incident ids are named, not their identity store row")
    void resolvesAnonymousIncidentsForReporter() {
        insertIncident(ANONYMOUS_INCIDENT, WHISTLEBLOWER, true);
        insertIncident(NORMAL_INCIDENT, WHISTLEBLOWER, false);

        // Only the anonymous one: this is used to name the incident in the FR-1.6
        // entry, and naming the report the reporter filed normally would mislabel it.
        assertThat(repository.anonymousIncidentIdsReportedBy(WHISTLEBLOWER))
                .containsExactly(ANONYMOUS_INCIDENT);
        assertThat(repository.anonymousIncidentIdsReportedBy(NORMAL_REPORTER))
                .isEmpty();
    }

    @Test
    @DisplayName("chain verification reports no problems for entries written through the function")
    void chainVerifiesIntact() {
        for (int i = 0; i < 3; i++) {
            writeEntry(ANALYST, "incident", NORMAL_INCIDENT, "action-" + i, "ALLOWED",
                    Instant.parse("2026-03-01T10:00:0" + i + "Z"), UUID.randomUUID().toString());
        }

        // Wide enough to cover the seeded partitions, so a row is never missed
        // because it fell in the DEFAULT partition.
        List<AuditLogQueryRepository.ChainProblem> problems =
                repository.verifyChain(Instant.parse("2020-01-01T00:00:00Z"),
                        Instant.parse("2030-01-01T00:00:00Z"));

        assertThat(problems).as("chain must verify for entries appended via audit_log_append").isEmpty();
    }

    @Test
    @DisplayName("chain verification reports a problem when an entry's payload is altered")
    void chainDetectsTampering() {
        writeEntry(ANALYST, "incident", NORMAL_INCIDENT, "original", "ALLOWED",
                Instant.parse("2026-03-01T10:00:00Z"), UUID.randomUUID().toString());
        assertThat(repository.verifyChain(WINDOW_START, WINDOW_END)).isEmpty();

        // The only way to alter history is the table owner suspending the append-only
        // trigger, which is exactly the privileged DBA action 7.11's SIEM copy exists
        // to catch -- and the reason verification has to be able to fail.
        jdbc.execute("ALTER TABLE incident_platform.audit_log DISABLE TRIGGER trg_audit_log_append_only");
        try {
            jdbc.update("UPDATE incident_platform.audit_log SET action = 'tampered'");
        } finally {
            jdbc.execute("ALTER TABLE incident_platform.audit_log ENABLE TRIGGER trg_audit_log_append_only");
        }

        List<AuditLogQueryRepository.ChainProblem> problems =
                repository.verifyChain(WINDOW_START, WINDOW_END);

        assertThat(problems).as("an altered entry must be reported").isNotEmpty();
        assertThat(problems).extracting(AuditLogQueryRepository.ChainProblem::problem)
                .anyMatch(problem -> problem != null && problem.toLowerCase().contains("hash"));
    }

    @Test
    @DisplayName("a filter value containing SQL is treated as data")
    void filterValuesAreNotSql() {
        // 7.5. The value is bound, so this is a query for a nonsense action that
        // matches nothing -- not an error, and not an injected statement.
        String hostile = "x'; DROP TABLE incident_platform.audit_log; --";
        writeEntry(ANALYST, "incident", NORMAL_INCIDENT, "real", "ALLOWED",
                WINDOW_START, UUID.randomUUID().toString());

        assertThat(totalFor(new AuditLogQuery(
                null, hostile, null, null, null, null, null, null))).isZero();
        // The table is still there, which is the actual assertion.
        assertThat(jdbc.queryForObject("SELECT count(*) FROM incident_platform.audit_log", Integer.class))
                .isEqualTo(1);
    }

    private long totalFor(AuditLogQuery query) {
        return repository.find(query, "timestamp", AuditLogQuery.SortDirection.DESC, 0, 25).total();
    }
}
