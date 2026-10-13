package com.company.incidentplatform.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.DeniedReason;
import com.company.incidentplatform.security.PlatformRole;
import com.company.incidentplatform.security.RolePermissions;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Section 7.11 -- proves the audit write path against a real PostgreSQL with the
 * real migrations applied.
 *
 * <p>This exists because the binding between {@link AuditService} and the
 * 19-parameter {@code audit_log_append} function is the kind of thing that looks
 * correct and is not. A misaligned pair of adjacent {@code text} parameters
 * would execute cleanly, insert a plausible row, and quietly corrupt the audit
 * trail -- which is worse than an outright failure, because the audit log is the
 * evidence base for every other control.
 *
 * <p>Tagged {@code integration} and excluded from the default surefire run: it
 * needs a Docker engine. Run it with {@code mvn verify -Pintegration} or
 * {@code -Dgroups=integration}.
 */
@Tag("integration")
@ExtendWith(SpringExtension.class)
@Testcontainers
@SpringBootTest(properties = {
        "spring.jpa.hibernate.ddl-auto=none",
        "incident-platform.user-state-cache-ttl=0s",
        "incident-platform.identity.dormancy.enabled=false"
})
class AuditServiceIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine")
            .withDatabaseName("incident_platform")
            .withUsername("postgres")
            .withPassword("postgres")
            // V9 grants privileges to incident_app and FAILS CLOSED if the role
            // is absent, which is the correct production behaviour. The role has
            // to be provisioned before Flyway runs, so it is created here the
            // same way a deployment pipeline would.
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

    private static final UUID ACTOR_ID = UUID.randomUUID();
    private static final UUID RESOURCE_ID = UUID.randomUUID();
    private static final UUID REQUEST_ID = UUID.randomUUID();
    private static final String APP_ROLE = "incident_app";
    private static final String APP_PASSWORD = "audit-it-app-password";

    @BeforeEach
    void reset() {
        jdbc.execute("ALTER TABLE incident_platform.audit_log DISABLE TRIGGER trg_audit_log_no_truncate");
        try {
            jdbc.execute("TRUNCATE incident_platform.audit_log");
        } finally {
            jdbc.execute("ALTER TABLE incident_platform.audit_log ENABLE TRIGGER trg_audit_log_no_truncate");
        }
        jdbc.execute("ALTER ROLE " + APP_ROLE + " PASSWORD '" + APP_PASSWORD + "'");
        jdbc.update(
                "INSERT INTO incident_platform.app_user "
                        + "(id, keycloak_subject, full_name, email, role_id, department) "
                        + "VALUES (?, ?, ?, ?, (SELECT id FROM incident_platform.platform_role "
                        + "WHERE name = 'ANALYST'), 'SECURITY') "
                        + "ON CONFLICT (id) DO NOTHING",
                ACTOR_ID, "audit-it-actor", "Analyst", "audit-it-actor@example.test");
    }

    private com.company.incidentplatform.security.PlatformUser actor() {
        RolePermissions permissions = RolePermissions.fromJson(
                new ObjectMapper().createObjectNode());
        return new com.company.incidentplatform.security.PlatformUser(
                ACTOR_ID, "kc-subject", "analyst@example.test", "Analyst",
                "SECURITY", PlatformRole.ANALYST, permissions, true, true);
    }

    @Test
    @DisplayName("a denied event is written with its 7.11 reason code, check type, and rule")
    void deniedEventIsClassified() {
        audit.recordDenied(
                actor(),
                DeniedReason.CROSS_USER_OBJECT_ACCESS,
                "incident",
                RESOURCE_ID,
                "read",
                "/api/v1/incidents/{id}",
                "GET",
                REQUEST_ID,
                "10.0.0.7",
                AuthorizationCheckType.OBJECT_LEVEL,
                "incident.read.not_assigned_not_department");

        Map<String, Object> row = jdbc.queryForMap(
                "SELECT * FROM incident_platform.audit_log WHERE request_id = ?", REQUEST_ID);

        assertThat(row.get("result")).isEqualTo("DENIED");
        assertThat(row.get("reason_code")).isEqualTo("CROSS_USER_OBJECT_ACCESS");
        assertThat(row.get("authorization_check")).isEqualTo("OBJECT_LEVEL");
        assertThat(row.get("authorization_rule")).isEqualTo("incident.read.not_assigned_not_department");
        assertThat(row.get("action")).isEqualTo("read");
        assertThat(row.get("entity_type")).isEqualTo("incident");
        assertThat(row.get("entity_id")).isEqualTo(RESOURCE_ID);
        assertThat(row.get("endpoint")).isEqualTo("/api/v1/incidents/{id}");
        assertThat(row.get("method")).isEqualTo("GET");
        assertThat(String.valueOf(row.get("ip_address"))).isEqualTo("10.0.0.7");
        assertThat(row.get("actor_id")).isEqualTo(ACTOR_ID);
        assertThat(row.get("actor_role")).isEqualTo("ANALYST");
    }

    @Test
    @DisplayName("an endpoint path is stored verbatim, so an IDOR burst is queryable")
    void endpointIsQueryable() {
        // 7.12 anomaly detection counts repeated denials against one endpoint.
        // That is only possible if the column holds the value the rule string
        // came from, rather than a re-derived or truncated form.
        audit.recordDenied(actor(), DeniedReason.INSUFFICIENT_ROLE, "incident", null,
                "reassign", "/api/v1/incidents/{id}/assignment", "PUT", REQUEST_ID,
                "10.0.0.7", AuthorizationCheckType.FUNCTION_LEVEL, "capability.can_reassign");

        Integer count = jdbc.queryForObject(
                "SELECT count(*) FROM incident_platform.audit_log "
                        + "WHERE result = 'DENIED' AND endpoint = ?",
                Integer.class,
                "/api/v1/incidents/{id}/assignment");

        assertThat(count).isEqualTo(1);
    }

    @Test
    @DisplayName("an allowed event records the check that permitted it")
    void allowedEventRecordsTheCheck() {
        audit.recordAllowed(actor(), "incident", RESOURCE_ID, "update", "/api/v1/incidents/{id}",
                "PUT", REQUEST_ID, "10.0.0.7", AuthorizationCheckType.OBJECT_LEVEL,
                "incident.read.assigned_to_self");

        Map<String, Object> row = jdbc.queryForMap(
                "SELECT * FROM incident_platform.audit_log WHERE request_id = ?", REQUEST_ID);

        assertThat(row.get("result")).isEqualTo("ALLOWED");
        assertThat(row.get("reason_code")).isNull();
        assertThat(row.get("authorization_check")).isEqualTo("OBJECT_LEVEL");
    }

    @Test
    @DisplayName("a null actor is auditable, for requests that fail before authentication")
    void nullActorIsAuditable() {
        // 7.11 requires unauthenticated denials to be recorded too -- that is
        // exactly the traffic 7.12 should see, and the user is by definition
        // unknown at that point.
        audit.recordDenied(null, DeniedReason.TOKEN_INVALID, "session", null, "authenticate",
                "/api/v1/incidents", "GET", REQUEST_ID, "203.0.113.9",
                AuthorizationCheckType.FUNCTION_LEVEL, "authentication.token_rejected");

        Map<String, Object> row = jdbc.queryForMap(
                "SELECT * FROM incident_platform.audit_log WHERE request_id = ?", REQUEST_ID);

        assertThat(row.get("actor_id")).isNull();
        assertThat(row.get("actor_role")).isNull();
        assertThat(row.get("reason_code")).isEqualTo("TOKEN_INVALID");
    }

    @Test
    @DisplayName("a malformed client-supplied address is discarded, not allowed to poison the write")
    void malformedIpIsDiscarded() {
        // X-Forwarded-For is client-controlled unless a proxy is trusted. A value
        // that is not a valid inet would otherwise fail the whole insert and cost
        // us the audit entry.
        audit.recordDenied(actor(), DeniedReason.CROSS_USER_OBJECT_ACCESS, "incident", RESOURCE_ID,
                "read", "/api/v1/incidents/{id}", "GET", REQUEST_ID,
                "not-an-ip-address", AuthorizationCheckType.OBJECT_LEVEL, "some.rule");

        Map<String, Object> row = jdbc.queryForMap(
                "SELECT * FROM incident_platform.audit_log WHERE request_id = ?", REQUEST_ID);

        assertThat(row).as("the entry must still be written").isNotNull();
        assertThat(row.get("ip_address")).isNull();
    }

    @Test
    @DisplayName("an address with a port suffix is recorded without the port")
    void portSuffixStripped() {
        audit.recordDenied(actor(), DeniedReason.CROSS_USER_OBJECT_ACCESS, "incident", RESOURCE_ID,
                "read", "/api/v1/incidents/{id}", "GET", REQUEST_ID,
                "10.0.0.7:54321", AuthorizationCheckType.OBJECT_LEVEL, "some.rule");

        Map<String, Object> row = jdbc.queryForMap(
                "SELECT * FROM incident_platform.audit_log WHERE request_id = ?", REQUEST_ID);

        assertThat(String.valueOf(row.get("ip_address"))).isEqualTo("10.0.0.7");
    }

    @Test
    @DisplayName("concurrent writes produce a single unbroken hash chain")
    void hashChainStaysIntactUnderConcurrency() throws InterruptedException {
        // The function serialises on an advisory lock precisely so the chain
        // cannot fork. If that lock were removed, concurrent appends would each
        // read the same previous hash and verify_audit_log_chain would fail --
        // silently, long after the fact.
        int threads = 8;
        int perThread = 5;
        var executor = java.util.concurrent.Executors.newFixedThreadPool(threads);
        var start = new java.util.concurrent.CountDownLatch(1);
        var done = new java.util.concurrent.CountDownLatch(threads);

        for (int t = 0; t < threads; t++) {
            executor.execute(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        audit.recordDenied(actor(), DeniedReason.INSUFFICIENT_ROLE, "incident", null,
                                "read", "/api/v1/incidents", "GET", UUID.randomUUID(), "10.0.0.7",
                                AuthorizationCheckType.FUNCTION_LEVEL, "concurrent.test");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertThat(done.await(60, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        executor.shutdown();

        Integer count = jdbc.queryForObject(
                "SELECT count(*) FROM incident_platform.audit_log "
                        + "WHERE action = 'read' AND authorization_rule = 'concurrent.test'",
                Integer.class);
        assertThat(count).isEqualTo(threads * perThread);

        List<Map<String, Object>> problems =
                jdbc.queryForList("SELECT * FROM incident_platform.verify_audit_log_chain(null, null)");
        assertThat(problems).as("hash chain must verify after concurrent appends").isEmpty();
    }

    @Test
    @DisplayName("the runtime role cannot write to audit_log directly, only through the function")
    void runtimeRoleCannotBypassTheFunction() throws Exception {
        // The structural guarantee behind the whole design. If direct INSERT were
        // possible, an unchained row could be written and the chain could not be
        // trusted -- so this is asserted rather than assumed.
        try (var connection = runtimeDataSource().getConnection()) {
            try (var statement = connection.createStatement()) {
                assertThatThrownBy(() -> statement.executeUpdate(
                        "INSERT INTO incident_platform.audit_log "
                                + "(id, timestamp, action, entity_type, result) "
                                + "VALUES (gen_random_uuid(), now(), 'forged', 'incident', 'ALLOWED')"))
                        .isInstanceOf(java.sql.SQLException.class)
                        .satisfies(thrown -> assertThat(thrown.getMessage().toUpperCase())
                                .contains("PERMISSION DENIED"));
            }
        }
    }

    @Test
    @DisplayName("the runtime role cannot modify or delete an existing entry")
    void runtimeRoleCannotMutateHistory() throws Exception {
        audit.recordDenied(actor(), DeniedReason.CROSS_USER_OBJECT_ACCESS, "incident", RESOURCE_ID,
                "read", "/api/v1/incidents/{id}", "GET", REQUEST_ID, "10.0.0.7",
                AuthorizationCheckType.OBJECT_LEVEL, "some.rule");

        try (var connection = runtimeDataSource().getConnection()) {
            for (String sql : new String[] {
                    "UPDATE incident_platform.audit_log SET action = 'tampered'",
                    "DELETE FROM incident_platform.audit_log",
                    "TRUNCATE incident_platform.audit_log"
            }) {
                try (var statement = connection.createStatement()) {
                    assertThatThrownBy(() -> statement.executeUpdate(sql))
                            .as("must refuse: %s", sql)
                            .isInstanceOf(java.sql.SQLException.class)
                            .satisfies(thrown -> assertThat(thrown.getMessage().toUpperCase())
                                    .contains("PERMISSION DENIED"));
                }
            }
        }
    }

    @Test
    @DisplayName("audit_log_append returns the new entry id")
    void appendReturnsId() {
        // The function RETURNS uuid; discarding it would mean an application that
        // could not reference the entry it just wrote, e.g. to attach it to a
        // response or correlate it explicitly.
        UUID id = jdbc.queryForObject(
                "SELECT incident_platform.audit_log_append("
                        + "p_action => 'read', p_entity_type => 'incident', "
                        + "p_result => 'ALLOWED'::incident_platform.audit_result)",
                UUID.class);

        assertThat(id).isNotNull();
        assertThat(jdbc.queryForObject(
                "SELECT count(*) FROM incident_platform.audit_log WHERE id = ?", Integer.class, id))
                .isEqualTo(1);
    }

    private javax.sql.DataSource runtimeDataSource() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("org.postgresql.Driver");
        dataSource.setUrl(POSTGRES.getJdbcUrl() + "?currentSchema=incident_platform");
        dataSource.setUsername(APP_ROLE);
        dataSource.setPassword(APP_PASSWORD);
        return dataSource;
    }
}
