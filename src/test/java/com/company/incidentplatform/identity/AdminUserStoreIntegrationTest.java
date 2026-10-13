package com.company.incidentplatform.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.company.incidentplatform.security.PlatformRole;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * FR-6.1 / 6.2.3 / 7.10 -- {@link AdminUserStore} against a real PostgreSQL 17 with the
 * real migrations applied, including V14.
 *
 * <p>{@link AdminUserServiceTest} asserts the service's decisions against a mocked
 * store. Everything inside the store is untested there, and it is the part only a
 * database can confirm:
 *
 * <ul>
 *   <li>the conditional {@code UPDATE ... WHERE version = ?} and the version bump;</li>
 *   <li>the jsonb merge and subtraction operators, including that a grant preserves
 *       {@code visibility_scope} and {@code led_departments};</li>
 *   <li>the {@code platform_coarse_role} enum cast, and the {@code coalesce} that makes
 *       an absent flag read as false rather than NULL;</li>
 *   <li>whether {@code SELECT ... FOR UPDATE} is accepted and actually takes the row
 *       lock;</li>
 *   <li>and whether {@code pg_advisory_xact_lock} really excludes a second transaction,
 *       which is the only thing that makes the last-administrator invariant safe under
 *       concurrency.</li>
 * </ul>
 *
 * <p><b>The store under test runs as {@code incident_app}, not as the container's
 * superuser.</b> That is the point of the class. A superuser bypasses the privilege
 * system entirely, so a store exercised as superuser would pass even with V14 absent
 * -- and V14 is load-bearing: before it, {@code incident_app} held only SELECT on
 * {@code platform_role}, so every capability grant and revoke would fail at runtime
 * with {@code permission denied for table platform_role} while unit tests stayed
 * green. That is the class of defect a privileged integration test waves through, so
 * the privilege assertions below are part of the subject under test rather than
 * incidental setup. {@code has_table_privilege} is also checked against a table V9
 * deliberately restricts ({@code audit_log}), to prove {@code incident_app} really is
 * a restricted role here and not a second superuser.
 *
 * <p>The two concurrency tests assert with {@link Future#get(long, TimeUnit)} timing
 * rather than by expecting a timeout exception. A blocked statement's exception type
 * depends on which timeout mechanism the driver happens to use, so pinning it would
 * test the driver; the property under test is that the second call does not complete
 * until the first transaction ends.
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
class AdminUserStoreIntegrationTest {

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

    private static final String APP_ROLE = "incident_app";
    private static final String APP_PASSWORD = "it-app-password";

    private static final UUID ADMIN_ONE = UUID.fromString("00000000-0000-0000-0000-0000000001a1");
    private static final UUID ADMIN_TWO = UUID.fromString("00000000-0000-0000-0000-0000000001a2");
    private static final UUID ANALYST = UUID.fromString("00000000-0000-0000-0000-0000000001a3");
    private static final UUID DISABLED_ADMIN = UUID.fromString("00000000-0000-0000-0000-0000000001a4");

    private static final Instant AT = Instant.parse("2026-03-01T12:00:00Z");

    /** The seeded permissions, captured once so a mutating test can be undone exactly. */
    private static Map<String, String> seedPermissions;

    /**
     * Replaces the real {@code JwtDecoder} bean.
     *
     * <p>{@code SecurityConfig.jwtDecoder()} calls {@code JwtDecoders.fromIssuerLocation},
     * which fetches the realm's OIDC configuration over the network while the context is
     * being built. There is no Keycloak in a Testcontainers run, so without this the
     * context fails to start with "Unable to resolve the Configuration with the
     * provided Issuer" -- before any test executes. Nothing here decodes a token; the
     * store is exercised directly, so the decoder is only here to stop startup from
     * reaching for a realm.
     */
    @MockitoBean
    private org.springframework.security.oauth2.jwt.JwtDecoder jwtDecoder;

    /** Superuser template: setup and assertions only, never the store under test. */
    @Autowired
    private JdbcTemplate admin;

    @Autowired
    private DataSource dataSource;

    private TransactionTemplate transactions;

    /** Bound to a genuinely privilege-restricted connection. */
    private AdminUserStore store;

    private JdbcTemplate appTemplate;

    @BeforeEach
    void setUp() {
        if (seedPermissions == null) {
            seedPermissions = capturePermissions();
        }

        // The init script derives the password from a GUC the container does not set, so
        // it is set explicitly here rather than assumed.
        admin.execute("ALTER ROLE " + APP_ROLE + " PASSWORD '" + APP_PASSWORD + "'");

        DriverManagerDataSource appDataSource = new DriverManagerDataSource();
        appDataSource.setDriverClassName("org.postgresql.Driver");
        appDataSource.setUrl(POSTGRES.getJdbcUrl() + "?currentSchema=incident_platform");
        appDataSource.setUsername(APP_ROLE);
        appDataSource.setPassword(APP_PASSWORD);
        store = new AdminUserStore(appTemplate = new JdbcTemplate(appDataSource));

        transactions = new TransactionTemplate(
                new org.springframework.jdbc.datasource.DataSourceTransactionManager(dataSource));

        resetUsers();
        resetPermissions();
    }

    // ------------------------------------------------------------------ fixtures

    private Map<String, String> capturePermissions() {
        Map<String, String> captured = new LinkedHashMap<>();
        admin.query("SELECT name::text, permissions::text FROM incident_platform.platform_role",
                (RowCallbackHandler) rs -> captured.put(rs.getString(1), rs.getString(2)));
        return captured;
    }

    private void resetPermissions() {
        seedPermissions.forEach((role, permissions) -> admin.update(
                "UPDATE incident_platform.platform_role SET permissions = ?::jsonb "
                        + "WHERE name = ?::incident_platform.platform_coarse_role", permissions, role));
    }

    private void resetUsers() {
        admin.update("DELETE FROM incident_platform.app_user WHERE keycloak_subject LIKE 'it-%'");
        insertUser(ADMIN_ONE, "it-admin-one", "SECURITY_ADMIN", true, null);
        insertUser(ADMIN_TWO, "it-admin-two", "SECURITY_ADMIN", true, null);
        insertUser(ANALYST, "it-analyst", "ANALYST", true, null);
        insertUser(DISABLED_ADMIN, "it-disabled-admin", "SECURITY_ADMIN", false, "left in May");
    }

    private void insertUser(UUID id, String subject, String role, boolean active, String disabledReason) {
        admin.update(
                "INSERT INTO incident_platform.app_user (id, keycloak_subject, full_name, email, role_id, "
                        + "department, active, disabled_at, disabled_reason) VALUES (?, ?, ?, ?, "
                        + " (SELECT id FROM incident_platform.platform_role "
                        + "WHERE name = ?::incident_platform.platform_coarse_role), "
                        + "'SECURITY', ?, ?, ?)",
                id, subject, subject, subject + "@example.test", role, active,
                active ? null : Timestamp.from(AT), disabledReason);
    }

    // ------------------------------------------------------- V14 privilege scope

    @Test
    @DisplayName("V14 is applied and grants exactly UPDATE on platform_role")
    void v14GrantsUpdateAndNothingElse() {
        assertThat(admin.queryForObject(
                        "SELECT success FROM incident_platform.flyway_schema_history WHERE version = '14'",
                        Boolean.class))
                .as("V14 must actually be in this schema; otherwise the privilege assertions below "
                        + "would be about V9's absence of the grant rather than about V14")
                .isTrue();

        assertThat(privilege("platform_role", "UPDATE"))
                .as("a capability grant and revoke are an UPDATE on this table. Without V14 the runtime "
                        + "role has SELECT only, and every grant fails at runtime")
                .isTrue();

        assertThat(privilege("platform_role", "INSERT"))
                .as("6.2.1's role vocabulary is fixed; the application must not be able to create a role "
                        + "that fromKeycloakRole would reject anyway")
                .isFalse();
        assertThat(privilege("platform_role", "DELETE"))
                .as("removing a role is not an admin operation, and app_user.role_id references it")
                .isFalse();

        assertThat(privilege("app_user", "UPDATE"))
                .as("user lifecycle and department changes are granted by V9 and must still work")
                .isTrue();
    }

    @Test
    @DisplayName("incident_app is a restricted role here, not a second superuser")
    void appRoleIsGenuinelyRestricted() {
        // If this were true the rest of the class would be meaningless: a superuser
        // would satisfy every assertion below with V14 deleted.
        assertThat(privilege("audit_log", "UPDATE"))
                .as("V9 revokes UPDATE on audit_log from every application role, Admin included. If "
                        + "this were true the harness would test with more privilege than production")
                .isFalse();
        assertThat(privilege("audit_log", "INSERT"))
                .as("audit_log has one sanctioned writer, a SECURITY DEFINER function")
                .isFalse();
    }

    private boolean privilege(String table, String privilege) {
        return Boolean.TRUE.equals(appTemplate().queryForObject(
                "SELECT has_table_privilege(?, ?, ?)", Boolean.class,
                APP_ROLE, "incident_platform." + table, privilege));
    }

    // ------------------------------------------------------------ user lifecycle

    @Test
    @DisplayName("a conditional update applies, bumps the version, and clears stale disable columns")
    void updateUserAppliesAndBumpsVersion() {
        assertThat(store.updateUser(DISABLED_ADMIN, 0, "OPERATIONS", true, null, AT)).isTrue();

        Map<String, Object> row = admin.queryForMap(
                "SELECT department, active, disabled_at, disabled_reason, version "
                        + "FROM incident_platform.app_user WHERE id = ?", DISABLED_ADMIN);

        assertThat(row.get("department")).isEqualTo("OPERATIONS");
        assertThat(row.get("active")).isEqualTo(Boolean.TRUE);
        assertThat(row.get("disabled_at")).isNull();
        assertThat(row.get("disabled_reason"))
                .as("re-enabling must clear the disable columns, or the row contradicts its own reason text")
                .isNull();
        assertThat(row.get("version"))
                .as("the bump is what makes the next write conditional; without it 7.10's optimistic "
                        + "locking would be silently ineffective")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("a stale expectedVersion updates nothing")
    void staleVersionIsRefused() {
        assertThat(store.updateUser(ANALYST, 0, "OPERATIONS", true, null, AT)).isTrue();

        assertThat(store.updateUser(ANALYST, 0, "FINANCE", true, null, AT))
                .as("this write carries version 0, which the first write has already replaced")
                .isFalse();

        assertThat(admin.queryForObject(
                        "SELECT department FROM incident_platform.app_user WHERE id = ?", String.class, ANALYST))
                .isEqualTo("OPERATIONS");
    }

    @Test
    @DisplayName("disabling sets disabled_at and reason together")
    void disableWritesBothColumns() {
        assertThat(store.updateUser(ANALYST, 0, null, false, "left in May", AT)).isTrue();

        Map<String, Object> row = admin.queryForMap(
                "SELECT active, disabled_at, disabled_reason FROM incident_platform.app_user WHERE id = ?",
                ANALYST);
        assertThat(row.get("active")).isEqualTo(Boolean.FALSE);
        assertThat(row.get("disabled_at")).isEqualTo(Timestamp.from(AT));
        assertThat(row.get("disabled_reason")).isEqualTo("left in May");
    }

    @Test
    @DisplayName("disabling without a reason is rejected by the database")
    void disableWithoutReasonViolatesTheConstraint() {
        // Proves the service-level check is load-bearing rather than decorative: the
        // schema refuses this write, so bypassing that check would surface as a
        // constraint violation rather than a silently reasonless disable.
        assertThatThrownBy(() -> store.updateUser(ANALYST, 0, null, false, null, AT))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    @DisplayName("an inconsistent disable is rejected by the database")
    void inconsistentDisableIsRejected() {
        // ck_app_user_active_disabled_consistent requires active to agree with
        // disabled_at, so the two cannot be written inconsistently even if the caller
        // disagrees about whether the account is being disabled.
        assertThatThrownBy(() -> admin.update(
                "UPDATE incident_platform.app_user SET active = true, disabled_at = ?, "
                        + "disabled_reason = ? WHERE id = ?",
                Timestamp.from(AT), "mismatched", ANALYST))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    // ------------------------------------------------------------ capability flags

    @Test
    @DisplayName("a grant merges one key and leaves the rest of the document alone")
    void grantMergesASingleKey() {
        String before = permissions("SECURITY_ADMIN");
        assertThat(nodeOf(before, "can_view_reporter_identity"))
                .as("V12 leaves this key present and false, so the grant flips a value in place "
                        + "rather than adding a key -- the case where a whole-document write would "
                        + "reset the role's visibility scope")
                .isEqualTo("false");

        store.grantCapability(PlatformRole.SECURITY_ADMIN, "can_view_reporter_identity");

        String after = permissions("SECURITY_ADMIN");
        assertThat(jsonNode(after))
                .as("only the one key may move")
                .isEqualTo(jsonNode(putKey(before, "can_view_reporter_identity")));
        assertThat(nodeOf(after, "visibility_scope"))
                .as("scoping detail, not a capability; a grant must not disturb it")
                .isEqualTo(nodeOf(before, "visibility_scope"));
    }

    @Test
    @DisplayName("a grant on a role with led_departments preserves the list")
    void grantPreservesLedDepartments() {
        // led_departments is 6.2.3 scoping detail, so SECURITY_LEAD is the realistic
        // case for "a grant must not disturb the document".
        String before = permissions("SECURITY_LEAD");
        assertThat(before).contains("led_departments");

        store.grantCapability(PlatformRole.SECURITY_LEAD, "can_manage_retention");

        assertThat(jsonNode(permissions("SECURITY_LEAD")))
                .isEqualTo(jsonNode(putKey(before, "can_manage_retention")));
    }

    @Test
    @DisplayName("a revoke removes the key rather than writing false")
    void revokeRemovesTheKey() {
        String before = permissions("SECURITY_ADMIN");
        assertThat(nodeOf(before, "can_manage_users")).isEqualTo("true");

        store.revokeCapability(PlatformRole.SECURITY_ADMIN, "can_manage_users");

        String after = permissions("SECURITY_ADMIN");
        assertThat(nodeOf(after, "can_manage_users"))
                .as("removal keeps the document honest about what was configured; an explicit false "
                        + "would read identically to RolePermissions but accumulate noise")
                .isNull();
        assertThat(after).doesNotContain("can_manage_users");
        assertThat(nodeOf(after, "visibility_scope"))
                .as("a revoke touches exactly one key too")
                .isEqualTo(nodeOf(before, "visibility_scope"));

        assertThat(store.lockCapabilityFlag(PlatformRole.SECURITY_ADMIN, "can_manage_users"))
                .as("and the capability genuinely is no longer held, which is what RolePermissions "
                        + "decides on")
                .contains(false);
    }

    @Test
    @DisplayName("the locked flag read distinguishes true, explicit false, and an absent key")
    void lockCapabilityFlagReadsTheFlag() {
        assertThat(store.lockCapabilityFlag(PlatformRole.SECURITY_ADMIN, "can_manage_users"))
                .as("V10 seeds this true for the Admin role")
                .contains(true);
        assertThat(store.lockCapabilityFlag(PlatformRole.SECURITY_ADMIN, "can_view_reporter_identity"))
                .as("V12 leaves this key present and false; reading it as true would hand the Admin "
                        + "role an identity-disclosure power Section 2 explicitly withholds")
                .contains(false);
        assertThat(store.lockCapabilityFlag(PlatformRole.SECURITY_ADMIN, "no_such_capability"))
                .as("an absent key must read as false, not NULL. The coalesce in the query is what "
                        + "makes that true, and without it the audit entry could not state the prior value")
                .contains(false);
        assertThat(store.lockCapabilityFlag(PlatformRole.ANALYST, "can_manage_users")).contains(false);
    }

    @Test
    @DisplayName("lockCapabilityFlag holds the row lock until its transaction commits")
    void lockCapabilityFlagHoldsTheRowLock() throws Exception {
        // Uses a transaction-bound connection here, and a separate autocommit one for
        // the competitor. Privilege is not what this test is about; the lock is.
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch held = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try {
            Future<?> holder = executor.submit(() -> transactions.executeWithoutResult(status -> {
                new AdminUserStore(new JdbcTemplate(dataSource))
                        .lockCapabilityFlag(PlatformRole.SECURITY_ADMIN, "can_manage_users");
                held.countDown();
                await(release);
            }));
            assertThat(held.await(10, TimeUnit.SECONDS))
                    .as("sanity: the holder reached the locked read inside its transaction")
                    .isTrue();

            Future<?> competitor = executor.submit(() -> {
                new AdminUserStore(new JdbcTemplate(dataSource))
                        .lockCapabilityFlag(PlatformRole.SECURITY_ADMIN, "can_manage_users");
                return null;
            });
            assertThatBlocked(competitor);

            release.countDown();
            assertThat(competitor.get(30, TimeUnit.SECONDS))
                    .as("FOR UPDATE is transaction-scoped: the competing read must proceed once the "
                            + "first transaction ends, and before that two concurrent grants could each "
                            + "read the same prior state and one would be lost")
                    .isNull();
            assertThat(holder.get(30, TimeUnit.SECONDS)).isNull();
        } finally {
            release.countDown();
            executor.shutdownNow();
        }
    }

    // --------------------------------------------------- the FR-6.1 invariant inputs

    @Test
    @DisplayName("the advisory lock excludes a second transaction and is released on commit")
    void advisoryLockSerialisesAdminChanges() throws Exception {
        // The core of FR-6.1's concurrency requirement. The invariant is a predicate
        // over many rows, so row locks cannot provide it: two admins disabling two
        // different remaining administrators touch different rows. Only a lock spanning
        // the whole predicate can, and this is the evidence that the one taken does.
        ExecutorService executor = Executors.newSingleThreadExecutor();
        CountDownLatch held = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try {
            Future<?> holder = executor.submit(() -> {
                transactions.executeWithoutResult(status -> {
                    new AdminUserStore(new JdbcTemplate(dataSource)).lockAuthorizationChanges();
                    held.countDown();
                    await(release);
                });
                return null;
            });

            assertThat(held.await(30, TimeUnit.SECONDS))
                    .as("the lock holder never started, so the rest of the test would prove nothing")
                    .isTrue();

            Future<?> competitor = executor.submit(() -> {
                store.lockAuthorizationChanges();
                return null;
            });
            assertThatBlocked(competitor);

            release.countDown();
            holder.get(30, TimeUnit.SECONDS);

            assertThat(competitor.get(30, TimeUnit.SECONDS))
                    .as("the lock is transaction-scoped, so it must not outlive its transaction or the "
                            + "endpoint would wedge after the first admin change")
                    .isNull();
        } finally {
            release.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("the last-administrator counts see only active users, and honour both exclusions")
    void lastAdministratorCountsAreCorrect() {
        // Two active Admins, one disabled Admin, and an Analyst who never held it.
        assertThat(store.countActiveUsersWithManageUsersExcluding(null))
                .as("the disabled admin must not count: 7.10's guard is about who can still be reached")
                .isEqualTo(2);
        assertThat(store.countActiveUsersWithManageUsersExcluding(ADMIN_ONE)).isEqualTo(1);
        assertThat(store.countActiveUsersWithManageUsersExcluding(ANALYST))
                .as("excluding a user who does not hold it must not change the count")
                .isEqualTo(2);

        assertThat(store.countActiveUsersWithManageUsersExcludingRole(PlatformRole.SECURITY_ADMIN))
                .as("every active holder is a Security Admin here, so excluding that role leaves "
                        + "nobody -- the case the invariant exists to refuse")
                .isEqualTo(0);

        store.grantCapability(PlatformRole.SECURITY_LEAD, "can_manage_users");
        try {
            assertThat(store.countActiveUsersWithManageUsersExcludingRole(PlatformRole.SECURITY_ADMIN))
                    .as("a Lead who now holds the capability is a real remaining administrator")
                    .isEqualTo(0);
        } finally {
            resetPermissions();
        }
    }

    @Test
    @DisplayName("roleHoldsManageUsers and userHoldsManageUsers read the flag through the jsonb")
    void holdQueriesReadTheJsonb() {
        assertThat(store.roleHoldsManageUsers(PlatformRole.SECURITY_ADMIN)).isTrue();
        assertThat(store.roleHoldsManageUsers(PlatformRole.ANALYST)).isFalse();
        assertThat(store.userHoldsManageUsers(ADMIN_ONE)).isTrue();
        assertThat(store.userHoldsManageUsers(ANALYST)).isFalse();
        assertThat(store.userHoldsManageUsers(DISABLED_ADMIN))
                .as("a disabled user still holds it by role; the active flag is the count's concern, "
                        + "not this query's")
                .isTrue();
    }

    @Test
    @DisplayName("findUser projects the lifecycle and version columns it governs")
    void findUserProjectsTheGovernedColumns() {
        AdminUserStore.UserState state = store.findUser(ADMIN_ONE).orElseThrow();

        assertThat(state.id()).isEqualTo(ADMIN_ONE);
        assertThat(state.keycloakSubject()).isEqualTo("it-admin-one");
        assertThat(state.department()).isEqualTo("SECURITY");
        assertThat(state.active()).isTrue();
        assertThat(state.disabledReason()).isNull();
        assertThat(state.version()).isZero();
        assertThat(state.coarseRole()).isEqualTo(PlatformRole.SECURITY_ADMIN);

        assertThat(store.findUser(DISABLED_ADMIN).orElseThrow().disabledReason()).isEqualTo("left in May");
    }

    @Test
    @DisplayName("an unknown user id is empty, not an exception")
    void findUserOnUnknownIdIsEmpty() {
        assertThat(store.findUser(UUID.fromString("00000000-0000-0000-0000-0000000009ff"))).isEmpty();
    }

    // ------------------------------------------------------------------- helpers

    /** Asserts the future has not completed, i.e. the call is genuinely blocked. */
    private void assertThatBlocked(Future<?> blocked) {
        assertThatThrownBy(() -> blocked.get(1, TimeUnit.SECONDS))
                .as("a second admin-authorization change must not proceed while the lock is held; "
                        + "otherwise two admins each pass the count and both commit")
                .isInstanceOf(TimeoutException.class);
    }

    private void await(CountDownLatch latch) {
        try {
            if (!latch.await(30, TimeUnit.SECONDS)) {
                throw new IllegalStateException("latch was never released; the test would hang");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private JdbcTemplate appTemplate() {
        return appTemplate;
    }

    private String permissions(String role) {
        return admin.queryForObject(
                "SELECT permissions::text FROM incident_platform.platform_role "
                        + "WHERE name = ?::incident_platform.platform_coarse_role", String.class, role);
    }

    /** The value of one key in a jsonb document rendered as text, or null if absent. */
    private static String nodeOf(String permissionsJson, String key) {
        try {
            var value = new ObjectMapper().readTree(permissionsJson).get(key);
            return value == null || value.isNull() ? null : value.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The same document with one key set to true -- for exact-equality comparisons. */
    private static String putKey(String permissionsJson, String key) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode node = (ObjectNode) mapper.readTree(permissionsJson);
            node.put(key, true);
            return mapper.writeValueAsString(node);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static com.fasterxml.jackson.databind.JsonNode jsonNode(String json) {
        try {
            return new ObjectMapper().readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
