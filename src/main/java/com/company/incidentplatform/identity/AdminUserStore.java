package com.company.incidentplatform.identity;

import com.company.incidentplatform.security.PlatformRole;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * Section 6.2.3 / 7.10 -- writes to the application-side authorization projection.
 *
 * <p>JDBC rather than the JPA entities, for two reasons that are not stylistic.
 * {@link AppUserEntity} has no setters (it is a read-side projection, and
 * {@code @Version} on it only protects JPA's own load-modify-save cycle, which is
 * not the cycle an admin command performs), and {@link PlatformRoleEntity} maps
 * {@code permissions} as a {@code String} over a {@code jsonb} column, so writing
 * it through the ORM means hand-serialising JSON and hoping the driver casts it.
 * The jsonb operators below do the read-modify-write inside PostgreSQL instead,
 * which is both shorter and atomic.
 *
 * <h2>7.10 concurrency</h2>
 *
 * <p>The two tables need different mechanisms because they carry different
 * concurrency support, and the difference is worth stating rather than papering
 * over:
 *
 * <ul>
 *   <li>{@code app_user} has a {@code version} column and {@code @Version}, so the
 *       user update is a conditional {@code UPDATE ... WHERE version = ?}. Zero
 *       rows affected means a concurrent admin won, and the caller is told so
 *       rather than silently overwriting a security-relevant change.</li>
 *   <li>{@code platform_role} has <em>no</em> version column -- the optimistic
 *       locking in {@link AppUserEntity} is per-user, and a capability change is
 *       per-role. So the role row is taken with {@code SELECT ... FOR UPDATE}
 *       instead, which serialises concurrent grants and revokes without a
 *       migration. A blind read-modify-write of the jsonb would let two admins'
 *       grants to different capabilities lose one of the two.</li>
 * </ul>
 */
@Repository
public class AdminUserStore {

    private final JdbcTemplate jdbc;

    public AdminUserStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** The user fields this endpoint is allowed to see and change. Deliberately no email/full_name. */
    public record UserState(
            UUID id,
            String keycloakSubject,
            String department,
            boolean active,
            String disabledReason,
            int version,
            PlatformRole coarseRole) {
    }

    public Optional<UserState> findUser(UUID id) {
        return jdbc.query(
                """
                SELECT u.id, u.keycloak_subject, u.department, u.active, u.disabled_reason, u.version,
                       r.name AS coarse_role
                  FROM incident_platform.app_user u
                  JOIN incident_platform.platform_role r ON r.id = u.role_id
                 WHERE u.id = ?
                """,
                (rs, rowNum) -> new UserState(
                        rs.getObject("id", UUID.class),
                        rs.getString("keycloak_subject"),
                        rs.getString("department"),
                        rs.getBoolean("active"),
                        rs.getString("disabled_reason"),
                        rs.getInt("version"),
                        PlatformRole.valueOf(rs.getString("coarse_role"))),
                id).stream().findFirst();
    }

    /**
     * Serialises every change that could remove the last {@code can_manage_users}
     * holder, for the duration of the transaction.
     *
     * <p>Row locking cannot cover this guard, and the reason is worth being explicit
     * about. The last-administrator check counts active users and then writes; two
     * admins acting at once could each pass the count and each commit, leaving
     * nobody. Locking the row being changed would not help, because the two
     * operations touch <em>different</em> rows -- two users being disabled, or the
     * same capability revoked from two different roles. The predicate spans rows, so
     * the lock has to as well.
     *
     * <p>A transaction-scoped advisory lock is the fit: it is released automatically
     * when the transaction ends, including on rollback, so a failure cannot leave the
     * endpoint wedged. It matches the existing precedent in this schema, where
     * {@code audit_log_append} takes an advisory lock to stop the hash chain forking.
     *
     * <p>The cost is that all admin authorization changes serialise against each
     * other. That is a deliberate trade: these are rare, human-initiated operations
     * where correctness of the lockout invariant matters more than write concurrency.
     */
    public void lockAuthorizationChanges() {
        jdbc.queryForObject("SELECT pg_advisory_xact_lock(?)", Object.class, ADVISORY_LOCK_AUTHORIZATION);
    }

    /**
     * A fixed, arbitrary 64-bit key, namespaced from the audit chain's lock so the
     * two cannot collide and mask each other.
     */
    private static final long ADVISORY_LOCK_AUTHORIZATION = 7_314_159_265_358L;

    /**
     * 7.10 conditional update. Returns false when the version no longer matches, which
     * the caller reports as a conflict rather than retrying -- a second admin editing
     * the same user is a conversation, not a race to be won.
     *
     * <p>{@code disabled_at} and {@code disabled_reason} are written together with
     * {@code active} because the schema enforces
     * {@code ck_app_user_active_disabled_consistent} (active iff disabled_at is null)
     * and {@code ck_app_user_disabled_reason}. Writing them independently would
     * produce a row the database rejects, and the resulting 409 would say nothing
     * about what the admin actually did.
     *
     * <p>Writes exactly what it is given: the caller owns the rule that an active
     * account carries no disable columns, and re-deriving it here would split one
     * decision across two layers that could disagree.
     *
     * <p>{@code updated_at} is not set. {@code trg_app_user_updated_at} calls
     * {@code set_updated_at()} on every UPDATE and would overwrite any value
     * supplied here, so writing one would be a dead assignment that reads as though
     * the caller's timestamp were being preserved.
     */
    public boolean updateUser(
            UUID id,
            int expectedVersion,
            String department,
            boolean active,
            String disabledReason,
            Instant disabledAt) {

        int rows = jdbc.update(
                """
                UPDATE incident_platform.app_user
                   SET department      = coalesce(?, department),
                       active          = ?,
                       disabled_at     = ?,
                       disabled_reason = ?,
                       version         = version + 1
                 WHERE id = ? AND version = ?
                """,
                department,
                active,
                active ? null : Timestamp.from(disabledAt),
                disabledReason,
                id,
                expectedVersion);
        return rows == 1;
    }

    /**
     * Takes the role row for update and reads back the one flag about to change, so it
     * can be audited as a before/after pair.
     *
     * <p>{@code FOR UPDATE} rather than a version predicate -- see the class comment.
     *
     * <p>{@code coalesce(..., 'false')} so an absent key reads as not held, matching how
     * {@code RolePermissions} treats an absent flag. Without it the comparison would be
     * NULL -- neither true nor false -- and the audit entry would be unable to say
     * what the state was. Reading the value here rather than in the service keeps
     * PostgreSQL the authority on its own jsonb, and
     * {@code ck_platform_role_permissions_object} means the document is always an
     * object, so there is no unparseable case to tolerate.
     */
    public Optional<Boolean> lockCapabilityFlag(PlatformRole role, String permissionKey) {
        return jdbc.query(
                "SELECT coalesce(permissions ->> ?::text, 'false') = 'true' "
                        + "FROM incident_platform.platform_role "
                        + "WHERE name = ?::incident_platform.platform_coarse_role FOR UPDATE",
                (rs, rowNum) -> rs.getBoolean(1),
                permissionKey,
                role.name()).stream().findFirst();
    }

    /**
     * Grants one capability by merging a single key into the jsonb.
     *
     * <p>Merging one key rather than replacing the whole document is deliberate.
     * {@code permissions} also carries {@code visibility_scope} and
     * {@code led_departments}, which are 6.2.3 scoping detail and not capabilities;
     * a whole-document write from a request body would let a capability grant
     * silently reset a role's visibility scope, and would make every grant a
     * full re-specification of the role. The single-key merge also makes the
     * operation idempotent, so a retried grant does not fail.
     */
    public void grantCapability(PlatformRole role, String permissionKey) {
        jdbc.update(
                "UPDATE incident_platform.platform_role "
                        + "SET permissions = permissions || jsonb_build_object(?::text, true), "
                        + "    updated_at = now() "
                        + "WHERE name = ?::incident_platform.platform_coarse_role",
                permissionKey, role.name());
    }

    /**
     * Revokes one capability by removing that key.
     *
     * <p>Removes the key rather than writing {@code false}. {@code RolePermissions}
     * defaults every absent flag to false, so the two spellings behave identically --
     * but removal keeps the stored document honest about what was configured rather
     * than accumulating explicit false entries, and it means {@code V10}/{@code V12}
     * seed lines that set a capability false read the same as one that never
     * mentioned it.
     */
    public void revokeCapability(PlatformRole role, String permissionKey) {
        jdbc.update(
                "UPDATE incident_platform.platform_role "
                        + "SET permissions = permissions - ?::text, updated_at = now() "
                        + "WHERE name = ?::incident_platform.platform_coarse_role",
                permissionKey, role.name());
    }

    /**
     * Counts ACTIVE users who would retain {@code can_manage_users}, optionally
     * excluding one user.
     *
     * <p>Exists to make an unrecoverable configuration impossible rather than merely
     * unlikely: revoking {@code can_manage_users} from the only role that holds it
     * leaves nobody able to grant it back, and this project has no Keycloak
     * write-through to fall back on. The check is a count of real active users
     * rather than a rule about which role may be edited, so it stays correct as
     * roles and headcount change.
     */
    public int countActiveUsersWithManageUsersExcluding(UUID excludedUserId) {
        Integer count = jdbc.queryForObject(
                """
                SELECT count(*)
                  FROM incident_platform.app_user u
                  JOIN incident_platform.platform_role r ON r.id = u.role_id
                 WHERE u.active
                   AND r.permissions->>'can_manage_users' = 'true'
                   AND (?::uuid IS NULL OR u.id <> ?::uuid)
                """,
                Integer.class,
                excludedUserId, excludedUserId);
        return count == null ? 0 : count;
    }

    /** As above, but excluding every user holding {@code role} -- used when a role loses the capability. */
    public int countActiveUsersWithManageUsersExcludingRole(PlatformRole excludedRole) {
        Integer count = jdbc.queryForObject(
                """
                SELECT count(*)
                  FROM incident_platform.app_user u
                  JOIN incident_platform.platform_role r ON r.id = u.role_id
                 WHERE u.active
                   AND r.permissions->>'can_manage_users' = 'true'
                   AND r.name <> ?::incident_platform.platform_coarse_role
                """,
                Integer.class,
                excludedRole.name());
        return count == null ? 0 : count;
    }

    /** True when the user currently holds {@code can_manage_users} through their role. */
    public boolean userHoldsManageUsers(UUID userId) {
        Boolean held = jdbc.queryForObject(
                """
                SELECT r.permissions->>'can_manage_users' = 'true'
                  FROM incident_platform.app_user u
                  JOIN incident_platform.platform_role r ON r.id = u.role_id
                 WHERE u.id = ?
                """,
                Boolean.class,
                userId);
        return Boolean.TRUE.equals(held);
    }

    /** True when the named role currently carries {@code can_manage_users}. */
    public boolean roleHoldsManageUsers(PlatformRole role) {
        return jdbc.query(
                        "SELECT permissions->>'can_manage_users' = 'true' FROM incident_platform.platform_role "
                                + "WHERE name = ?::incident_platform.platform_coarse_role",
                        (rs, rowNum) -> rs.getBoolean(1),
                        role.name())
                .stream()
                .findFirst()
                .orElse(false);
    }
}
