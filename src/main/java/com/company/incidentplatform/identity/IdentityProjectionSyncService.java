package com.company.incidentplatform.identity;

import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.audit.RequestContext;
import com.company.incidentplatform.authorization.DepartmentKey;
import com.company.incidentplatform.security.PlatformRole;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Synchronizes the minimum identity projection from a validated Keycloak access
 * token. Keycloak remains the source of the coarse role and department claims.
 */
@Service
public class IdentityProjectionSyncService {

    private static final Logger log = LoggerFactory.getLogger(IdentityProjectionSyncService.class);

    private final JdbcTemplate jdbc;
    private final AuditService audit;
    private final Clock clock;
    private final boolean enabled;

    public IdentityProjectionSyncService(
            JdbcTemplate jdbc,
            AuditService audit,
            Clock clock,
            @Value("${incident-platform.identity.token-projection-sync-enabled:true}") boolean enabled) {
        this.jdbc = jdbc;
        this.audit = audit;
        this.clock = clock;
        this.enabled = enabled;
    }

    /**
     * Inserts a newly authenticated principal or applies newer IdP state. A
     * previously disabled application account is never re-enabled by a token.
     */
    @Transactional
    public boolean synchronize(
            String subject,
            String roleName,
            String email,
            String fullName,
            String department,
            Instant issuedAt) {
        if (!enabled || blank(subject) || blank(roleName) || issuedAt == null) {
            return !enabled;
        }

        PlatformRole role;
        try {
            role = PlatformRole.fromKeycloakRole(roleName);
        } catch (IllegalArgumentException invalidRole) {
            log.warn("Refusing identity projection sync for subject {} with unknown role {}", subject, roleName);
            return false;
        }

        Instant now = clock.instant();
        if (issuedAt.isAfter(now.plusSeconds(60))) {
            log.warn("Refusing identity projection sync for subject {} with future token issue time", subject);
            return false;
        }

        Projection before = jdbc.query("""
                    SELECT email, full_name
                      FROM incident_platform.app_user
                     WHERE keycloak_subject = ?
                    """, rs -> rs.next() ? projection(rs) : null, subject);
        if (before == null && blank(email)) {
            return false;
        }
        String effectiveEmail = blank(email) ? before.email() : email.trim();
        String displayName = blank(fullName)
                ? before == null ? subject : before.fullName()
                : fullName.trim();
        int changed = jdbc.update("""
                    INSERT INTO incident_platform.app_user AS existing_user
                        (id, keycloak_subject, full_name, email, department, role_id, active,
                         role_synced_at, last_login_at)
                    SELECT ?, ?, ?, lower(?), ?, r.id, true, ?, ?
                      FROM incident_platform.platform_role r
                     WHERE r.name = ?::incident_platform.platform_coarse_role
                    ON CONFLICT (keycloak_subject) DO UPDATE
                       SET full_name = EXCLUDED.full_name,
                           email = EXCLUDED.email,
                           department = EXCLUDED.department,
                           role_id = EXCLUDED.role_id,
                           role_synced_at = EXCLUDED.role_synced_at,
                           last_login_at = EXCLUDED.last_login_at,
                           version = existing_user.version + 1
                     WHERE existing_user.active = true
                       AND (existing_user.role_synced_at IS NULL
                            OR existing_user.role_synced_at < EXCLUDED.role_synced_at)
                """,
                UUID.randomUUID(),
                subject,
                displayName,
                effectiveEmail,
                DepartmentKey.validate(department),
                Timestamp.from(issuedAt),
                Timestamp.from(now),
                role.name());
        boolean exists = changed > 0 || jdbc.query("""
                    SELECT EXISTS (SELECT 1 FROM incident_platform.app_user WHERE keycloak_subject = ?)
                    """, rs -> rs.next() && rs.getBoolean(1), subject);
        if (changed > 0) {
            UUID id = jdbc.queryForObject("""
                        SELECT id FROM incident_platform.app_user WHERE keycloak_subject = ?
                        """, UUID.class, subject);
            audit.recordSystemEvent(
                    "app_user",
                    id,
                    before == null ? "identity_projection.provision" : "identity_projection.sync",
                    "Keycloak-issued identity projection updated (profile values are excluded from audit detail)",
                    RequestContext.requestId().orElse(UUID.randomUUID()),
                    RequestContext.remoteAddress());
        }
        return exists;
    }

    /**
     * Applies the authoritative Keycloak Admin API snapshot. Unlike token-based
     * refresh, this path can revoke a role or disable an account even when its
     * holder has not obtained a fresh token.
     */
    @Transactional
    public void synchronizeFromIdentityProvider(
            String subject,
            String roleName,
            String email,
            String fullName,
            String department,
            boolean enabled) {
        if (blank(subject)) {
            throw new IllegalArgumentException("Keycloak user subject is required");
        }
        Projection before = jdbc.query("""
                SELECT email, full_name
                  FROM incident_platform.app_user
                 WHERE keycloak_subject = ?
                """, rs -> rs.next() ? projection(rs) : null, subject);

        if (!enabled || blank(roleName) || !isKnownRole(roleName)) {
            String reason = enabled
                    ? "Keycloak account has no recognized platform role"
                    : "Keycloak account disabled by identity provider";
            int changed = jdbc.update("""
                    UPDATE incident_platform.app_user
                       SET active = false, disabled_at = ?, disabled_reason = ?, version = version + 1
                     WHERE keycloak_subject = ? AND active = true
                    """, Timestamp.from(clock.instant()), reason, subject);
            if (changed == 1) {
                UUID id = jdbc.queryForObject("""
                        SELECT id FROM incident_platform.app_user WHERE keycloak_subject = ?
                        """, UUID.class, subject);
                audit.recordSystemEvent(
                        "app_user", id, "identity.account.disabled",
                        reason + "; application access revoked from the current identity-provider state",
                        RequestContext.requestId().orElse(UUID.randomUUID()),
                        RequestContext.remoteAddress());
            }
            return;
        }

        PlatformRole role = PlatformRole.fromKeycloakRole(roleName);
        if (before == null && blank(email)) {
            log.warn("Skipping new Keycloak identity {} because the provider supplied no email", subject);
            return;
        }
        String effectiveEmail = blank(email) ? before.email() : email.trim();
        String effectiveName = blank(fullName) ? (before == null ? subject : before.fullName()) : fullName.trim();
        String effectiveDepartment = blank(department) ? null : department.trim();
        int changed = jdbc.update("""
                INSERT INTO incident_platform.app_user AS existing_user
                    (id, keycloak_subject, full_name, email, department, role_id, active,
                     role_synced_at, last_login_at)
                SELECT ?, ?, ?, lower(?), ?, r.id, true, ?, NULL
                  FROM incident_platform.platform_role r
                 WHERE r.name = ?::incident_platform.platform_coarse_role
                ON CONFLICT (keycloak_subject) DO UPDATE
                   SET full_name = EXCLUDED.full_name,
                       email = EXCLUDED.email,
                       department = EXCLUDED.department,
                       role_id = EXCLUDED.role_id,
                       active = true,
                       disabled_at = NULL,
                       disabled_reason = NULL,
                       role_synced_at = EXCLUDED.role_synced_at,
                       version = existing_user.version + 1
                 WHERE (existing_user.active = true
                        OR existing_user.disabled_reason LIKE 'Keycloak %')
                   AND (existing_user.active = false
                        OR existing_user.full_name IS DISTINCT FROM EXCLUDED.full_name
                        OR existing_user.email IS DISTINCT FROM EXCLUDED.email
                        OR existing_user.department IS DISTINCT FROM EXCLUDED.department
                        OR existing_user.role_id IS DISTINCT FROM EXCLUDED.role_id)
                """,
                UUID.randomUUID(), subject, effectiveName, effectiveEmail, effectiveDepartment,
                Timestamp.from(clock.instant()), role.name());

        if (changed == 0) {
            return;
        }
        UUID id = jdbc.queryForObject(
                "SELECT id FROM incident_platform.app_user WHERE keycloak_subject = ?", UUID.class, subject);
        if (changed > 0) {
            audit.recordSystemEvent(
                    "app_user", id,
                    before == null ? "identity_projection.provision" : "identity_projection.sync",
                    "Identity projection reconciled from Keycloak; profile values are excluded from audit detail",
                    RequestContext.requestId().orElse(UUID.randomUUID()),
                    RequestContext.remoteAddress());
        }
    }

    @Transactional
    public void reconcileSnapshot(List<ProviderIdentity> identities) {
        if (identities.isEmpty()) {
            throw new IllegalStateException("Refusing to reconcile an empty Keycloak user snapshot");
        }
        Set<String> subjects = new java.util.HashSet<>();
        for (ProviderIdentity identity : identities) {
            if (!subjects.add(identity.subject())) {
                throw new IllegalStateException("Keycloak user snapshot contains a duplicate subject");
            }
        }
        for (ProviderIdentity identity : identities) {
            synchronizeFromIdentityProvider(
                    identity.subject(),
                    identity.roleName(),
                    identity.email(),
                    identity.fullName(),
                    identity.department(),
                    identity.enabled());
        }
        deactivateMissingIdentityProviderUsers(subjects);
    }

    @Transactional
    public void deactivateMissingIdentityProviderUsers(Set<String> seenSubjects) {
        if (seenSubjects.isEmpty()) {
            throw new IllegalStateException("Refusing to deprovision users from an empty Keycloak snapshot");
        }
        List<ProjectionSubject> currentUsers = jdbc.query("""
                SELECT id, keycloak_subject FROM incident_platform.app_user WHERE active = true
                """, (rs, rowNum) -> new ProjectionSubject(
                rs.getObject("id", UUID.class), rs.getString("keycloak_subject")));
        for (ProjectionSubject user : currentUsers) {
            if (seenSubjects.contains(user.subject())) {
                continue;
            }
            int changed = jdbc.update("""
                    UPDATE incident_platform.app_user
                       SET active = false, disabled_at = ?, disabled_reason = ?,
                           version = version + 1
                     WHERE id = ? AND active = true
                    """,
                    Timestamp.from(clock.instant()),
                    "Keycloak identity no longer exists",
                    user.id());
            if (changed == 1) {
                audit.recordSystemEvent(
                        "app_user", user.id(), "identity.account.deprovisioned",
                        "Account disabled because the identity provider no longer returns this subject",
                        RequestContext.requestId().orElse(UUID.randomUUID()),
                        RequestContext.remoteAddress());
            }
        }
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static boolean isKnownRole(String roleName) {
        try {
            PlatformRole.fromKeycloakRole(roleName);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static Projection projection(ResultSet rs) throws SQLException {
        return new Projection(rs.getString("email"), rs.getString("full_name"));
    }

    private record Projection(String email, String fullName) {
    }

    private record ProjectionSubject(UUID id, String subject) {
    }

    public record ProviderIdentity(
            String subject,
            String roleName,
            String email,
            String fullName,
            String department,
            boolean enabled) {
    }
}
