package com.company.incidentplatform.audit;

import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.DeniedReason;
import com.company.incidentplatform.security.PlatformUser;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Timestamp;
import java.time.Clock;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Section 7.11 -- the audit write path.
 *
 * <p>Writes exclusively through the {@code audit_log_append} function defined in
 * {@code V7__audit_log.sql}. That function is the only sanctioned writer: the
 * runtime role's direct INSERT, UPDATE, DELETE, and TRUNCATE on
 * {@code audit_log} are all revoked ({@code V9__database_security_grants.sql}),
 * and the function computes the previous-entry hash and links the chain under an
 * advisory lock itself. Writing the table directly would be a privilege error
 * at best, and an unchained, unattributable row at worst -- which would silently
 * break {@code verify_audit_log_chain}, the very control 7.11 exists to provide.
 *
 * <h2>Named-argument binding</h2>
 *
 * <p>The call uses PostgreSQL's named notation ({@code p_action => ?}) rather
 * than positional. The function has 19 parameters, several of them
 * {@code jsonb} or enum-typed, and positional binding to a signature this wide is
 * a silent-corruption risk: a swapped pair of adjacent {@code text} parameters
 * would still execute, and would write a plausible-looking but incorrect audit
 * trail. Named notation fails loudly if a parameter is renamed and makes each
 * value self-describing at the call site.
 *
 * <h2>Fail-open on write failure, deliberately</h2>
 *
 * <p>An audit-write failure must not become a 500, and must not be swallowed.
 * The call is retried, and on persistent failure an ERROR is logged with enough
 * context to reconstruct the event by hand. Audit durability is enforced
 * structurally -- the runtime role <em>cannot</em> reach the table by any other
 * route -- so an entry can only be lost while the database itself is unavailable,
 * which is already a reportable outage and will surface through the
 * application's health checks.
 *
 * <p>Failing closed was rejected deliberately: making a permission change
 * depend on an audit insert would hand anyone able to exhaust the connection
 * pool a denial-of-service primitive against the entire authorization system.
 * Loss of audit fidelity is bad; loss of availability is worse, and 7.11's
 * priority is that denials are <em>recorded</em>, not that they are fatal.
 */
@Component
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    /**
     * Named notation, with explicit casts for the enum and {@code inet}
     * parameters. The driver sends text/unknown, and PostgreSQL will not
     * implicitly cast a parameter into a user-defined enum.
     */
    private static final String APPEND_SQL = """
            SELECT incident_platform.audit_log_append(
                p_action                 => ?,
                p_entity_type            => ?,
                p_entity_id              => ?::uuid,
                p_actor_id               => ?::uuid,
                p_actor_role             => ?::incident_platform.platform_coarse_role,
                p_actor_keycloak_subject => ?,
                p_result                 => ?::incident_platform.audit_result,
                p_reason_code            => ?,
                p_reason_detail          => ?,
                p_endpoint               => ?,
                p_method                 => ?,
                p_request_id             => ?::uuid,
                p_authorization_check    => ?::incident_platform.authorization_check_type,
                p_authorization_rule     => ?,
                p_ip_address             => ?::inet,
                p_before_value           => ?::jsonb,
                p_after_value            => ?::jsonb,
                p_pii_redacted           => ?::boolean,
                p_timestamp              => ?::timestamptz
            )
            """;

    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final int maxAttempts;

    public AuditService(
            JdbcTemplate jdbc,
            Clock clock,
            @Value("${audit.max-attempts:3}") int maxAttempts) {
        this.jdbc = jdbc;
        this.clock = clock;
        this.maxAttempts = Math.max(1, maxAttempts);
    }

    /**
     * Records a denied-authorization event, as 7.11 requires.
     *
     * @param reason the 7.11 "reason/category"; this is what turns a burst of
     *               denials into the IDOR/BOLA anomaly signal of 7.12. A 403 with
     *               no classification is indistinguishable from ordinary client
     *               error and simply disappears from the logs.
     */
    public void recordDenied(
            PlatformUser actor,
            DeniedReason reason,
            String resourceType,
            UUID resourceId,
            String action,
            String endpoint,
            String httpMethod,
            UUID requestId,
            String remoteAddress,
            AuthorizationCheckType checkType,
            String authorizationRule) {
        write(
                actor,
                AuditResult.DENIED,
                reason.name(),
                "Section 7.11 denial: " + authorizationRule,
                resourceType,
                resourceId,
                action,
                endpoint,
                httpMethod,
                requestId,
                remoteAddress,
                checkType,
                authorizationRule,
                null,
                null,
                false);
    }

    /** Records an allowed action together with the check that permitted it (7.11). */
    public void recordAllowed(
            PlatformUser actor,
            String resourceType,
            UUID resourceId,
            String action,
            String endpoint,
            String httpMethod,
            UUID requestId,
            String remoteAddress,
            AuthorizationCheckType checkType,
            String authorizationRule) {
        write(
                actor,
                AuditResult.ALLOWED,
                null,
                null,
                resourceType,
                resourceId,
                action,
                endpoint,
                httpMethod,
                requestId,
                remoteAddress,
                checkType,
                authorizationRule,
                null,
                null,
                false);
    }

    /**
     * Records an action by the platform itself rather than by a user.
     *
     * <p>Exists for 7.1's account lockout and unlock events, which have no
     * {@link PlatformUser} -- the actor is the monitoring control, and the subject
     * of the row is the affected account. {@code actor_id} is left null and the
     * detail carries the username, so the row is still attributable to a subject
     * even though there is no authenticated principal behind it. 7.11's
     * "with actor" is satisfied by recording who was locked out and why, which is
     * the information an investigation actually needs.
     */
    public void recordSystemEvent(
            String resourceType,
            UUID resourceId,
            String action,
            String detail,
            UUID requestId,
            String remoteAddress) {
        write(
                null,
                AuditResult.ALLOWED,
                null,
                detail,
                resourceType,
                resourceId,
                action,
                null,
                null,
                requestId,
                remoteAddress,
                AuthorizationCheckType.NONE,
                "system.control",
                null,
                null,
                false);
    }

    /**
     * Records an action carrying the before/after values 7.11 requires.
     *
     * <p>The values must already be redacted by the caller -- 7.11 forbids secrets,
     * tokens, keys, and sensitive PII from being written into these columns even
     * temporarily, and redacting at the call site rather than inside the insert is
     * deliberate: a redaction step in this class would be one refactor away from
     * being bypassed, whereas a caller that never assembles the raw value cannot
     * leak it. {@code piiRedacted} records that the caller did so.
     */
    public void recordChange(
            PlatformUser actor,
            String resourceType,
            UUID resourceId,
            String action,
            String endpoint,
            String httpMethod,
            UUID requestId,
            String remoteAddress,
            AuthorizationCheckType checkType,
            String authorizationRule,
            String beforeValueJson,
            String afterValueJson,
            boolean piiRedacted) {
        write(
                actor,
                AuditResult.ALLOWED,
                null,
                null,
                resourceType,
                resourceId,
                action,
                endpoint,
                httpMethod,
                requestId,
                remoteAddress,
                checkType,
                authorizationRule,
                beforeValueJson,
                afterValueJson,
                piiRedacted);
    }

    private void write(
            PlatformUser actor,
            AuditResult result,
            String reasonCode,
            String reasonDetail,
            String resourceType,
            UUID resourceId,
            String action,
            String endpoint,
            String httpMethod,
            UUID requestId,
            String remoteAddress,
            AuthorizationCheckType checkType,
            String authorizationRule,
            String beforeValueJson,
            String afterValueJson,
            boolean piiRedacted) {

        Timestamp occurredAt = Timestamp.from(clock.instant());

        Object[] args = {
            action,
            resourceType,
            resourceId,
            actor == null ? null : actor.id(),
            actor == null ? null : actor.role().name(),
            actor == null ? null : actor.keycloakSubject(),
            result.name(),
            reasonCode,
            reasonDetail,
            endpoint,
            httpMethod,
            requestId,
            (checkType == null ? AuthorizationCheckType.NONE : checkType).name(),
            authorizationRule,
            sanitizeIp(remoteAddress),
            blankToNull(beforeValueJson),
            blankToNull(afterValueJson),
            piiRedacted,
            occurredAt
        };

        RuntimeException last = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                jdbc.queryForObject(APPEND_SQL, String.class, args);
                return;
            } catch (RuntimeException e) {
                last = e;
                log.error(
                        "Audit append failed (attempt {}/{}) result={} entity={}:{} action={} "
                                + "requestId={} actor={} rule={}",
                        attempt,
                        maxAttempts,
                        result,
                        resourceType,
                        resourceId,
                        action,
                        requestId,
                        actor == null ? "<none>" : actor.email(),
                        authorizationRule,
                        e);
            }
        }
        log.error("Audit entry permanently lost after {} attempts: {}",
                maxAttempts, describe(args), last);
    }

    /**
     * The column is {@code inet}, and {@code X-Forwarded-For} is
     * client-controlled (7.5 trust-the-proxy guidance). A header value that is
     * not a valid address would make the whole insert fail and cost us the audit
     * entry, so an unparseable address is recorded as null rather than allowed
     * to poison the write.
     */
    private static String sanitizeIp(String remoteAddress) {
        if (remoteAddress == null || remoteAddress.isBlank()) {
            return null;
        }
        String candidate = remoteAddress.trim();
        // Strip a port suffix ("10.0.0.1:54321") and a zone id, both of which
        // appear in proxy-forwarded values.
        int colon = candidate.lastIndexOf(':');
        if (colon > 0 && candidate.indexOf(':') == colon) {
            candidate = candidate.substring(0, colon);
        }
        int zone = candidate.indexOf('%');
        if (zone > 0) {
            candidate = candidate.substring(0, zone);
        }
        if (candidate.isBlank()) {
            return null;
        }
        if (candidate.indexOf(':') >= 0) {
            if (!candidate.matches("[0-9a-fA-F:.]+")) {
                return null;
            }
            try {
                return InetAddress.getByName(candidate).getHostAddress();
            } catch (UnknownHostException e) {
                return null;
            }
        }
        String[] octets = candidate.split("\\.", -1);
        if (octets.length != 4) {
            return null;
        }
        for (String octet : octets) {
            if (!octet.matches("\\d{1,3}") || Integer.parseInt(octet) > 255) {
                return null;
            }
        }
        return candidate;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private static String describe(Object[] a) {
        return "action=" + a[0]
                + " entity=" + a[1] + ":" + a[2]
                + " actor=" + a[4] + "/" + a[5]
                + " result=" + a[6]
                + " reason=" + a[7]
                + " endpoint=" + a[9] + " " + a[10]
                + " requestId=" + a[11]
                + " rule=" + a[13];
    }

    private enum AuditResult {
        ALLOWED,
        DENIED
    }
}
