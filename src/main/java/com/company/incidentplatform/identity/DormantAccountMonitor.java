package com.company.incidentplatform.identity;

import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.audit.RequestContext;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Disables dormant human accounts and audits each lifecycle change. */
@Component
@ConditionalOnProperty(
        prefix = "incident-platform.identity.dormancy",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
public class DormantAccountMonitor {

    private static final Logger log = LoggerFactory.getLogger(DormantAccountMonitor.class);

    private final JdbcTemplate jdbc;
    private final AuditService audit;
    private final Clock clock;
    private final int inactiveDays;

    public DormantAccountMonitor(
            JdbcTemplate jdbc,
            AuditService audit,
            Clock clock,
            @Value("${incident-platform.identity.dormancy.inactive-days:90}") int inactiveDays) {
        if (inactiveDays < 1) {
            throw new IllegalArgumentException("Dormant-account inactivity period must be at least one day");
        }
        this.jdbc = jdbc;
        this.audit = audit;
        this.clock = clock;
        this.inactiveDays = inactiveDays;
    }

    @Scheduled(
            fixedDelayString = "${incident-platform.identity.dormancy.poll-interval-ms:3600000}",
            initialDelayString = "${incident-platform.identity.dormancy.initial-delay-ms:60000}")
    @Transactional
    public void disableDormantAccounts() {
        OffsetDateTime cutoff = OffsetDateTime.ofInstant(
                clock.instant().minus(Duration.ofDays(inactiveDays)), ZoneOffset.UTC);
        List<UUID> candidates = jdbc.query("""
                SELECT u.id
                  FROM incident_platform.app_user u
                  JOIN incident_platform.platform_role r ON r.id = u.role_id
                 WHERE u.active = true
                   AND r.name <> 'SERVICE_ACCOUNT'
                   AND (u.last_login_at IS NULL OR u.last_login_at < ?)
                   AND u.created_at < ?
                 ORDER BY u.id
                """,
                (rs, rowNum) -> rs.getObject(1, UUID.class),
                Timestamp.from(cutoff.toInstant()), Timestamp.from(cutoff.toInstant()));

        for (UUID id : candidates) {
            int changed = jdbc.update("""
                    UPDATE incident_platform.app_user
                       SET active = false,
                           disabled_at = ?,
                           disabled_reason = ?,
                           version = version + 1
                     WHERE id = ? AND active = true
                       AND (last_login_at IS NULL OR last_login_at < ?)
                       AND created_at < ?
                    """,
                    Timestamp.from(clock.instant()),
                    "Dormant account: no login for at least " + inactiveDays + " days",
                    id,
                    Timestamp.from(cutoff.toInstant()),
                    Timestamp.from(cutoff.toInstant()));
            if (changed == 1) {
                audit.recordSystemEvent(
                        "app_user",
                        id,
                        "identity.account.auto_disabled",
                        "Account disabled after configured inactivity period of " + inactiveDays + " days",
                        RequestContext.requestId().orElse(UUID.randomUUID()),
                        RequestContext.remoteAddress());
                log.info("Disabled dormant account {} after {} inactive days", id, inactiveDays);
            }
        }
    }
}
