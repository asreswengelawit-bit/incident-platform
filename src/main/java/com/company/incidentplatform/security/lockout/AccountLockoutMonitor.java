package com.company.incidentplatform.security.lockout;

import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.audit.RequestContext;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Section 7.1 -- the control that makes the realm's brute-force lockout actually
 * <em>notify</em> anyone.
 *
 * <p>7.1: "Lockout and unlock events are audited and notify the Admin for
 * privileged accounts (Analyst, Security Lead, Security Admin, Auditor) -- Reporter
 * lockouts are audited but need not page an Admin by default, to avoid alert
 * fatigue from routine forgotten-password lockouts."
 *
 * <p>Both destinations are written, and they are written for every lockout:
 * <ul>
 *   <li><strong>Audit</strong> (7.11) via {@link AuditService}, for every account
 *       including Reporters. This is the record, and it is unconditional.</li>
 *   <li><strong>Kafka</strong> (5.1/5.4) on {@code security.account-lockout},
 *       carrying {@code pageAdmin} so the Phase 5 Notification Service decides who
 *       to wake. The event is published regardless of role so that audit and
 *       notification cannot drift apart -- a consumer filtering on role before
 *       writing its record would reintroduce the silent-drop 7.1 warns about.</li>
 * </ul>
 *
 * <p>Publication is asynchronous and at-least-once, so a broker outage cannot
 * block or roll back the incident path this runs alongside -- 5.4's requirement
 * that a dropped notification never fails the underlying state change. The
 * cost of that choice is that a page can be lost while the audit record, written
 * in the same pass, survives; 7.1's own DLQ requirement (5.4) covers that case.
 */
@Component
@ConditionalOnProperty(
        prefix = "incident-platform.lockout-monitor",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
public class AccountLockoutMonitor {

    private static final Logger log = LoggerFactory.getLogger(AccountLockoutMonitor.class);

    /** 5.1: partitioned by the locked user id so per-account ordering is preserved. */
    public static final String TOPIC = "security.account-lockout";

    private final KeycloakEventFeedClient feed;
    private final BruteForceLockoutDetector detector;
    private final AuditService auditService;
    private final KafkaTemplate<String, Object> kafka;
    private final int eventBatchSize;
    private final boolean publishToKafka;

    private volatile BruteForcePolicy cachedPolicy;
    private volatile boolean warnedNoPolicy;

    public AccountLockoutMonitor(
            KeycloakEventFeedClient feed,
            BruteForceLockoutDetector detector,
            AuditService auditService,
            KafkaTemplate<String, Object> kafka,
            @Value("${incident-platform.lockout-monitor.event-batch-size:200}") int eventBatchSize,
            @Value("${incident-platform.lockout-monitor.publish-to-kafka:true}") boolean publishToKafka) {
        this.feed = feed;
        this.detector = detector;
        this.auditService = auditService;
        this.kafka = kafka;
        this.eventBatchSize = eventBatchSize;
        this.publishToKafka = publishToKafka;
    }

    /**
     * Polled rather than event-driven because Keycloak offers no push for this.
     * {@code fixedDelay} rather than {@code fixedRate} so a slow poll cannot
     * overlap itself and double-count a failure, which would inflate the
     * reconstructed wait and page on a lockout that had not happened yet.
     */
    @Scheduled(
            fixedDelayString = "${incident-platform.lockout-monitor.poll-interval-ms:30000}",
            initialDelayString = "${incident-platform.lockout-monitor.initial-delay-ms:60000}")
    public void poll() {
        try {
            refreshPolicy();
            if (cachedPolicy == null) {
                return;
            }
            for (KeycloakEventFeedClient.LoginEvent event : feed.fetchRecentLoginEvents(eventBatchSize)) {
                process(event);
            }
        } catch (RuntimeException e) {
            // An uncaught throw from a @Scheduled method cancels all subsequent
            // runs in Spring's scheduler, which would silently end 7.1's alerting
            // for the lifetime of the pod. Swallowing at the boundary is what
            // keeps the control alive.
            log.error("Account lockout poll failed; monitoring continues next cycle", e);
        }
    }

    void process(KeycloakEventFeedClient.LoginEvent event) {
        if (event.success()) {
            // 7.1: the unlock event. The detector clears the counter so a later
            // attack alerts again rather than being suppressed as "already paged".
            boolean wasLocked = detector.wasLocked(event.userId());
            detector.recordSuccess(event.userId());
            if (wasLocked) {
                record(event, "account_unlock", false, "Account unlocked after brute-force lockout (Section 7.1)");
            }
            return;
        }

        Set<String> roles = feed.fetchRealmRoles(event.userId());
        Optional<AccountLockoutAlert> alert = detector.recordFailure(
                event.userId(), event.username(), event.occurredAt(), roles);
        alert.ifPresent(lockout -> record(lockout, AccountLockoutAlert.AUDIT_ACTION, lockout.pageAdmin(),
                lockout.summary()));
    }

    private void record(AccountLockoutAlert alert, String action, boolean pageAdmin, String detail) {
        // 7.1: every lockout is audited; paging is the role-dependent part.
        auditService.recordSystemEvent(
                "user",
                alert.userId(),
                action,
                detail,
                RequestContext.requestId().orElse(UUID.randomUUID()),
                // The configured trusted-proxy decision, not a hard-coded false:
                // behind a proxy that overwrites X-Forwarded-For, the socket
                // address is the proxy's and every lockout would be attributed
                // to it. 7.12 counts denials and lockouts per source address.
                RequestContext.remoteAddress());

        if (!publishToKafka) {
            return;
        }
        try {
            kafka.send(TOPIC, alert.userId().toString(), alert)
                    .whenComplete((result, error) -> {
                        if (error != null) {
                            log.error("Failed to publish account lockout alert for user {}: {}",
                                    alert.userId(), error.getMessage());
                        } else if (pageAdmin) {
                            log.warn("Section 7.1 -- privileged account locked, Admin page required: {}",
                                    alert.summary());
                        }
                    });
        } catch (RuntimeException e) {
            // A notification failure must not abort the poll loop; 5.4 makes
            // delivery at-least-once with a DLQ the durability mechanism, and the
            // audit record above has already been written.
            log.error("Failed to publish account lockout alert for user {}: {}",
                    alert.userId(), e.getMessage());
        }
    }

    private void record(
            KeycloakEventFeedClient.LoginEvent event, String action, boolean pageAdmin, String detail) {
        AccountLockoutAlert synthetic = new AccountLockoutAlert(
                event.userId(), event.username(), event.occurredAt(), 0, 0L, Set.of(), pageAdmin, false);
        record(synthetic, action, pageAdmin, detail);
    }

    /**
     * Re-reads the realm's parameters on first use and then on a slow cadence.
     * Re-reading them constantly would add an admin-API call per poll for a value
     * that changes perhaps quarterly; never re-reading them would mean a realm
     * change silently left this reconstructing the old lockout behaviour.
     */
    private void refreshPolicy() {
        if (cachedPolicy != null) {
            return;
        }
        BruteForcePolicy fetched = feed.fetchBruteForcePolicy();
        if (fetched == null) {
            if (!warnedNoPolicy) {
                log.warn("Brute-force policy unavailable from Keycloak; lockout alerting inactive "
                        + "until the realm admin API is reachable");
                warnedNoPolicy = true;
            }
            return;
        }
        cachedPolicy = fetched;
        detector.setPolicy(fetched);
        log.info("Brute-force policy loaded: factor={} increment={}s maxWait={}s decay={}s protected={}",
                fetched.failureFactor(), fetched.waitIncrementSeconds(), fetched.maxFailureWaitSeconds(),
                fetched.maxDeltaTimeSeconds(), fetched.bruteForceProtected());
        if (fetched.bruteForceProtected() && fetched.waitIncrementSeconds() <= 0L) {
            log.warn("Section 7.1 requires INCREMENTAL lockout wait, but the realm reports "
                    + "waitIncrementSeconds=0, which is a fixed flat lockout window. "
                    + "This is the configuration 7.1 explicitly rejects.");
        }
    }

    /** Test seam. */
    void setCachedPolicy(BruteForcePolicy policy) {
        this.cachedPolicy = policy;
        this.detector.setPolicy(policy);
    }
}
