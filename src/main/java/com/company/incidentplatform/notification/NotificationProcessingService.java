package com.company.incidentplatform.notification;

import com.company.incidentplatform.authorization.DepartmentKey;
import com.company.incidentplatform.authorization.IncidentResponsibilityResolver;
import com.company.incidentplatform.security.PlatformRole;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class NotificationProcessingService {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationProcessingService.class);

    private final NotificationOutboxRepository outboxRepository;
    private final NotificationRuleRepository ruleRepository;
    private final IncidentResponsibilityResolver responsibilityResolver;
    private final NotificationDeliveryService deliveryService;

    public NotificationProcessingService(
            NotificationOutboxRepository outboxRepository,
            NotificationRuleRepository ruleRepository,
            IncidentResponsibilityResolver responsibilityResolver,
            NotificationDeliveryService deliveryService) {
        this.outboxRepository = outboxRepository;
        this.ruleRepository = ruleRepository;
        this.responsibilityResolver = responsibilityResolver;
        this.deliveryService = deliveryService;
    }

    public void process(IncidentLifecycleEvent event) {
        Map<RecipientChannel, UUID> recipients = new LinkedHashMap<>();
        addBaseRecipients(event, recipients);
        addRuleRecipients(event, recipients);

        for (Map.Entry<RecipientChannel, UUID> entry : recipients.entrySet()) {
            UUID recipientId = entry.getValue();
            if (entry.getKey().channel() == NotificationChannel.IN_APP) {
                deliveryService.createInAppIfMissing(event, recipientId);
            } else if (deliveryService.prepareEmailIfMissing(event, recipientId)) {
                deliveryService.sendPendingEmail(event, recipientId);
            }
        }
    }

    @Transactional
    public void markDeadLettered(UUID eventId, String reason) {
        outboxRepository.findById(eventId).ifPresent(outbox ->
                outbox.markDeadLettered(reason, OffsetDateTime.now(ZoneOffset.UTC)));
    }

    private void addBaseRecipients(
            IncidentLifecycleEvent event, Map<RecipientChannel, UUID> recipients) {
        addBothChannels(recipients, event.recipientUserId());
        addBothChannels(recipients, event.assigneeUserId());
        addBothChannels(recipients, event.reporterUserId());
    }

    private void addRuleRecipients(
            IncidentLifecycleEvent event, Map<RecipientChannel, UUID> recipients) {
        if (!isBroadcastType(event.eventType())) {
            return;
        }
        String department = DepartmentKey.normalize(event.departmentKey());
        for (NotificationRuleEntity rule : NotificationRuleMatcher.matching(
                ruleRepository.findByEnabledTrueAndDeletedAtIsNull(), event)) {
            PlatformRole role = rule.getRecipientRole();
            if (role != PlatformRole.SECURITY_LEAD && role != PlatformRole.SECURITY_ADMIN) {
                throw new IllegalStateException("Notification rule has unsupported recipient role: " + role);
            }
            var resolved = responsibilityResolver.resolve(role, department);
            if (role == PlatformRole.SECURITY_LEAD && resolved.isEmpty()) {
                LOGGER.warn("No SECURITY_LEAD matches canonical department '{}'; routing event {} to SECURITY_ADMIN",
                        department, event.idempotencyKey());
                resolved = responsibilityResolver.resolve(PlatformRole.SECURITY_ADMIN, department);
            }
            resolved.forEach(userId -> recipients.putIfAbsent(
                    new RecipientChannel(userId, rule.getChannel()), userId));
        }
    }

    private void addBothChannels(Map<RecipientChannel, UUID> recipients, UUID userId) {
        if (userId == null) {
            return;
        }
        recipients.putIfAbsent(new RecipientChannel(userId, NotificationChannel.IN_APP), userId);
        recipients.putIfAbsent(new RecipientChannel(userId, NotificationChannel.EMAIL), userId);
    }

    private boolean isBroadcastType(IncidentLifecycleEventType type) {
        return switch (type) {
            case INCIDENT_CREATED, SEVERITY_CHANGED, ESCALATED, SLA_BREACHED, SLA_AT_RISK -> true;
            case STATUS_CHANGED, ASSIGNED -> false;
        };
    }

    private record RecipientChannel(UUID recipientId, NotificationChannel channel) {
    }
}
