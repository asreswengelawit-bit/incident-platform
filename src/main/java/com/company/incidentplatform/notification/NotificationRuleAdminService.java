package com.company.incidentplatform.notification;

import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.audit.AuditLogQuery;
import com.company.incidentplatform.audit.RequestContext;
import com.company.incidentplatform.authorization.AuthorizationDeniedException;
import com.company.incidentplatform.authorization.Capability;
import com.company.incidentplatform.error.ConflictException;
import com.company.incidentplatform.error.ResourceNotFoundException;
import com.company.incidentplatform.incident.IncidentSeverity;
import com.company.incidentplatform.incident.PagedResponse;
import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.PlatformRole;
import com.company.incidentplatform.security.PlatformUser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class NotificationRuleAdminService {

    private final NotificationRuleRepository rules;
    private final JdbcTemplate jdbc;
    private final AuditService audit;
    private final CriticalNotificationRuleCoverage coverage;
    private final EntityManager entityManager;
    private final ObjectMapper json;

    public NotificationRuleAdminService(
            NotificationRuleRepository rules,
            JdbcTemplate jdbc,
            AuditService audit,
            CriticalNotificationRuleCoverage coverage,
            EntityManager entityManager,
            ObjectMapper json) {
        this.rules = rules;
        this.jdbc = jdbc;
        this.audit = audit;
        this.coverage = coverage;
        this.entityManager = entityManager;
        this.json = json;
    }

    @Transactional(readOnly = true)
    public PagedResponse<NotificationRuleView> list(
            int page, int pageSize, boolean includeDeleted, PlatformUser caller) {
        requireRead(caller);
        int safePage = Math.max(0, page);
        int safePageSize = AuditLogQuery.clampPageSize(pageSize);
        Page<NotificationRuleEntity> result = includeDeleted
                ? rules.findAll(PageRequest.of(safePage, safePageSize, Sort.by(Sort.Direction.DESC, "createdAt")))
                : rules.findByDeletedAtIsNull(
                        PageRequest.of(safePage, safePageSize, Sort.by(Sort.Direction.DESC, "createdAt")));
        return PagedResponse.of(
                result.getContent().stream().map(NotificationRuleView::from).toList(),
                result.getNumber(),
                result.getSize(),
                result.getTotalElements());
    }

    @Transactional(readOnly = true)
    public NotificationRuleView get(UUID id, boolean includeDeleted, PlatformUser caller) {
        requireRead(caller);
        NotificationRuleEntity rule = rules.findById(id)
                .filter(row -> includeDeleted || row.getDeletedAt() == null)
                .orElseThrow(() -> new ResourceNotFoundException("notification_rule", id));
        return NotificationRuleView.from(rule);
    }

    @Transactional
    public RuleMutation create(RuleCommand command, PlatformUser caller) {
        requireWrite(caller, null);
        validate(command);
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        NotificationRuleEntity rule = new NotificationRuleEntity(
                UUID.randomUUID(),
                command.eventType(),
                command.minSeverity(),
                command.categoryId(),
                command.channel(),
                command.recipientRole(),
                enabledValue(command),
                caller.id(),
                now);
        rules.saveAndFlush(rule);
        NotificationRuleView after = NotificationRuleView.from(rule);
        audit(caller, rule.getId(), "admin.notification_rule.create", null, after);
        return new RuleMutation(after, coverage.warningIfUncovered());
    }

    @Transactional
    public RuleMutation update(
            UUID id, int expectedVersion, RuleCommand command, PlatformUser caller) {
        requireWrite(caller, id);
        validate(command);
        NotificationRuleEntity rule = findActive(id);
        if (!Integer.valueOf(expectedVersion).equals(rule.getVersion())) {
            throw staleVersion();
        }
        NotificationRuleView before = NotificationRuleView.from(rule);
        rule.update(
                command.eventType(),
                command.minSeverity(),
                command.categoryId(),
                command.channel(),
                command.recipientRole(),
                enabledValue(command),
                caller.id(),
                OffsetDateTime.now(ZoneOffset.UTC));
        try {
            rules.saveAndFlush(rule);
        } catch (OptimisticLockingFailureException conflict) {
            throw staleVersion();
        }
        entityManager.refresh(rule);
        NotificationRuleView after = NotificationRuleView.from(rule);
        String warning = coverage.warningIfUncovered();
        audit(caller, id, "admin.notification_rule.update", before, withWarning(after, warning));
        return new RuleMutation(after, warning);
    }

    @Transactional
    public RuleMutation delete(UUID id, int expectedVersion, PlatformUser caller) {
        requireWrite(caller, id);
        NotificationRuleEntity rule = findActive(id);
        if (!Integer.valueOf(expectedVersion).equals(rule.getVersion())) {
            throw staleVersion();
        }
        NotificationRuleView before = NotificationRuleView.from(rule);
        rule.softDelete(caller.id(), OffsetDateTime.now(ZoneOffset.UTC));
        try {
            rules.saveAndFlush(rule);
        } catch (OptimisticLockingFailureException conflict) {
            throw staleVersion();
        }
        entityManager.refresh(rule);
        NotificationRuleView after = NotificationRuleView.from(rule);
        String warning = coverage.warningIfUncovered();
        audit(caller, id, "admin.notification_rule.delete", before, withWarning(after, warning));
        return new RuleMutation(after, warning);
    }

    private NotificationRuleEntity findActive(UUID id) {
        return rules.findByIdAndDeletedAtIsNull(id)
                .orElseThrow(() -> new ResourceNotFoundException("notification_rule", id));
    }

    private void validate(RuleCommand command) {
        if (command.eventType() == IncidentLifecycleEventType.SEVERITY_CHANGED
                && command.minSeverity() == null) {
            throw new IllegalArgumentException("minSeverity is required for SEVERITY_CHANGED rules");
        }
        if (command.categoryId() != null) {
            Boolean exists = jdbc.queryForObject(
                    "SELECT EXISTS (SELECT 1 FROM incident_platform.incident_category WHERE id = ?)",
                    Boolean.class,
                    command.categoryId());
            if (!Boolean.TRUE.equals(exists)) {
                throw new ResourceNotFoundException("incident_category", command.categoryId());
            }
        }
        if (command.recipientRole() != PlatformRole.SECURITY_LEAD
                && command.recipientRole() != PlatformRole.SECURITY_ADMIN) {
            throw new IllegalArgumentException(
                    "recipientRole must be SECURITY_LEAD or SECURITY_ADMIN");
        }
    }

    private boolean enabledValue(RuleCommand command) {
        return command.enabled() == null || command.enabled();
    }

    private void requireRead(PlatformUser caller) {
        if (caller.role() != PlatformRole.SECURITY_ADMIN && caller.role() != PlatformRole.AUDITOR) {
            throw AuthorizationDeniedException.forMissingCapability(
                    Capability.MANAGE_NOTIFICATION_RULES, "notification_rule", null);
        }
    }

    private void requireWrite(PlatformUser caller, UUID id) {
        if (caller.permissions().isReadOnly()) {
            throw AuthorizationDeniedException.forReadOnlyRole("notification_rule", id);
        }
        if (caller.role() != PlatformRole.SECURITY_ADMIN
                || !Capability.MANAGE_NOTIFICATION_RULES.isHeldBy(caller.permissions())) {
            throw AuthorizationDeniedException.forMissingCapability(
                    Capability.MANAGE_NOTIFICATION_RULES, "notification_rule", id);
        }
    }

    private void audit(
            PlatformUser caller, UUID id, String action, Object before, Object after) {
        audit.recordChange(
                caller,
                "notification_rule",
                id,
                action,
                RequestContext.endpoint(),
                RequestContext.method(),
                RequestContext.requestId().orElse(null),
                RequestContext.remoteAddress(),
                AuthorizationCheckType.FUNCTION_LEVEL,
                Capability.MANAGE_NOTIFICATION_RULES.rule(),
                serialize(before),
                serialize(after),
                false);
    }

    private String serialize(Object value) {
        if (value == null) {
            return null;
        }
        try {
            return json.writeValueAsString(value);
        } catch (JsonProcessingException failure) {
            throw new IllegalStateException("Could not serialize notification rule audit values", failure);
        }
    }

    private Object withWarning(NotificationRuleView view, String warning) {
        if (warning == null) {
            return view;
        }
        return Map.of("rule", view, "warning", warning);
    }

    private ConflictException staleVersion() {
        return new ConflictException("Notification rule changed since it was read; reload and reapply the change");
    }

    public record RuleCommand(
            @jakarta.validation.constraints.NotNull IncidentLifecycleEventType eventType,
            IncidentSeverity minSeverity,
            UUID categoryId,
            @jakarta.validation.constraints.NotNull NotificationChannel channel,
            @jakarta.validation.constraints.NotNull PlatformRole recipientRole,
            Boolean enabled) {
    }

    public record RuleMutation(NotificationRuleView rule, String warning) {
    }
}
