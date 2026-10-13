package com.company.incidentplatform.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.authorization.AuthorizationDeniedException;
import com.company.incidentplatform.error.ConflictException;
import com.company.incidentplatform.incident.IncidentSeverity;
import com.company.incidentplatform.security.PlatformRole;
import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.security.RolePermissions;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.boot.actuate.health.Status;
import org.springframework.test.util.ReflectionTestUtils;

class NotificationRuleAdminServiceTest {

    private NotificationRuleRepository rules;
    private JdbcTemplate jdbc;
    private AuditService audit;
    private EntityManager entityManager;
    private NotificationRuleAdminService service;
    private PlatformUser admin;

    @BeforeEach
    void setUp() throws Exception {
        rules = mock(NotificationRuleRepository.class);
        jdbc = mock(JdbcTemplate.class);
        audit = mock(AuditService.class);
        entityManager = mock(EntityManager.class);
        ObjectMapper mapper = new ObjectMapper();
        mapper.findAndRegisterModules();
        service = new NotificationRuleAdminService(
                rules, jdbc, audit, new CriticalNotificationRuleCoverage(rules), entityManager, mapper);
        admin = user(PlatformRole.SECURITY_ADMIN,
                mapper.readTree("{\"can_manage_notification_rules\":true}"));
    }

    @Test
    void nonAdminRolesCannotWriteRules() throws Exception {
        for (PlatformRole role : List.of(
                PlatformRole.ANALYST,
                PlatformRole.SECURITY_LEAD,
                PlatformRole.REPORTER,
                PlatformRole.AUDITOR)) {
            PlatformUser caller = user(role, new ObjectMapper().readTree(
                    role == PlatformRole.AUDITOR ? "{\"read_only\":true}" : "{}"));

            assertThatThrownBy(() -> service.create(command(), caller))
                    .isInstanceOf(AuthorizationDeniedException.class);
        }
    }

    @Test
    void staleExpectedVersionReturnsConflict() {
        UUID id = UUID.randomUUID();
        NotificationRuleEntity existing = rule(id);
        when(rules.findByIdAndDeletedAtIsNull(id)).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> service.update(id, 2, command(), admin))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void severityChangedRequiresMinimumSeverity() {
        NotificationRuleAdminService.RuleCommand invalid = new NotificationRuleAdminService.RuleCommand(
                IncidentLifecycleEventType.SEVERITY_CHANGED,
                null,
                null,
                NotificationChannel.EMAIL,
                PlatformRole.SECURITY_ADMIN,
                true);

        assertThatThrownBy(() -> service.create(invalid, admin))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("minSeverity is required");
    }

    @Test
    void newRulesDefaultToEnabled() {
        when(rules.saveAndFlush(any(NotificationRuleEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(rules.findByEnabledTrueAndDeletedAtIsNull()).thenReturn(List.of());
        NotificationRuleAdminService.RuleCommand command = new NotificationRuleAdminService.RuleCommand(
                IncidentLifecycleEventType.INCIDENT_CREATED,
                IncidentSeverity.CRITICAL,
                null,
                NotificationChannel.EMAIL,
                PlatformRole.SECURITY_ADMIN,
                null);

        assertThat(service.create(command, admin).rule().enabled()).isTrue();
    }

    @Test
    void disablingLastCriticalCoveringRuleReturnsWarningAndAuditsChange() {
        UUID id = UUID.randomUUID();
        NotificationRuleEntity existing = rule(id);
        when(rules.findByIdAndDeletedAtIsNull(id)).thenReturn(Optional.of(existing));
        when(rules.saveAndFlush(any(NotificationRuleEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(rules.findByEnabledTrueAndDeletedAtIsNull()).thenReturn(List.of());
        doNothing().when(entityManager).refresh(existing);

        NotificationRuleAdminService.RuleMutation result = service.update(
                id,
                0,
                new NotificationRuleAdminService.RuleCommand(
                        IncidentLifecycleEventType.INCIDENT_CREATED,
                        IncidentSeverity.CRITICAL,
                        null,
                        NotificationChannel.EMAIL,
                        PlatformRole.SECURITY_ADMIN,
                        false),
                admin);

        assertThat(result.warning()).isEqualTo(CriticalNotificationRuleCoverage.WARNING);
        assertThat(existing.isEnabled()).isFalse();
        assertThat(new NotificationRuleHealthIndicator(new CriticalNotificationRuleCoverage(rules))
                        .health().getStatus())
                .isEqualTo(Status.DOWN);
        verify(audit).recordChange(
                eq(admin),
                eq("notification_rule"),
                eq(id),
                eq("admin.notification_rule.update"),
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                eq(false));
    }

    private NotificationRuleEntity rule(UUID id) {
        NotificationRuleEntity rule = new NotificationRuleEntity(
                id,
                IncidentLifecycleEventType.INCIDENT_CREATED,
                IncidentSeverity.CRITICAL,
                null,
                NotificationChannel.EMAIL,
                PlatformRole.SECURITY_ADMIN,
                true,
                admin.id(),
                OffsetDateTime.now());
        ReflectionTestUtils.setField(rule, "version", 0);
        return rule;
    }

    private NotificationRuleAdminService.RuleCommand command() {
        return new NotificationRuleAdminService.RuleCommand(
                IncidentLifecycleEventType.INCIDENT_CREATED,
                IncidentSeverity.CRITICAL,
                null,
                NotificationChannel.EMAIL,
                PlatformRole.SECURITY_ADMIN,
                true);
    }

    private PlatformUser user(PlatformRole role, com.fasterxml.jackson.databind.JsonNode permissions) {
        return new PlatformUser(
                UUID.randomUUID(),
                "subject-" + role.name(),
                role.name().toLowerCase() + "@example.test",
                role.name(),
                null,
                role,
                RolePermissions.fromJson(permissions),
                true,
                true);
    }
}
