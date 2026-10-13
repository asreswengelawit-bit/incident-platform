package com.company.incidentplatform.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.reset;

import com.company.incidentplatform.incident.ChangeStatusRequest;
import com.company.incidentplatform.incident.IncidentEntity;
import com.company.incidentplatform.incident.IncidentRepository;
import com.company.incidentplatform.incident.IncidentService;
import com.company.incidentplatform.incident.IncidentStatus;
import com.company.incidentplatform.incident.IncidentSeverity;
import com.company.incidentplatform.error.ResourceNotFoundException;
import com.company.incidentplatform.security.PlatformRole;
import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.security.RolePermissions;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.mail.internet.MimeMessage;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.kafka.KafkaContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.containers.wait.strategy.Wait;

/**
 * Exercises a persisted status change through the real Kafka consumer and SMTP
 * relay, then checks the message in Mailpit's inbox.
 */
@Tag("integration")
@Testcontainers
@AutoConfigureMockMvc(addFilters = false)
@SpringBootTest(properties = {
        "spring.jpa.hibernate.ddl-auto=none",
        "incident-platform.user-state-cache-ttl=0s",
        "incident-platform.identity.dormancy.enabled=false",
        "incident-platform.notifications.kafka.enabled=true",
        "incident-platform.notifications.kafka.group-id=smtp-notification-it",
        "incident-platform.notifications.email.enabled=true",
        "incident-platform.notifications.email.from=no-reply@example.test"
})
class SmtpNotificationIntegrationTest {

    private UUID reporterId;
    private UUID analystId;
    private UUID incidentId;
    private String analystEmail;
    private String testSuffix;

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine")
            .withDatabaseName("incident_platform")
            .withUsername("postgres")
            .withPassword("postgres")
            .withInitScript("db/test/01-create-runtime-role.sql");

    @Container
    @SuppressWarnings("resource")
    static final KafkaContainer KAFKA = new KafkaContainer(
            DockerImageName.parse("apache/kafka-native:3.9.1"));

    @Container
    @SuppressWarnings("resource")
    static final GenericContainer<?> MAILPIT = new GenericContainer<>(
            DockerImageName.parse("axllent/mailpit:v1.31.4"))
            .withExposedPorts(1025, 8025)
            .waitingFor(Wait.forHttp("/").forPort(8025).forStatusCode(200))
            .withStartupTimeout(Duration.ofMinutes(2));

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",
                () -> POSTGRES.getJdbcUrl()
                        + (POSTGRES.getJdbcUrl().contains("?") ? "&" : "?")
                        + "currentSchema=incident_platform");
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.kafka.bootstrap-servers", KAFKA::getBootstrapServers);
        registry.add("spring.mail.host", MAILPIT::getHost);
        registry.add("spring.mail.port", () -> MAILPIT.getMappedPort(1025));
    }

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private IncidentService incidentService;

    @Autowired
    private IncidentRepository incidentRepository;

    @Autowired
    private NotificationOutboxService outboxService;

    @Autowired
    private IncidentSlaBreachScheduler slaBreachScheduler;

    @Autowired
    private NotificationRuleAdminService notificationRuleAdminService;

    @Autowired
    private MockMvc mockMvc;

    @MockitoSpyBean
    private JavaMailSender mailSender;

    @Autowired
    private KafkaTemplate<String, Object> kafkaTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${incident-platform.notifications.kafka.topic:incident.lifecycle.events}")
    private String topic;

    @BeforeEach
    void seedIncident() throws Exception {
        reset(mailSender);
        reporterId = UUID.randomUUID();
        analystId = UUID.randomUUID();
        incidentId = UUID.randomUUID();
        testSuffix = UUID.randomUUID().toString().substring(0, 8);
        analystEmail = "analyst-" + testSuffix + "@example.test";
        jdbc.update("UPDATE incident_platform.app_user SET active = false, disabled_at = now(), "
                + "disabled_reason = 'integration-test-reset' WHERE active = true");
        clearMailpit();
        insertUser(reporterId, "smtp-it-reporter-" + testSuffix, "REPORTER",
                "reporter-" + testSuffix + "@example.test");
        insertUser(analystId, "smtp-it-analyst-" + testSuffix, "ANALYST", analystEmail);
        jdbc.update(
                """
                INSERT INTO incident_platform.incident
                    (id, title, description, category_id, reporter_id, assignee_id,
                     severity, status, occurred_at, affected_department)
                VALUES (?, ?, ?, (SELECT id FROM incident_platform.incident_category LIMIT 1),
                        ?, ?, 'HIGH'::incident_platform.incident_severity,
                        'ASSIGNED'::incident_platform.incident_status, now(), 'smtp integration')
                """,
                incidentId,
                "SMTP integration status change",
                "Incident used to verify SMTP delivery",
                reporterId,
                analystId);
    }

    @Test
    @DisplayName("a real incident status change reaches the assigned analyst's Mailpit inbox")
    void deliversStatusChangeEmailThroughKafkaAndSmtp() throws Exception {
        PlatformUser analyst = platformUser(analystId, analystEmail, "ANALYST");
        incidentService.changeStatus(
                incidentId,
                new ChangeStatusRequest(IncidentStatus.INVESTIGATING, null, null, null, null, null, null),
                analyst);

        String inbox = awaitInboxMessage(analystEmail);

        assertThat(inbox)
                .contains(analystEmail)
                .contains("[Incident Platform] status changed")
                .contains("Incident ID:")
                .contains("Severity: HIGH")
                .contains("Category:")
                .contains("Link:")
                .doesNotContain("SMTP integration status change", "Incident used to verify");
        awaitDeliveryStatus(incidentId, analystId, NotificationDeliveryStatus.SENT.name());
        assertThat(jdbc.queryForObject(
                        "SELECT status::text FROM incident_platform.incident WHERE id = ?",
                        String.class,
                        incidentId))
                .isEqualTo("INVESTIGATING");
        assertThat(jdbc.queryForObject(
                        "SELECT delivery_status FROM incident_platform.notification "
                                + "WHERE incident_id = ? AND recipient_user_id = ? AND channel = 'EMAIL'",
                        String.class,
                        incidentId,
                        analystId))
                .isEqualTo(NotificationDeliveryStatus.SENT.name());
        assertThat(jdbc.queryForObject(
                        "SELECT status FROM incident_platform.notification_outbox WHERE incident_id = ?",
                        String.class,
                        incidentId))
                .isEqualTo(NotificationOutboxStatus.PUBLISHED.name());
    }

    @Test
    @DisplayName("all broadcast event types reach a real Mailpit inbox through Kafka")
    void deliversEachBroadcastEventTypeThroughKafkaAndSmtp() throws Exception {
        String adminEmail = "broadcast-admin-" + testSuffix + "@example.test";
        insertUser(UUID.randomUUID(), "smtp-it-admin-" + testSuffix, "SECURITY_ADMIN", adminEmail);
        jdbc.update("UPDATE incident_platform.incident SET severity = 'CRITICAL'::incident_platform.incident_severity "
                + "WHERE id = ?", incidentId);

        IncidentEntity incident = notificationIncident();
        outboxService.enqueue(IncidentLifecycleEventType.INCIDENT_CREATED, incident, null, incident.getStatus(), null);
        awaitInboxCount(adminEmail, 1);

        incident = notificationIncident();
        outboxService.enqueueSeverityChanged(incident, IncidentSeverity.HIGH, IncidentSeverity.CRITICAL);
        awaitInboxCount(adminEmail, 2);

        incident = notificationIncident();
        outboxService.enqueue(IncidentLifecycleEventType.ESCALATED, incident,
                incident.getStatus(), incident.getStatus(), null);
        awaitInboxCount(adminEmail, 3);

        incident = notificationIncident();
        outboxService.enqueueSlaBreach(incident, SlaType.RESOLUTION);
        awaitInboxCount(adminEmail, 4);

        assertThat(jdbc.queryForList(
                        "SELECT event_type FROM incident_platform.notification_outbox "
                                + "WHERE incident_id = ? AND event_type IN "
                                + "('INCIDENT_CREATED', 'SEVERITY_CHANGED', 'ESCALATED', 'SLA_BREACHED')",
                        String.class,
                        incidentId))
                .containsExactlyInAnyOrder(
                        "INCIDENT_CREATED", "SEVERITY_CHANGED", "ESCALATED", "SLA_BREACHED");
    }

    @Test
    @DisplayName("an unknown department falls back to Security Admin")
    void unknownDepartmentRoutesToAdmin() throws Exception {
        String adminEmail = "unknown-dept-admin-" + testSuffix + "@example.test";
        insertUser(UUID.randomUUID(), "smtp-it-admin-" + testSuffix, "SECURITY_ADMIN", adminEmail);
        jdbc.update("UPDATE incident_platform.incident SET severity = 'CRITICAL'::incident_platform.incident_severity, "
                + "affected_department = 'unrecognized unit' WHERE id = ?", incidentId);

        IncidentEntity incident = notificationIncident();
        outboxService.enqueue(IncidentLifecycleEventType.INCIDENT_CREATED, incident, null, incident.getStatus(), null);

        String inbox = awaitInboxMessage(adminEmail);
        assertThat(inbox).contains(adminEmail).contains("Incident ID:");
    }

    @Test
    @DisplayName("redelivering an already-sent Kafka event does not send another email")
    void redeliveredSentEventIsDeduplicated() throws Exception {
        String adminEmail = "redelivery-admin-" + testSuffix + "@example.test";
        insertUser(UUID.randomUUID(), "smtp-it-admin-" + testSuffix, "SECURITY_ADMIN", adminEmail);
        UUID eventId = outboxService.enqueue(IncidentLifecycleEventType.SLA_BREACHED,
                notificationIncident(), IncidentStatus.ASSIGNED, IncidentStatus.ASSIGNED, null);
        awaitInboxCount(adminEmail, 1);

        String payload = jdbc.queryForObject(
                "SELECT payload FROM incident_platform.notification_outbox WHERE id = ?",
                String.class,
                eventId);
        IncidentLifecycleEvent event = objectMapper.readValue(payload, IncidentLifecycleEvent.class);
        kafkaTemplate.send(topic, event.eventId().toString(), event).get(10, TimeUnit.SECONDS);
        Thread.sleep(2500);

        JsonNode inbox = mailpitMessages();
        assertThat(messageIdsFor(inbox, adminEmail)).hasSize(1);
        assertThat(jdbc.queryForObject(
                        "SELECT count(*) FROM incident_platform.notification_delivery_dedupe "
                                + "WHERE idempotency_key = ? AND channel = 'EMAIL' "
                                + "AND recipient_user_id = (SELECT id FROM incident_platform.app_user WHERE email = ?)",
                        Integer.class,
                        event.idempotencyKey(),
                        adminEmail))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject(
                        "SELECT count(*) FROM incident_platform.notification "
                                + "WHERE event_id = ? AND recipient_user_id = "
                                + "(SELECT id FROM incident_platform.app_user WHERE email = ?) "
                                + "AND channel = 'IN_APP'",
                        Integer.class,
                        event.eventId(),
                        adminEmail))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject(
                        "SELECT count(*) FROM incident_platform.notification_delivery_dedupe "
                                + "WHERE idempotency_key = ? AND channel = 'IN_APP' "
                                + "AND recipient_user_id = (SELECT id FROM incident_platform.app_user WHERE email = ?)",
                        Integer.class,
                        event.idempotencyKey(),
                        adminEmail))
                .isEqualTo(1);
    }

    @Test
    @DisplayName("a post-SMTP crash replays with the same Message-ID and at most one duplicate")
    void retriesAfterSmtpAcceptanceWithStableMessageId() throws Exception {
        String adminEmail = "smtp-crash-admin-" + testSuffix + "@example.test";
        insertUser(UUID.randomUUID(), "smtp-it-admin-" + testSuffix, "SECURITY_ADMIN", adminEmail);
        AtomicBoolean failAfterAccept = new AtomicBoolean();
        doAnswer(invocation -> {
            MimeMessage message = invocation.getArgument(0);
            boolean target = recipients(message).contains(adminEmail);
            Object result = invocation.callRealMethod();
            if (target && failAfterAccept.compareAndSet(false, true)) {
                throw new MailSendException("Simulated consumer crash after SMTP acceptance");
            }
            return result;
        }).when(mailSender).send(any(MimeMessage.class));

        outboxService.enqueue(IncidentLifecycleEventType.SLA_BREACHED,
                notificationIncident(), IncidentStatus.ASSIGNED, IncidentStatus.ASSIGNED, null);

        JsonNode inbox = awaitInboxJsonCount(adminEmail, 2);
        Thread.sleep(2000);
        inbox = mailpitMessages();
        List<String> messageIds = messageIdsFor(inbox, adminEmail);
        assertThat(messageIds).hasSize(2).containsOnly(messageIds.get(0));
        assertThat(failAfterAccept).isTrue();
        assertThat(jdbc.queryForObject(
                        "SELECT delivery_status FROM incident_platform.notification_delivery_dedupe "
                                + "WHERE recipient_user_id = (SELECT id FROM incident_platform.app_user WHERE email = ?) "
                                + "AND channel = 'EMAIL' AND idempotency_key LIKE 'event:%' "
                                + "ORDER BY created_at DESC LIMIT 1",
                        String.class,
                        adminEmail))
                .isEqualTo(DeliveryDedupeStatus.SENT.name());
    }

    @Test
    @DisplayName("a failed five-recipient fan-out resumes without skipping or resending sent recipients")
    void resumesInterruptedFiveRecipientFanout() throws Exception {
        List<String> adminEmails = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            String email = "fanout-" + i + "-" + testSuffix + "@example.test";
            adminEmails.add(email);
            insertUser(UUID.randomUUID(), "smtp-it-fanout-" + i + "-" + testSuffix, "SECURITY_ADMIN", email);
        }
        AtomicInteger acceptedAdmins = new AtomicInteger();
        AtomicBoolean failOnce = new AtomicBoolean();
        doAnswer(invocation -> {
            MimeMessage message = invocation.getArgument(0);
            boolean target = recipients(message).stream().anyMatch(adminEmails::contains);
            if (target && acceptedAdmins.getAndIncrement() == 1 && failOnce.compareAndSet(false, true)) {
                throw new MailSendException("Simulated consumer crash during recipient fan-out");
            }
            return invocation.callRealMethod();
        }).when(mailSender).send(any(MimeMessage.class));

        outboxService.enqueue(IncidentLifecycleEventType.SLA_BREACHED,
                notificationIncident(), IncidentStatus.ASSIGNED, IncidentStatus.ASSIGNED, null);

        for (String email : adminEmails) {
            awaitInboxCount(email, 1);
        }
        Thread.sleep(2000);
        JsonNode inbox = mailpitMessages();
        for (String email : adminEmails) {
            assertThat(messageIdsFor(inbox, email)).hasSize(1);
        }
        assertThat(failOnce).isTrue();
    }

    @Test
    @DisplayName("response/resolution SLA breach emits again after a reopen cycle")
    void slaBreachCanBeEmittedAgainAfterReopen() throws Exception {
        String adminEmail = "sla-admin-" + testSuffix + "@example.test";
        insertUser(UUID.randomUUID(), "smtp-it-admin-" + testSuffix, "SECURITY_ADMIN", adminEmail);
        PlatformUser analyst = platformUser(analystId, analystEmail, "ANALYST");
        jdbc.update("UPDATE incident_platform.incident SET status = 'INVESTIGATING'::incident_platform.incident_status, "
                + "sla_due_at = now() - interval '1 second' WHERE id = ?", incidentId);

        slaBreachScheduler.emitBreaches();
        awaitInboxCount(adminEmail, 1);
        jdbc.update("UPDATE incident_platform.incident SET status = 'RESOLVED'::incident_platform.incident_status, "
                + "resolved_at = now(), resolved_by = assignee_id, resolution_summary = 'test resolution' "
                + "WHERE id = ?", incidentId);
        slaBreachScheduler.emitBreaches();
        assertThat(jdbc.queryForObject(
                        "SELECT count(*) FROM incident_platform.notification_outbox "
                                + "WHERE incident_id = ? AND event_type = 'SLA_BREACHED'",
                        Integer.class,
                        incidentId))
                .isEqualTo(1);

        incidentService.changeStatus(
                incidentId,
                new ChangeStatusRequest(IncidentStatus.REOPENED, null, null, null, null,
                        "The incident recurred", null),
                analyst);
        incidentService.changeStatus(
                incidentId,
                new ChangeStatusRequest(IncidentStatus.INVESTIGATING, null, null, null, null, null, null),
                analyst);
        assertThat(jdbc.queryForObject(
                        "SELECT sla_cycle FROM incident_platform.incident WHERE id = ?",
                        Integer.class,
                        incidentId))
                .isEqualTo(1);
        slaBreachScheduler.emitBreaches();
        awaitInboxCount(adminEmail, 2);

        assertThat(jdbc.queryForObject(
                        "SELECT count(DISTINCT idempotency_key) FROM incident_platform.notification_outbox "
                                + "WHERE incident_id = ? AND event_type = 'SLA_BREACHED'",
                        Integer.class,
                        incidentId))
                .isEqualTo(2);
    }

    @Test
    @DisplayName("the SLA scheduler publishes response breaches as well as resolution breaches")
    void responseSlaSchedulerPublishesBreach() throws Exception {
        String adminEmail = "response-sla-admin-" + testSuffix + "@example.test";
        insertUser(UUID.randomUUID(), "smtp-it-admin-" + testSuffix, "SECURITY_ADMIN", adminEmail);
        jdbc.update("UPDATE incident_platform.incident SET status = 'ASSIGNED'::incident_platform.incident_status, "
                + "sla_response_due_at = now() - interval '1 second', sla_due_at = NULL WHERE id = ?",
                incidentId);

        slaBreachScheduler.emitBreaches();
        awaitInboxCount(adminEmail, 1);

        String payload = jdbc.queryForObject(
                "SELECT payload FROM incident_platform.notification_outbox "
                        + "WHERE incident_id = ? AND event_type = 'SLA_BREACHED'",
                String.class,
                incidentId);
        assertThat(objectMapper.readTree(payload).path("slaType").asText()).isEqualTo("RESPONSE");
    }

    @Test
    @DisplayName("real database notification rule CRUD enforces roles, versions, soft delete, and audit")
    void notificationRuleAdminCrud() throws Exception {
        UUID adminId = UUID.randomUUID();
        String adminEmail = "notification-rule-admin-" + testSuffix + "@example.test";
        insertUser(adminId, "notification-rule-admin-" + testSuffix, "SECURITY_ADMIN", adminEmail);
        PlatformUser admin = platformUser(adminId, adminEmail, "SECURITY_ADMIN");
        NotificationRuleAdminService.RuleCommand command = new NotificationRuleAdminService.RuleCommand(
                IncidentLifecycleEventType.INCIDENT_CREATED,
                IncidentSeverity.CRITICAL,
                null,
                NotificationChannel.EMAIL,
                PlatformRole.SECURITY_ADMIN,
                true);

        for (PlatformRole role : List.of(
                PlatformRole.ANALYST,
                PlatformRole.SECURITY_LEAD,
                PlatformRole.REPORTER,
                PlatformRole.AUDITOR)) {
            PlatformUser forbidden = platformUser(UUID.randomUUID(), role.name().toLowerCase() + "@example.test",
                    role.name());
            assertThatThrownBy(() -> notificationRuleAdminService.create(command, forbidden))
                    .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        }
        assertThat(notificationRuleAdminService.list(
                        0, 10000, false, platformUser(UUID.randomUUID(), "auditor@example.test", "AUDITOR"))
                .pageSize()).isEqualTo(100);

        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken(admin, null, "ROLE_SECURITY_ADMIN"));
        UUID ruleId;
        int createdVersion;
        try {
            String createdJson = mockMvc.perform(post("/api/v1/admin/notification-rules")
                            .contentType("application/json")
                            .content(objectMapper.writeValueAsString(command)))
                    .andExpect(status().isCreated())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();
            JsonNode created = objectMapper.readTree(createdJson).path("rule");
            ruleId = UUID.fromString(created.path("id").asText());
            createdVersion = created.path("version").asInt();
            assertThat(UUID.fromString(created.path("createdBy").asText())).isEqualTo(adminId);
            mockMvc.perform(put("/api/v1/admin/notification-rules/{id}?expectedVersion={version}",
                            ruleId, createdVersion + 1)
                            .contentType("application/json")
                            .content(objectMapper.writeValueAsString(command)))
                    .andExpect(status().isConflict());
        } finally {
            SecurityContextHolder.clearContext();
        }

        NotificationRuleAdminService.RuleMutation updated = notificationRuleAdminService.update(
                ruleId,
                createdVersion,
                new NotificationRuleAdminService.RuleCommand(
                        command.eventType(),
                        command.minSeverity(),
                        command.categoryId(),
                        command.channel(),
                        command.recipientRole(),
                        false),
                admin);
        assertThat(updated.rule().updatedBy()).isEqualTo(adminId);
        assertThat(updated.rule().version()).isEqualTo(createdVersion + 1);

        NotificationRuleAdminService.RuleMutation deleted =
                notificationRuleAdminService.delete(ruleId, updated.rule().version(), admin);
        assertThat(deleted.rule().deletedAt()).isNotNull();
        assertThat(deleted.rule().deletedBy()).isEqualTo(adminId);
        assertThat(notificationRuleAdminService.get(ruleId, true, admin).deletedAt()).isNotNull();
        assertThatThrownBy(() -> notificationRuleAdminService.get(ruleId, false, admin))
                .isInstanceOf(ResourceNotFoundException.class);
        assertThat(jdbc.queryForObject(
                        "SELECT count(*) FROM incident_platform.audit_log "
                                + "WHERE entity_type = 'notification_rule' AND entity_id = ?",
                        Long.class,
                        ruleId))
                .isEqualTo(3L);
    }

    private void insertUser(UUID id, String subject, String role, String email) {
        jdbc.update(
                """
                INSERT INTO incident_platform.app_user
                    (id, keycloak_subject, full_name, email, role_id, department, active)
                VALUES (?, ?, ?, ?, (SELECT id FROM incident_platform.platform_role
                                     WHERE name = ?::incident_platform.platform_coarse_role), ?, true)
                """,
                id,
                subject,
                subject,
                email,
                role,
                "SMTP Integration");
    }

    private PlatformUser platformUser(UUID id, String email, String role) throws Exception {
        String permissionsJson = jdbc.queryForObject(
                "SELECT permissions::text FROM incident_platform.platform_role "
                        + "WHERE name = ?::incident_platform.platform_coarse_role",
                String.class,
                role);
        return new PlatformUser(
                id,
                "smtp-it-analyst",
                email,
                "SMTP Integration Analyst",
                "SMTP Integration",
                PlatformRole.valueOf(role),
                RolePermissions.fromJson(objectMapper.readTree(permissionsJson)),
                true,
                true);
    }

    private IncidentEntity notificationIncident() {
        return incidentRepository.findNotificationSnapshot(incidentId).orElseThrow();
    }

    private void clearMailpit() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(mailpitUri()).DELETE().build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isBetween(200, 299);
    }

    private void awaitInboxCount(String recipient, int count) throws Exception {
        awaitInboxJsonCount(recipient, count);
    }

    private void awaitDeliveryStatus(UUID incident, UUID recipient, String expected) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        String observed = null;
        while (System.nanoTime() < deadline) {
            observed = jdbc.query(
                    "SELECT delivery_status FROM incident_platform.notification "
                            + "WHERE incident_id = ? AND recipient_user_id = ? AND channel = 'EMAIL' "
                            + "ORDER BY created_at DESC LIMIT 1",
                    rs -> rs.next() ? rs.getString(1) : null,
                    incident,
                    recipient);
            if (expected.equals(observed)) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("Expected notification status " + expected + " but observed " + observed);
    }

    private JsonNode awaitInboxJsonCount(String recipient, int count) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(90).toNanos();
        JsonNode lastResponse = objectMapper.createObjectNode();
        while (System.nanoTime() < deadline) {
            lastResponse = mailpitMessages();
            if (messageIdsFor(lastResponse, recipient).size() >= count) {
                return lastResponse;
            }
            Thread.sleep(500);
        }
        throw new AssertionError("Expected " + count + " Mailpit messages for " + recipient
                + "; last inbox response was " + lastResponse);
    }

    private JsonNode mailpitMessages() throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(mailpitUri()).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        return objectMapper.readTree(response.body());
    }

    private URI mailpitUri() {
        return URI.create("http://" + MAILPIT.getHost() + ":" + MAILPIT.getMappedPort(8025) + "/api/v1/messages");
    }

    private List<String> recipients(MimeMessage message) throws Exception {
        if (message.getAllRecipients() == null) {
            return List.of();
        }
        return java.util.Arrays.stream(message.getAllRecipients())
                .map(Object::toString)
                .toList();
    }

    private List<String> messageIdsFor(JsonNode inbox, String recipient) {
        List<String> ids = new ArrayList<>();
        for (JsonNode message : inbox.path("messages")) {
            boolean addressed = false;
            for (JsonNode to : message.path("To")) {
                if (recipient.equalsIgnoreCase(to.path("Address").asText())) {
                    addressed = true;
                    break;
                }
            }
            if (addressed) {
                ids.add(message.path("MessageID").asText());
            }
        }
        return ids;
    }

    private String awaitInboxMessage(String recipient) throws Exception {
        URI inboxUri = URI.create(
                "http://" + MAILPIT.getHost() + ":" + MAILPIT.getMappedPort(8025) + "/api/v1/messages");
        HttpClient client = HttpClient.newHttpClient();
        long deadline = System.nanoTime() + Duration.ofSeconds(45).toNanos();
        String lastResponse = "";
        while (System.nanoTime() < deadline) {
            HttpResponse<String> response = client.send(
                    HttpRequest.newBuilder(inboxUri).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).isEqualTo(200);
            lastResponse = response.body();
            if (lastResponse.contains(recipient)) {
                return lastResponse;
            }
            Thread.sleep(500);
        }
        throw new AssertionError("No email for " + recipient + " arrived in Mailpit; last inbox response: "
                + lastResponse);
    }
}
