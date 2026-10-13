package com.company.incidentplatform.evidence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.company.incidentplatform.error.EvidenceRejectedException;
import com.company.incidentplatform.security.PlatformRole;
import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.security.RolePermissions;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Runs the real evidence upload path against PostgreSQL and clamd containers.
 */
@Tag("integration")
@Testcontainers
@SpringBootTest(properties = {
        "spring.jpa.hibernate.ddl-auto=none",
        "incident-platform.user-state-cache-ttl=0s",
        "incident-platform.identity.dormancy.enabled=false",
        "incident-platform.evidence.scanner=clamav"
})
class ClamAvEvidenceUploadIntegrationTest {

    private static final String EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
            + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    private static final UUID REPORTER_ID = UUID.randomUUID();
    private static final UUID INCIDENT_ID = UUID.randomUUID();
    private static final Path STORAGE_ROOT = Path.of(
            System.getProperty("java.io.tmpdir"),
            "incident-platform-clamav-it-" + UUID.randomUUID());

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine")
            .withDatabaseName("incident_platform")
            .withUsername("postgres")
            .withPassword("postgres")
            .withInitScript("db/test/01-create-runtime-role.sql");

    @Container
    @SuppressWarnings("resource")
    static final GenericContainer<?> CLAMAV = new GenericContainer<>(DockerImageName.parse("clamav/clamav:1.4.3"))
            .withExposedPorts(3310)
            .withStartupTimeout(Duration.ofMinutes(5));

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",
                () -> POSTGRES.getJdbcUrl()
                        + (POSTGRES.getJdbcUrl().contains("?") ? "&" : "?")
                        + "currentSchema=incident_platform");
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("incident-platform.evidence.clamav.host", CLAMAV::getHost);
        registry.add("incident-platform.evidence.clamav.port", () -> CLAMAV.getMappedPort(3310));
        registry.add("incident-platform.evidence.storage-root", STORAGE_ROOT::toString);
    }

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @Autowired
    private EvidenceService evidenceService;

    @Autowired
    private EvidenceScanner scanner;

    @Autowired
    private EvidenceStorage storage;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void seedReporterAndIncident() {
        jdbc.update(
                "INSERT INTO incident_platform.app_user "
                        + "(id, keycloak_subject, full_name, email, role_id) "
                        + "VALUES (?, ?, ?, ?, (SELECT id FROM incident_platform.platform_role "
                        + "WHERE name = 'REPORTER'))",
                REPORTER_ID,
                "clamav-it-" + REPORTER_ID,
                "ClamAV integration reporter",
                "clamav-it-" + REPORTER_ID + "@example.test");
        jdbc.update(
                "INSERT INTO incident_platform.incident "
                        + "(id, title, description, category_id, reporter_id, occurred_at) "
                        + "VALUES (?, ?, ?, (SELECT id FROM incident_platform.incident_category LIMIT 1), ?, now())",
                INCIDENT_ID,
                "ClamAV integration upload",
                "Test incident for real antivirus upload verification",
                REPORTER_ID);
    }

    @AfterAll
    static void removeTemporaryEvidence() throws IOException {
        if (Files.exists(STORAGE_ROOT)) {
            try (var paths = Files.walk(STORAGE_ROOT)) {
                paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    } catch (IOException failure) {
                        throw new UncheckedIOException(failure);
                    }
                });
            } catch (UncheckedIOException failure) {
                throw failure.getCause();
            }
        }
    }

    @Test
    @DisplayName("real EICAR upload is quarantined by clamd and cannot be downloaded")
    void quarantinesEicarOnUpload() throws Exception {
        awaitClamAvDatabase();

        String roleJson = jdbc.queryForObject(
                "SELECT permissions::text FROM incident_platform.platform_role WHERE name = 'REPORTER'",
                String.class);
        PlatformUser reporter = new PlatformUser(
                REPORTER_ID,
                "clamav-it-" + REPORTER_ID,
                "clamav-it-" + REPORTER_ID + "@example.test",
                "ClamAV integration reporter",
                null,
                PlatformRole.REPORTER,
                RolePermissions.fromJson(objectMapper.readTree(roleJson)),
                true,
                true);
        MockMultipartFile eicar = new MockMultipartFile(
                "file",
                "eicar.txt",
                "text/plain",
                EICAR.getBytes(StandardCharsets.US_ASCII));

        EvidenceViews.EvidenceView uploaded = evidenceService.upload(INCIDENT_ID, eicar, null, reporter);

        assertThat(uploaded.scanStatus()).isEqualTo(EvidenceScanStatus.QUARANTINED);
        assertThat(uploaded.downloadable()).isFalse();
        assertThat(uploaded.scannerEngine()).isEqualTo("clamd");
        assertThat(uploaded.quarantineReason()).containsIgnoringCase("Eicar");

        String signature = jdbc.queryForObject(
                "SELECT scanner_signature FROM incident_platform.incident_evidence WHERE id = ?",
                String.class,
                uploaded.id());
        assertThat(signature).isNotBlank().containsIgnoringCase("Eicar");

        assertThatThrownBy(() -> evidenceService.download(INCIDENT_ID, uploaded.id(), reporter))
                .isInstanceOf(EvidenceRejectedException.class)
                .hasMessageContaining("quarantined");
    }

    private void awaitClamAvDatabase() throws IOException, InterruptedException {
        String readinessKey = "clamav-readiness/" + UUID.randomUUID();
        byte[] eicar = EICAR.getBytes(StandardCharsets.US_ASCII);
        storage.store(readinessKey, new ByteArrayInputStream(eicar), eicar.length);
        try {
            long deadline = System.nanoTime() + Duration.ofMinutes(4).toNanos();
            EvidenceScanner.Verdict lastVerdict = null;
            while (System.nanoTime() < deadline) {
                lastVerdict = scanner.scan("eicar-readiness.txt", readinessKey, "text/plain");
                if (lastVerdict.status() == EvidenceScanner.Verdict.Status.QUARANTINED) {
                    return;
                }
                if (lastVerdict.status() == EvidenceScanner.Verdict.Status.CLEAN) {
                    throw new AssertionError("ClamAV returned CLEAN for the EICAR readiness probe");
                }
                Thread.sleep(1000);
            }
            throw new AssertionError("ClamAV did not load signatures in time; last verdict: " + lastVerdict);
        } finally {
            storage.deleteForRetention(readinessKey, "Remove temporary ClamAV readiness probe");
        }
    }
}
