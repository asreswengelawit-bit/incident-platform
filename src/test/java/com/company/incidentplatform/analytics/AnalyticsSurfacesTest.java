package com.company.incidentplatform.analytics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.authorization.AuthorizationDeniedException;
import com.company.incidentplatform.authorization.IncidentAccessGuard;
import com.company.incidentplatform.authorization.IncidentSnapshotRepository;
import com.company.incidentplatform.security.PlatformRole;
import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.security.RolePermissions;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;

class AnalyticsSurfacesTest {

    @Test
    void csvEscapesSpreadsheetFormulasAndContainsNoReporterIdentityColumns() {
        AnalyticsIncident incident = incident("=HYPERLINK(\"https://example.invalid\")", true);

        String csv = new String(AnalyticsCsvWriter.write(List.of(incident)), java.nio.charset.StandardCharsets.UTF_8);

        assertTrue(csv.startsWith("id,title,description,category,severity,status,"));
        assertFalse(csv.toLowerCase().contains("reporter"));
        assertFalse(csv.contains("Finance"));
        assertTrue(csv.contains("\"'=HYPERLINK(\"\"https://example.invalid\"\")\""));
    }

    @Test
    void pdfIsAValidPdfEnvelopeAndDoesNotContainReporterIdentity() {
        String pdf = new String(AnalyticsPdfWriter.write(incident("Example incident", true)), java.nio.charset.StandardCharsets.US_ASCII);

        assertTrue(pdf.startsWith("%PDF-1.4"));
        assertTrue(pdf.contains("xref"));
        assertTrue(pdf.contains("Example incident"));
        assertFalse(pdf.contains("reporter@example.invalid"));
        assertFalse(pdf.contains("Finance"));
    }

    @Test
    void filterRejectsInvertedDateRangeAndNormalizesDepartment() {
        assertThrows(IllegalArgumentException.class, () -> new AnalyticsFilter(
                null, null, null, null, Instant.parse("2026-02-02T00:00:00Z"), Instant.parse("2026-02-01T00:00:00Z")));

        AnalyticsFilter filter = new AnalyticsFilter(null, null, null, "  Finance  ", null, null);
        assertEquals("Finance", filter.department());
    }

    @Test
    void summaryRejectsRolesOutsideAnalystLeadAndAdminBeforeQuerying() {
        AnalyticsQueryRepository queries = mock(AnalyticsQueryRepository.class);
        IncidentSnapshotRepository snapshots = mock(IncidentSnapshotRepository.class);
        IncidentAccessGuard guard = mock(IncidentAccessGuard.class);
        AuditService audit = mock(AuditService.class);
        AnalyticsService service = new AnalyticsService(queries, snapshots, guard, audit);

        assertThrows(
                AccessDeniedException.class,
                () -> service.summary(new AnalyticsFilter(null, null, null, null, null, null), user(PlatformRole.AUDITOR)));
        verifyNoInteractions(queries, snapshots, guard, audit);
    }

    @Test
    void csvRejectsAnExportLimitAboveFiftyThousandBeforeQuerying() {
        AnalyticsQueryRepository queries = mock(AnalyticsQueryRepository.class);
        IncidentSnapshotRepository snapshots = mock(IncidentSnapshotRepository.class);
        IncidentAccessGuard guard = mock(IncidentAccessGuard.class);
        AuditService audit = mock(AuditService.class);
        AnalyticsService service = new AnalyticsService(queries, snapshots, guard, audit);

        assertThrows(
                IllegalArgumentException.class,
                () -> service.csv(new AnalyticsFilter(null, null, null, null, null, null), 50_001, user(PlatformRole.ANALYST)));
        verifyNoInteractions(queries, snapshots, guard, audit);
    }

    @Test
    void csvRequiresTheExistingExportCapabilityBeforeQuerying() {
        AnalyticsQueryRepository queries = mock(AnalyticsQueryRepository.class);
        IncidentSnapshotRepository snapshots = mock(IncidentSnapshotRepository.class);
        IncidentAccessGuard guard = mock(IncidentAccessGuard.class);
        AuditService audit = mock(AuditService.class);
        AnalyticsService service = new AnalyticsService(queries, snapshots, guard, audit);

        assertThrows(
                AuthorizationDeniedException.class,
                () -> service.csv(new AnalyticsFilter(null, null, null, null, null, null), 1, user(PlatformRole.ANALYST)));
        verifyNoInteractions(queries, snapshots, guard, audit);
    }

    private static AnalyticsIncident incident(String title, boolean anonymous) {
        OffsetDateTime now = OffsetDateTime.parse("2026-01-01T12:00:00Z");
        return new AnalyticsIncident(
                UUID.randomUUID(),
                title,
                "Description",
                "Phishing",
                null,
                com.company.incidentplatform.incident.IncidentStatus.NEW,
                now,
                now,
                null,
                "mail",
                "Finance",
                false,
                anonymous);
    }

    private static PlatformUser user(PlatformRole role) {
        return new PlatformUser(
                UUID.randomUUID(),
                "subject",
                "person@example.invalid",
                "Person",
                "Finance",
                role,
                RolePermissions.fromJson(null),
                true,
                true);
    }
}
