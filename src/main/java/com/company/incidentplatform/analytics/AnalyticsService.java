package com.company.incidentplatform.analytics;

import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.audit.RequestContext;
import com.company.incidentplatform.authorization.AuthorizationDeniedException;
import com.company.incidentplatform.authorization.AuthorizationDecision;
import com.company.incidentplatform.authorization.Capability;
import com.company.incidentplatform.authorization.IncidentAccessGuard;
import com.company.incidentplatform.authorization.IncidentSnapshotRepository;
import com.company.incidentplatform.authorization.IncidentSnapshot;
import com.company.incidentplatform.authorization.IncidentViewResolver;
import com.company.incidentplatform.error.ResourceNotFoundException;
import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.DeniedReason;
import com.company.incidentplatform.security.PlatformRole;
import com.company.incidentplatform.security.PlatformUser;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Authorization-aware analytics, report and export orchestration. */
@Service
public class AnalyticsService {

    static final int EXPORT_MAX_ROWS = 50_000;
    private static final int BATCH_SIZE = 500;
    private static final String SUMMARY_ENDPOINT = "/api/v1/analytics/summary";
    private static final String CSV_ENDPOINT = "/api/v1/analytics/incidents.csv";
    private static final String PDF_ENDPOINT = "/api/v1/analytics/incidents/{id}/report.pdf";

    private final AnalyticsQueryRepository queries;
    private final IncidentSnapshotRepository snapshots;
    private final IncidentAccessGuard accessGuard;
    private final AuditService auditService;
    private final IncidentViewResolver viewResolver = new IncidentViewResolver();

    public AnalyticsService(
            AnalyticsQueryRepository queries,
            IncidentSnapshotRepository snapshots,
            IncidentAccessGuard accessGuard,
            AuditService auditService) {
        this.queries = queries;
        this.snapshots = snapshots;
        this.accessGuard = accessGuard;
        this.auditService = auditService;
    }

    @Transactional(readOnly = true)
    public AnalyticsSummary summary(AnalyticsFilter filter, PlatformUser caller) {
        requireSummaryRole(caller);
        Map<String, Long> statuses = new LinkedHashMap<>();
        Map<String, Long> severities = new LinkedHashMap<>();
        long total = 0;
        long escalated = 0;
        long anonymous = 0;
        long offset = 0;
        while (true) {
            List<AnalyticsIncident> candidates =
                    queries.findVisibleCandidates(filter, caller, offset, BATCH_SIZE, false);
            if (candidates.isEmpty()) {
                break;
            }
            List<AnalyticsIncident> visible = authorize(candidates, caller);
            for (AnalyticsIncident incident : visible) {
                total++;
                if (incident.escalated()) {
                    escalated++;
                }
                if (incident.anonymous()) {
                    anonymous++;
                }
                statuses.merge(incident.status().name(), 1L, Long::sum);
                severities.merge(incident.severity() == null ? "UNCLASSIFIED" : incident.severity().name(), 1L, Long::sum);
            }
            offset += candidates.size();
            if (candidates.size() < BATCH_SIZE) {
                break;
            }
        }
        recordRead(caller, "analytics.summary", SUMMARY_ENDPOINT, "incident.analytics.scoped_visibility");
        auditAnonymousSuppression(caller, anonymous, SUMMARY_ENDPOINT);
        return new AnalyticsSummary(total, escalated, Map.copyOf(statuses), Map.copyOf(severities));
    }

    @Transactional(readOnly = true)
    public byte[] csv(AnalyticsFilter filter, int maxRows, PlatformUser caller) {
        if (maxRows < 1 || maxRows > EXPORT_MAX_ROWS) {
            throw new IllegalArgumentException("maxRows must be between 1 and " + EXPORT_MAX_ROWS);
        }
        requireExportCapability(caller);
        List<AnalyticsIncident> results = new ArrayList<>(Math.min(maxRows, BATCH_SIZE));
        long anonymous = 0;
        long offset = 0;
        while (results.size() < maxRows) {
            int requested = Math.min(BATCH_SIZE, maxRows - results.size());
            List<AnalyticsIncident> candidates =
                    queries.findVisibleCandidates(filter, caller, offset, requested, true);
            if (candidates.isEmpty()) {
                break;
            }
            List<AnalyticsIncident> visible = authorize(candidates, caller);
            anonymous += visible.stream().filter(AnalyticsIncident::anonymous).count();
            results.addAll(visible);
            offset += candidates.size();
            if (candidates.size() < requested) {
                break;
            }
        }
        if (results.size() > maxRows) {
            results.subList(maxRows, results.size()).clear();
        }
        recordRead(caller, "incident.export.csv", CSV_ENDPOINT, "incident.export.scoped_visibility");
        auditAnonymousSuppression(caller, anonymous, CSV_ENDPOINT);
        return AnalyticsCsvWriter.write(results);
    }

    @Transactional(readOnly = true)
    public byte[] pdf(UUID incidentId, PlatformUser caller) {
        requireExportCapability(caller);
        accessGuard.requireRead(caller, incidentId);
        List<AnalyticsIncident> candidates = queries.findVisibleCandidate(incidentId, caller);
        if (candidates.isEmpty()) {
            throw new ResourceNotFoundException("incident", incidentId);
        }
        AnalyticsIncident incident = authorize(candidates, caller).stream().findFirst()
                .orElseThrow(() -> new ResourceNotFoundException("incident", incidentId));
        recordRead(caller, "incident.report.pdf", PDF_ENDPOINT, "incident.read.analytics_report");
        auditAnonymousSuppression(caller, incident.anonymous() ? 1 : 0, PDF_ENDPOINT);
        return AnalyticsPdfWriter.write(incident);
    }

    private List<AnalyticsIncident> authorize(List<AnalyticsIncident> candidates, PlatformUser caller) {
        Map<UUID, IncidentSnapshot> byId = snapshots.findAllByIds(candidates.stream()
                .map(AnalyticsIncident::id)
                .toList());
        var visibleIds = accessGuard.filterVisible(caller, new ArrayList<>(byId.values())).stream()
                .map(IncidentSnapshot::id)
                .collect(java.util.stream.Collectors.toSet());
        return candidates.stream().filter(row -> visibleIds.contains(row.id())).toList();
    }

    private void requireSummaryRole(PlatformUser caller) {
        if (caller.role() != PlatformRole.ANALYST
                && caller.role() != PlatformRole.SECURITY_LEAD
                && caller.role() != PlatformRole.SECURITY_ADMIN) {
            throw new org.springframework.security.access.AccessDeniedException(
                    "Analytics summary is restricted to Analysts, Security Leads, and Security Admins");
        }
    }

    private void requireExportCapability(PlatformUser caller) {
        if (!Capability.EXPORT.isHeldBy(caller.permissions())) {
            throw AuthorizationDeniedException.forMissingCapability(Capability.EXPORT, "incident", null);
        }
    }

    private void recordRead(PlatformUser caller, String action, String endpoint, String rule) {
        auditService.recordAllowed(
                caller,
                "incident",
                null,
                action,
                endpoint,
                "GET",
                RequestContext.requestId().orElse(UUID.randomUUID()),
                RequestContext.remoteAddress(),
                AuthorizationCheckType.OBJECT_LEVEL,
                rule);
    }

    private void auditAnonymousSuppression(PlatformUser caller, long anonymousCount, String endpoint) {
        if (anonymousCount == 0) {
            return;
        }
        AuthorizationDecision decision = viewResolver.recordPropertyDecision(caller, true, true);
        auditService.recordDenied(
                caller,
                DeniedReason.PROPERTY_SUPPRESSION,
                "incident",
                null,
                "view_reporter_identity",
                endpoint,
                "GET",
                RequestContext.requestId().orElse(UUID.randomUUID()),
                RequestContext.remoteAddress(),
                decision.checkType(),
                decision.rule());
    }
}
