package com.company.incidentplatform.audit;

import com.company.incidentplatform.incident.PagedResponse;
import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.web.CurrentUser;
import java.time.Instant;
import java.util.UUID;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Section 9 -- the audit log read endpoints.
 *
 * <p>Thin by design, matching {@code IncidentController}: it translates HTTP into
 * a service call and holds no authorization logic. 7.2's function-level check
 * lives in {@link AuditLogService} against {@code can_view_audit_log}, so it is
 * enforced identically whether the caller arrives over HTTP or from a scheduled
 * verification job.
 *
 * <p>Filtering is by query parameters rather than a POST body: the endpoint is a
 * plain read, GET is cacheable and bookmarkable, and 9.1's list endpoints are
 * specified this way. There is no free-text search parameter -- see
 * {@link AuditLogQuery} for why the filter set is closed.
 */
@RestController
@RequestMapping("/api/v1/audit-logs")
public class AuditLogController {

    private final AuditLogService auditLogService;

    public AuditLogController(AuditLogService auditLogService) {
        this.auditLogService = auditLogService;
    }

    /**
     * 7.11 / FR-6.3: the filtered, paginated audit trail.
     *
     * <p>Gated on {@code can_view_audit_log}, granted by {@code V10} to Admin and
     * Auditor. Read access is what makes the Auditor role meaningful -- 7.3 requires
     * audit review to be possible outside the Admin's own control, and an endpoint
     * nobody can call does not satisfy that.
     */
    @GetMapping
    PagedResponse<AuditLogViews.AuditEntryView> list(
            @RequestParam(required = false) String result,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String entityType,
            @RequestParam(required = false) UUID entityId,
            @RequestParam(required = false) UUID actorId,
            @RequestParam(required = false) UUID requestId,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int pageSize,
            @RequestParam(required = false) String sortBy,
            @RequestParam(required = false) String sortDirection,
            @CurrentUser PlatformUser caller) {

        return auditLogService.query(
                new AuditLogQuery(result, action, entityType, entityId, actorId, requestId, from, to),
                page, pageSize, sortBy, sortDirection, caller);
    }

    /**
     * 7.11: verify the hash chain over a window.
     *
     * <p>A GET, because it reads and changes nothing in the log. The call is itself
     * audited, so a GET with a side effect on the audit table is not entirely
     * pure -- the same is true of every audited read in this system, and 7.11
     * requires the record more than it requires purity.
     *
     * <p>Defaults to the last 30 days rather than all time: the function recomputes
     * a digest per row, so an unbounded window is a full-table hash driven by a
     * request parameter. Callers verify the full history in successive windows.
     */
    @GetMapping("/verify-chain")
    AuditLogViews.ChainVerificationView verifyChain(
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @CurrentUser PlatformUser caller) {

        return auditLogService.verifyChain(from, to, caller);
    }
}
