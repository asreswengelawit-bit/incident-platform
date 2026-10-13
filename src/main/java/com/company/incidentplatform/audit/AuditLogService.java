package com.company.incidentplatform.audit;

import com.company.incidentplatform.authorization.AuthorizationDeniedException;
import com.company.incidentplatform.authorization.Capability;
import com.company.incidentplatform.incident.PagedResponse;
import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.PlatformUser;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Section 7.11 / FR-6.3 -- the audit log read path.
 *
 * <p>This is the endpoint that makes the audit trail a control rather than a
 * write-only table. Before it existed {@link AuditService} could append an entry
 * for anything but nothing in the application could read one back, which left two
 * documented requirements unmet in practice:
 *
 * <ul>
 *   <li>7.11: "Audit log read access is available to Admin and Auditor roles" --
 *       entries were being written to a place only a DBA could read.</li>
 *   <li>7.3: "the Auditor role exists precisely to provide independent review
 *       outside the Admin's own control" -- an Auditor who cannot open the log
 *       cannot review anything, so the separation of duties existed on paper only.
 *       That matters because 7.3 also forbids Admins being the sole reviewers of
 *       the audit trail covering their own changes, and there is no mechanism to
 *       satisfy that without a reader.</li>
 * </ul>
 *
 * <h2>Why every read is itself audited</h2>
 *
 * <p>7.11 lists "download/export" among the actions that must be logged, and an
 * audit-log query is the most sensitive read in the product: it is a chronological
 * record of who did what, including the denials. A reviewer reading it is not
 * materially different from one exporting it, and 7.12's "access to a large number
 * of incidents in a short window (possible data-scraping)" applies with more force
 * here than anywhere else.
 *
 * <p>The cost is self-referential log growth -- every read adds a row, so the log
 * grows fastest when it is used most. That is accepted: the volume is a row of
 * metadata, whereas an unlogged oversight read cannot be reconstructed after the
 * fact, and 7.3's independence is worth more than tidiness. The entry names the
 * filter that was used, so an auditor can distinguish "reviewing one actor's
 * activity" from "sweeping the entire table" -- which is the distinction 7.12's
 * scraping alert actually needs.
 *
 * <h2>Function level only</h2>
 *
 * <p>Unlike the incident endpoints there is no object level here. The audit log has
 * no per-row ownership model, and {@code can_view_audit_log} is granted only to the
 * roles 7.11 names. Department scoping (7.2.1) is deliberately not applied: an
 * Auditor's scope is organisation-wide by definition, and an audit entry about
 * department X is not department X's property. Adding a department predicate here
 * would let the subject of a record shape what compliance can see about it.
 */
@Service
public class AuditLogService {

    /**
     * 7.11: the action name for reading the log. Distinct from every incident action
     * so an auditor can filter for oversight reads specifically -- which is how a
     * reviewer would notice one account systematically reading the whole trail.
     */
    public static final String ACTION_AUDIT_QUERY = "audit_log.query";

    /** 7.11 chain-verification action; rarer and more significant than a query. */
    public static final String ACTION_CHAIN_VERIFY = "audit_log.verify_chain";

    /**
     * FR-1.6: the action name for a protected-identity disclosure. The spec words
     * this as "identity of anonymous report #X viewed by Y" and requires it be a
     * <em>distinct</em> entry, separate from the read that made it necessary.
     */
    public static final String ACTION_IDENTITY_VIEWED = "reporter_identity.viewed";

    /**
     * 7.11: verification needs a bounded window for the same reason reads do. An
     * unbounded chain check recomputes a digest per row, so "all time" is a
     * full-table hash driven by a request parameter.
     */
    private static final int DEFAULT_VERIFY_DAYS = 30;

    /** Caps the problem list so a wholesale-tamper response cannot become a large payload. */
    private static final int MAX_CHAIN_PROBLEMS_REPORTED = 100;

    private final AuditLogQueryRepository repository;
    private final AuditService auditService;

    public AuditLogService(AuditLogQueryRepository repository, AuditService auditService) {
        this.repository = repository;
        this.auditService = auditService;
    }

    /**
     * FR-6.3 / 7.11: a filtered, paginated page of audit entries.
     *
     * <p>The capability check precedes the query, so a caller without
     * {@code can_view_audit_log} cannot learn the table's size, its shape, or
     * whether any entry matches their filters: a refusal leaks nothing about what
     * they were asking for.
     */
    @Transactional(readOnly = true)
    public PagedResponse<AuditLogViews.AuditEntryView> query(
            AuditLogQuery query,
            int page,
            int requestedPageSize,
            String sortBy,
            String sortDirection,
            PlatformUser caller) {

        requireAuditLogAccess(caller);

        query.validateRange();
        String validatedSortBy = query.validatedSortBy(sortBy);
        AuditLogQuery.SortDirection validatedDirection = query.validatedDirection(sortDirection);
        int pageSize = AuditLogQuery.clampPageSize(requestedPageSize);
        // A negative page would make OFFSET negative, which PostgreSQL rejects with
        // a driver error and a 500. Normalising to 0 is 9.1's "clamp rather than
        // reject" applied to the offset; the sort field is the one input that must
        // be rejected outright, since an unknown column has no safe interpretation.
        int safePage = Math.max(0, page);

        AuditLogQueryRepository.Page result =
                repository.find(query, validatedSortBy, validatedDirection, safePage, pageSize);

        // FR-1.6: ask the database which of this page's actors are protected
        // reporters. The ids are not selected, so nothing protected is read here.
        //
        // Guarded because an empty candidate set would build "IN ()", which is a
        // syntax error in PostgreSQL rather than a false predicate -- so a page of
        // actor-less entries (system events, lockouts) would otherwise fail the
        // whole request rather than simply needing no redaction.
        Set<UUID> candidateActors = new LinkedHashSet<>();
        for (AuditLogEntry entry : result.entries()) {
            if (entry.actorId() != null) {
                candidateActors.add(entry.actorId());
            }
        }
        Set<UUID> protectedActors = candidateActors.isEmpty()
                ? Set.of()
                : repository.protectedReporterIds(List.copyOf(candidateActors));

        // Whether the caller may see a protected identity at all. V12 deliberately
        // seeds this false for every role including Admin -- Section 2's decision is
        // that the Security Administrator grants it to themself, or to a low-privilege
        // account, as a deliberate audited action. So on a fresh deployment this is
        // always false and no anonymous reporter's identity is ever disclosed through
        // this endpoint; a role that has been granted it at runtime (FR-6.2) does see
        // identities, and every such disclosure is audited below.
        boolean identityPermissionHeld = Capability.VIEW_REPORTER_IDENTITY.isHeldBy(caller.permissions());

        List<AuditLogViews.AuditEntryView> views = new ArrayList<>(result.entries().size());
        Map<UUID, Integer> disclosuresByActor = new LinkedHashMap<>();

        for (AuditLogEntry entry : result.entries()) {
            boolean protectedActor = entry.actorId() != null && protectedActors.contains(entry.actorId());

            if (protectedActor && !identityPermissionHeld) {
                views.add(AuditLogViews.toView(entry, true));
            } else {
                views.add(AuditLogViews.toView(entry, false));
                if (protectedActor) {
                    disclosuresByActor.merge(entry.actorId(), 1, Integer::sum);
                }
            }
        }

        // The FR-1.6 entry is written only when a protected identity was actually
        // surfaced. A withheld row is not a denial -- the caller was not refused
        // anything; they received a redacted view like everyone else. Recording it as
        // a refusal would pollute 7.12's denial signal with entries that are simply
        // the ordinary, intended behaviour for every audit read.
        if (!disclosuresByActor.isEmpty()) {
            recordIdentityAccess(disclosuresByActor, caller);
        }

        recordQuery(caller, query, safePage, pageSize, validatedSortBy, validatedDirection,
                result.entries().size(), result.total(),
                disclosuresByActor.values().stream().mapToInt(Integer::intValue).sum());

        return PagedResponse.of(views, safePage, pageSize, result.total());
    }

    /**
     * 7.11: "Integrity of the audit log itself is periodically verified".
     *
     * <p>Runs {@code verify_audit_log_chain} over a window. Zero rows means the
     * chain is intact across that window; any row is tampering, truncation, or a
     * write that bypassed {@code audit_log_append}.
     *
     * <p>The window is bounded rather than defaulting to all time because the
     * function recomputes a digest per row. Callers wanting the whole history
     * verify it in successive windows, which is also how the periodic job should be
     * built -- and successive windows are what make truncation detectable at all,
     * since a chain gap at a window boundary only shows up as a mismatch in the
     * window that contains the gap's successor.
     */
    @Transactional(readOnly = true)
    public AuditLogViews.ChainVerificationView verifyChain(Instant from, Instant to, PlatformUser caller) {

        requireAuditLogAccess(caller);

        Instant effectiveTo = to == null ? Instant.now() : to;
        Instant effectiveFrom = from == null ? effectiveTo.minusSeconds(DEFAULT_VERIFY_DAYS * 86400L) : from;

        if (!effectiveTo.isAfter(effectiveFrom)) {
            throw new IllegalArgumentException(
                    "'to' must be strictly after 'from'; the range is half-open [from, to)");
        }
        long days = java.time.Duration.between(effectiveFrom, effectiveTo).toDays();
        if (days > AuditLogQuery.MAX_RANGE_DAYS) {
            throw new IllegalArgumentException(
                    "Chain verification window must not exceed " + AuditLogQuery.MAX_RANGE_DAYS
                            + " days (requested " + days + "). Verify successive windows instead.");
        }

        List<AuditLogQueryRepository.ChainProblem> problems = repository.verifyChain(effectiveFrom, effectiveTo);
        boolean truncated = problems.size() >= MAX_CHAIN_PROBLEMS_REPORTED;

        // A verification result is itself a record 7.11 wants kept: was the chain
        // checked, by whom, over what window, and did it pass. Uses recordChange
        // rather than recordAllowed because the outcome is the point -- "verified,
        // 0 problems" and "verified, 4 problems" must not look identical.
        auditService.recordChange(
                caller,
                "audit_log",
                null,
                ACTION_CHAIN_VERIFY,
                RequestContext.endpoint(),
                RequestContext.method(),
                RequestContext.requestId().orElseGet(RequestContext::newRequestId),
                RequestContext.remoteAddress(),
                AuthorizationCheckType.FUNCTION_LEVEL,
                Capability.VIEW_AUDIT_LOG.rule(),
                null,
                describeVerification(effectiveFrom, effectiveTo, problems.size()),
                false);

        return new AuditLogViews.ChainVerificationView(
                problems.isEmpty(), effectiveFrom, effectiveTo, problems.size(), truncated, problems);
    }

    /**
     * 7.2 function level: {@code can_view_audit_log}, refused as a denial so 7.11
     * records who attempted it and 7.12 can alert on repeated attempts.
     */
    private void requireAuditLogAccess(PlatformUser caller) {
        if (!Capability.VIEW_AUDIT_LOG.isHeldBy(caller.permissions())) {
            throw AuthorizationDeniedException.forMissingCapability(
                    Capability.VIEW_AUDIT_LOG, "audit_log", null);
        }
    }

    /**
     * FR-1.6: the "distinct, separately-audited action" -- the entry that says who
     * looked at a protected identity and which anonymous report it belonged to.
     *
     * <p>Keyed by the reporter, then by the incident they reported anonymously,
     * rather than per row: a reviewer paging through one reporter's history would
     * otherwise produce a burst of near-identical entries that buries the signal.
     * Grouped, it reads as what it is -- one person reviewing one anonymous report
     * -- and the number of entries covered is recorded so the grouping does not
     * understate how much was seen.
     *
     * <p>The actor id is written into {@code after_value} deliberately. This entry
     * records that the identity was accessed; an access record that omitted the
     * identity being accessed would not tell an investigator what was exposed.
     * Reaching it requires {@code can_view_reporter_identity}, which is exactly the
     * permission whose exercise is being recorded.
     */
    private void recordIdentityAccess(Map<UUID, Integer> disclosuresByActor, PlatformUser caller) {
        for (Map.Entry<UUID, Integer> disclosure : disclosuresByActor.entrySet()) {
            UUID reporterId = disclosure.getKey();
            int entriesDisclosed = disclosure.getValue();
            Set<UUID> incidentIds = repository.anonymousIncidentIdsReportedBy(reporterId);

            // The lookup should always find at least the incident whose row prompted
            // the check. Emitting one entity-less entry if it somehow does not keeps
            // the disclosure on record rather than dropping it -- an unrecorded
            // identity access is the one outcome FR-1.6 cannot tolerate.
            if (incidentIds.isEmpty()) {
                writeIdentityAccessEntry(caller, null, reporterId, entriesDisclosed);
                continue;
            }
            for (UUID incidentId : incidentIds) {
                writeIdentityAccessEntry(caller, incidentId, reporterId, entriesDisclosed);
            }
        }
    }

    private void writeIdentityAccessEntry(
            PlatformUser caller, UUID incidentId, UUID reporterId, int entriesDisclosed) {
        auditService.recordChange(
                caller,
                "incident",
                incidentId,
                ACTION_IDENTITY_VIEWED,
                RequestContext.endpoint(),
                RequestContext.method(),
                RequestContext.requestId().orElseGet(RequestContext::newRequestId),
                RequestContext.remoteAddress(),
                AuthorizationCheckType.PROPERTY_LEVEL,
                Capability.VIEW_REPORTER_IDENTITY.rule(),
                null,
                "{\"access_via\":\"audit_log\",\"reporter_id\":\"" + reporterId
                        + "\",\"entries_disclosed\":" + entriesDisclosed + ",\"control\":\"FR-1.6\"}",
                false);
    }

    /**
     * Records the read itself, including the filters used.
     *
     * <p>Filters go into {@code after_value} so a reviewer asking "was this account
     * being watched?" can tell a targeted single-actor lookup from a full sweep.
     * The value is assembled here from the caller's own parameters and carries no
     * entry content -- 7.11's warning that "the audit system ... must not itself
     * become a data-leak vector" applies to an audit-log read harder than anywhere
     * else, since reproducing entry content here would duplicate the entire
     * sensitive corpus into rows that must be redacted independently.
     */
    private void recordQuery(
            PlatformUser caller,
            AuditLogQuery query,
            int page,
            int pageSize,
            String sortBy,
            AuditLogQuery.SortDirection direction,
            int returned,
            long total,
            int identitiesDisclosed) {

        StringBuilder filters = new StringBuilder("{");
        appendFilter(filters, "result", query.result());
        appendFilter(filters, "action", query.action());
        appendFilter(filters, "entity_type", query.entityType());
        appendFilter(filters, "entity_id", query.entityId());
        appendFilter(filters, "actor_id", query.actorId());
        appendFilter(filters, "request_id", query.requestId());
        appendFilter(filters, "from", query.from());
        appendFilter(filters, "to", query.to());
        appendFilter(filters, "page", page);
        appendFilter(filters, "page_size", pageSize);
        appendFilter(filters, "sort_by", sortBy);
        appendFilter(filters, "sort_direction", direction.name());
        appendFilter(filters, "returned", returned);
        appendFilter(filters, "total_matched", total);
        appendFilter(filters, "anonymous_identities_disclosed", identitiesDisclosed);
        filters.append('}');

        auditService.recordChange(
                caller,
                "audit_log",
                null,
                ACTION_AUDIT_QUERY,
                RequestContext.endpoint(),
                RequestContext.method(),
                RequestContext.requestId().orElseGet(RequestContext::newRequestId),
                RequestContext.remoteAddress(),
                AuthorizationCheckType.FUNCTION_LEVEL,
                Capability.VIEW_AUDIT_LOG.rule(),
                null,
                filters.toString(),
                false);
    }

    private static void appendFilter(StringBuilder json, String name, Object value) {
        if (value == null || (value instanceof String s && s.isBlank())) {
            return;
        }
        if (json.length() > 1) {
            json.append(',');
        }
        json.append('"').append(name).append("\":");
        if (value instanceof Number || value instanceof Boolean) {
            json.append(value);
        } else {
            json.append('"').append(escape(String.valueOf(value))).append('"');
        }
    }

    private static String describeVerification(Instant from, Instant to, int problemCount) {
        return "{\"from\":\"" + from + "\",\"to\":\"" + to + "\",\"problems_found\":" + problemCount
                + ",\"intact\":" + (problemCount == 0) + "}";
    }

    /**
     * The values assembled above land in a {@code jsonb} column, so a filter value
     * containing a quote must not be able to terminate its own JSON string. Without
     * this an {@code action} filter of {@code a","b":"c} would inject a key into the
     * audit row -- 7.5's parameterization concern in a place where the query is
     * already parameterised, and so easy to forget.
     */
    private static String escape(String value) {
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }
}
