package com.company.incidentplatform.incident;

import com.company.incidentplatform.security.PlatformRole;
import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.web.CurrentUser;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * Section 9 -- the incident endpoints.
 *
 * <p>The controller is deliberately thin. It translates HTTP into a service call
 * and a service result into a response, and holds no authorization logic of its
 * own: 7.2's three layers live in the service and the guard, so that a rule is
 * enforced identically whether it is reached from here, from a scheduled job, or
 * from a future endpoint. A check duplicated in a controller is a check that
 * will be skipped the next time someone adds a second way in.
 *
 * <p>What the controller does own is the HTTP-level contract 7.7 and 9.1 ask
 * for: versioning in the path, pagination parameters passed through as bounded
 * values, the idempotency key header for the 5.4 ingestion path, and a
 * {@code Location} on creation so a client can follow the resource it just made.
 */
@RestController
@RequestMapping("/api/v1/incidents")
public class IncidentController {

    private static final int DEFAULT_PAGE_SIZE = 25;

    private final IncidentService incidentService;

    public IncidentController(IncidentService incidentService) {
        this.incidentService = incidentService;
    }

    /**
     * FR-1.1 / Section 9: create an incident report.
     *
     * <p>{@code Idempotency-Key} is honoured for every caller, not only service
     * accounts. A browser retrying a submit after a dropped connection is the
     * same duplicate-report problem as a SIEM retrying a timed-out POST, and
     * 5.4's at-most-once guarantee is worth more than the extra state it costs.
     *
     * <p>A replayed key returns 200 with the existing incident rather than 201
     * with a new one, which is what lets 5.4's retrying caller distinguish "I
     * created this" from "this already existed" without comparing ids.
     */
    @PostMapping
    ResponseEntity<Object> create(
            @Valid @RequestBody CreateIncidentRequest request,
            @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
            @CurrentUser PlatformUser caller) {

        CreateIncidentResult result = incidentService.createIncident(
                request, caller, null, null, idempotencyKey, sourceFor(caller));

        if (result.replayed()) {
            return ResponseEntity.ok(result);
        }
        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(result.id())
                .toUri();
        return ResponseEntity.created(location).body(result);
    }

    /**
     * FR-2.1 / 9.1: the filtered, department-scoped, paginated incident list.
     *
     * <p>{@code includeDeleted} is the 6.2/7.14 compliance scope. It is accepted
     * from any caller rather than only from Admin and Auditor, because refusing
     * the parameter outright would tell a Reporter that the flag exists; the
     * service ignores it for anyone without organisation scope, and using it
     * honestly is its own audited action.
     */
    @GetMapping
    PagedResponse<Object> list(
            @RequestParam(required = false) IncidentStatus status,
            @RequestParam(required = false) IncidentSeverity severity,
            @RequestParam(required = false) UUID categoryId,
            @RequestParam(required = false) UUID assigneeId,
            @RequestParam(required = false) String department,
            @RequestParam(required = false) Boolean unassignedOnly,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "" + DEFAULT_PAGE_SIZE) int pageSize,
            @RequestParam(required = false) String sortBy,
            @RequestParam(required = false, defaultValue = "DESC") String sortDirection,
            @RequestParam(required = false, defaultValue = "false") boolean includeDeleted,
            @CurrentUser PlatformUser caller) {

        return incidentService.listIncidents(
                status, severity, categoryId, assigneeId, department, unassignedOnly,
                page, pageSize, sortBy, sortDirection, includeDeleted, caller);
    }

    /** 7.2 object level: one incident, in a view this caller is entitled to. */
    @GetMapping("/{id}")
    Object get(
            @PathVariable UUID id,
            @RequestParam(required = false, defaultValue = "false") boolean includeDeleted,
            @CurrentUser PlatformUser caller) {

        return incidentService.getIncident(id, caller, includeDeleted);
    }

    /**
     * Section 8.2: the status transition endpoint.
     *
     * <p>The transition matrix is evaluated server-side against the specific
     * (current, next) pair, never against "this role is an Analyst" generally --
     * which is why the request body carries impact and likelihood rather than a
     * severity, and why the response is a 422 for an unlisted pair rather than a
     * validation error.
     */
    @PatchMapping("/{id}/status")
    Object changeStatus(
            @PathVariable UUID id,
            @Valid @RequestBody ChangeStatusRequest request,
            @CurrentUser PlatformUser caller) {

        return incidentService.changeStatus(id, request, caller);
    }

    /** FR-2.3 / 7.10: assign or reassign, with the race guarded in SQL. */
    @PatchMapping("/{id}/assign")
    Object assign(
            @PathVariable UUID id,
            @Valid @RequestBody AssignIncidentRequest request,
            @CurrentUser PlatformUser caller) {

        return incidentService.assignIncident(id, request, caller);
    }

    /**
     * FR-2.7: escalation.
     *
     * <p>POST rather than PATCH, and distinct from the status endpoint on purpose.
     * Escalation is an attribute change, not a lifecycle transition, and putting
     * it on the status path would invite exactly the conflation 8.1 warns
     * against -- a client that believes it can escalate by moving the status
     * would be wrong, and the 8.2 matrix would have to grow a fiction to allow
     * it.
     */
    @PostMapping("/{id}/escalate")
    Object escalate(
            @PathVariable UUID id,
            @Valid @RequestBody EscalateRequest request,
            @CurrentUser PlatformUser caller) {

        return incidentService.escalateIncident(id, request, caller);
    }

    /**
     * Section 5.4: the ingestion path records where a report came from, and the
     * source is derived from the authenticated role rather than accepted from the
     * client. A body claiming {@code SIEM} from a browser session would put a
     * fabricated channel in the audit record and in FR-5.2's source analytics.
     */
    private static IncidentSource sourceFor(PlatformUser caller) {
        return caller.role() == PlatformRole.SERVICE_ACCOUNT
                ? IncidentSource.API_INGESTION
                : IncidentSource.WEB_UI;
    }
}
