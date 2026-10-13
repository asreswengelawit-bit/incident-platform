package com.company.incidentplatform.incident;

import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.audit.RequestContext;
import com.company.incidentplatform.authorization.AuthorizationDecision;
import com.company.incidentplatform.authorization.AuthorizationDeniedException;
import com.company.incidentplatform.authorization.Capability;
import com.company.incidentplatform.authorization.IncidentAccessGuard;
import com.company.incidentplatform.authorization.IncidentSnapshot;
import com.company.incidentplatform.authorization.DepartmentKey;
import com.company.incidentplatform.authorization.IncidentSnapshotRepository;
import com.company.incidentplatform.authorization.IncidentViewResolver;
import com.company.incidentplatform.authorization.IncidentViews;
import com.company.incidentplatform.error.ConflictException;
import com.company.incidentplatform.error.ResourceNotFoundException;
import com.company.incidentplatform.identity.AppUserEntity;
import com.company.incidentplatform.notification.IncidentLifecycleEventType;
import com.company.incidentplatform.notification.NotificationOutboxService;
import com.company.incidentplatform.identity.AppUserRepository;
import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.PlatformRole;
import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.security.VisibilityScope;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.criteria.Predicate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Core Incident Service implementing Section 3.1, 3.2, 7.2, 7.10, 8, and 9.1.
 */
@Service
public class IncidentService {

    private static final Set<String> ALLOWED_SORT_FIELDS = Set.of(
            "reportedAt", "occurredAt", "status", "severity", "title", "slaDueAt", "createdAt"
    );

    /**
     * Section 6.2 / 7.11: the audit action for using the soft-delete compliance
     * scope, and the rule string it is recorded under.
     *
     * <p>Distinct from "read" on purpose. 6.2 requires that oversight access to
     * soft-deleted records "log every use of it as its own audited action", and a
     * reviewer filtering the audit log needs to find every such query without
     * also matching ordinary incident reads.
     */
    static final String AUDIT_ACTION_INCLUDE_DELETED = "read_include_deleted";
    static final String RULE_INCLUDE_DELETED = "incident.read.soft_deleted_audit";

    private final IncidentRepository incidentRepository;
    private final IncidentCategoryRepository categoryRepository;
    private final IncidentCollaboratorRepository collaboratorRepository;
    private final IncidentStatusHistoryRepository statusHistoryRepository;
    private final IncidentReporterIdentityRepository reporterIdentityRepository;
    private final ResponseActionRepository responseActionRepository;
    private final InvestigationNoteRepository noteRepository;
    private final AppUserRepository userRepository;
    private final IncidentSnapshotRepository snapshotRepository;
    private final IncidentAccessGuard accessGuard;
    private final IncidentStateMachine stateMachine;
    private final SeverityClassifier severityClassifier;
    private final SlaDeadlineService slaDeadlines;
    private final IncidentViewResolver viewResolver;
    private final AuditService auditService;
    private final ObjectMapper json;
    private final NotificationOutboxService notificationOutbox;

    public IncidentService(
            IncidentRepository incidentRepository,
            IncidentCategoryRepository categoryRepository,
            IncidentCollaboratorRepository collaboratorRepository,
            IncidentStatusHistoryRepository statusHistoryRepository,
            IncidentReporterIdentityRepository reporterIdentityRepository,
            ResponseActionRepository responseActionRepository,
            InvestigationNoteRepository noteRepository,
            AppUserRepository userRepository,
            IncidentSnapshotRepository snapshotRepository,
            IncidentAccessGuard accessGuard,
            IncidentStateMachine stateMachine,
            SeverityClassifier severityClassifier,
            SlaDeadlineService slaDeadlines,
            AuditService auditService,
            ObjectMapper json,
            NotificationOutboxService notificationOutbox) {
        this.incidentRepository = incidentRepository;
        this.categoryRepository = categoryRepository;
        this.collaboratorRepository = collaboratorRepository;
        this.statusHistoryRepository = statusHistoryRepository;
        this.reporterIdentityRepository = reporterIdentityRepository;
        this.responseActionRepository = responseActionRepository;
        this.noteRepository = noteRepository;
        this.userRepository = userRepository;
        this.snapshotRepository = snapshotRepository;
        this.accessGuard = accessGuard;
        this.stateMachine = stateMachine;
        this.severityClassifier = severityClassifier;
        this.slaDeadlines = slaDeadlines;
        this.viewResolver = new IncidentViewResolver();
        this.auditService = auditService;
        this.json = json;
        this.notificationOutbox = notificationOutbox;
    }

    /**
     * FR-1.1: Create a new incident report.
     *
     * <p>Function level is checked here rather than at the controller because
     * 7.2's rule is that the three layers are evaluated per operation, and the
     * capability that gates creation is a property of the call, not of any
     * existing incident to authorize against.
     */
    @Transactional
    public CreateIncidentResult createIncident(
            CreateIncidentRequest request,
            PlatformUser caller,
            String remoteAddress,
            String userAgent,
            String idempotencyKey,
            IncidentSource source) {

        // Section 7.2 (1) function level. 12.1 grants can_create_incident to
        // everyone including the read-only Auditor, because a human Reporter must
        // be able to file; Auditor's own writes are still blocked by the
        // read-only check below, so the grant cannot be used to modify anything.
        if (caller.permissions().isReadOnly()) {
            throw AuthorizationDeniedException.forReadOnlyRole("incident", null);
        }
        if (!Capability.CREATE_INCIDENT.isHeldBy(caller.permissions())) {
            throw AuthorizationDeniedException.forMissingCapability(
                    Capability.CREATE_INCIDENT, "incident", null);
        }

        // 5.4 ingestion: a service account is a machine, not an employee, so the
        // web-facing create grant is not enough on its own -- SIEM submission is a
        // distinct authority and is checked distinctly, so revoking it does not
        // silently revoke reporting from the people who use the UI.
        if (caller.role() == PlatformRole.SERVICE_ACCOUNT
                && !Capability.INGEST_INCIDENT.isHeldBy(caller.permissions())) {
            throw AuthorizationDeniedException.forMissingCapability(
                    Capability.INGEST_INCIDENT, "incident", null);
        }

        String normalizedKey = idempotencyKey != null && !idempotencyKey.isBlank()
                ? idempotencyKey.trim()
                : null;
        UUID requestId = RequestContext.requestId().orElse(UUID.randomUUID());

        // Section 5.4: at-most-once per Idempotency-Key. The replay returns the
        // stored incident rather than inserting again, and the caller is told it
        // is a replay so a retrying SIEM can tell "created" from "already there".
        if (normalizedKey != null) {
            Optional<IncidentEntity> existing = incidentRepository.findByIdempotencyKey(normalizedKey);
            if (existing.isPresent()) {
                return new CreateIncidentResult(
                        existing.get().getId(),
                        true,
                        existing.get().getSource(),
                        buildResolvedView(existing.get(), caller, false));
            }
        }

        AppUserEntity reporter = userRepository.findById(caller.id())
                .orElseThrow(() -> new ResourceNotFoundException("user", caller.id()));

        // 6.2 / FR-6.2: a category that is disabled or in the delete queue stops
        // accepting new reports. Not filtering it out of the response either --
        // an incident filed under a retired category is a governance question, and
        // silently moving it to another category would misfile it.
        IncidentCategoryEntity category = categoryRepository.findById(request.categoryId())
                .orElseThrow(() -> new ResourceNotFoundException("incident_category", request.categoryId()));
        if (!category.isActive() || category.getDeletedAt() != null) {
            throw new ConflictException(
                    "Incident category " + category.getName()
                            + " is not accepting new reports (FR-6.2: deleted or disabled categories are not selectable)");
        }

        UUID incidentId = UUID.randomUUID();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime occurredAt = request.occurredAt() != null ? request.occurredAt() : now;
        IncidentSource effectiveSource = source != null ? source : IncidentSource.WEB_UI;

        IncidentEntity incident = new IncidentEntity(
                incidentId,
                request.title().trim(),
                request.description().trim(),
                category,
                request.severity(),
                reporter,
                occurredAt,
                now,
                request.affectedSystem(),
                DepartmentKey.normalize(request.affectedDepartment()),
                request.anonymous(),
                request.containsPii(),
                effectiveSource,
                normalizedKey
        );

        // Section 6.3 denormalized SLA calculation. A self-assessed severity on
        // the report selects the severity-level policy when one exists; with none,
        // the category default applies, and a later classification recalculates.
        SlaDeadlineService.Deadlines deadlines = slaDeadlines.compute(
                category, incident.getSeverity(), now);
        incident.setSlaResponseDueAt(deadlines.responseDue());
        incident.setSlaDueAt(deadlines.resolutionDue());

        IncidentEntity saved = incidentRepository.save(incident);

        // FR-1.6 restricted anonymous store: persist true reporter identity.
        // Written here even though the reporter is also on `incident`, because the
        // point of FR-1.6 is a separately-permissioned store: an identity leaked
        // by a reporting bug in the incident path still finds nothing in the
        // restricted table, which only a can_view_reporter_identity read reaches.
        if (request.anonymous()) {
            IncidentReporterIdentityEntity identity = new IncidentReporterIdentityEntity(
                    incidentId,
                    caller.id(),
                    caller.email(),
                    remoteAddress,
                    userAgent,
                    incident.getSource(),
                    now
            );
            reporterIdentityRepository.save(identity);
        }

        // Record initial status history entry
        IncidentStatusHistoryEntity statusHistory = new IncidentStatusHistoryEntity(
                UUID.randomUUID(), saved, null, IncidentStatus.NEW, reporter, now, "Initial report submitted", requestId
        );
        statusHistoryRepository.save(statusHistory);
        notificationOutbox.enqueue(
                IncidentLifecycleEventType.INCIDENT_CREATED, saved, null, saved.getStatus(), null);

        // Section 7.11 audit record, with the created state as the "after" value
        // so a later dispute about what was reported is answerable from the log
        // alone. The description is included deliberately: it is the report the
        // reporter made, not PII belonging to someone else, and an audit trail
        // that omits it cannot evidence the report.
        Map<String, Object> after = new LinkedHashMap<>();
        after.put("status", IncidentStatus.NEW.name());
        after.put("severity", incident.getSeverity() == null ? null : incident.getSeverity().name());
        after.put("category", category.getName());
        after.put("source", effectiveSource.name());
        after.put("anonymous", incident.isAnonymous());
        after.put("title", saved.getTitle());
        after.put("description", saved.getDescription());
        after.put("sla_response_due_at", String.valueOf(deadlines.responseDue()));
        after.put("sla_due_at", String.valueOf(deadlines.resolutionDue()));
        after.put("sla_rule", deadlines.rule());

        auditService.recordChange(
                caller,
                "incident",
                incidentId,
                "create",
                "/api/v1/incidents",
                "POST",
                requestId,
                remoteAddress,
                AuthorizationCheckType.FUNCTION_LEVEL,
                "capability.can_create_incident",
                null,
                toJson(after),
                false);

        return new CreateIncidentResult(incidentId, false, effectiveSource, buildResolvedView(saved, caller, false));
    }

    /**
     * 7.2 object-level & property-level: fetch single incident detail.
     *
     * <p>{@code includeDeleted} is the 6.2/7.14 opt-in compliance scope. Using it
     * is recorded as its own audit action rather than folded into the ordinary
     * read: 6.2 says oversight access must be "traceable", and a read rule string
     * that varies subtly is not a reviewable signal. An Auditor pulling
     * soft-deleted records is a compliance act, and it reads as one in the log.
     */
    @Transactional(readOnly = true)
    public Object getIncident(UUID id, PlatformUser caller, boolean includeDeleted) {
        // Enforce object-level check (7.2.1 BOLA prevention). The guard is what
        // rejects includeDeleted for any role without organisation scope, so a
        // non-privileged caller is refused before the flag is ever acted on, and
        // before any repository lookup -- the guard reads the authorization
        // snapshot, so an unauthorized caller learns nothing about existence.
        accessGuard.requireRead(caller, id, includeDeleted);

        IncidentEntity incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("incident", id));

        UUID requestId = RequestContext.requestId().orElse(UUID.randomUUID());
        boolean softDeletedVisible = includeDeleted && incident.isDeleted();

        if (softDeletedVisible) {
            // The distinct action. Deliberately not "read": a query that happens
            // to return a deleted record is not the same event as one that was
            // scoped to them, and only the second is the compliance access 6.2
            // requires be traceable.
            auditService.recordAllowed(
                    caller,
                    "incident",
                    id,
                    AUDIT_ACTION_INCLUDE_DELETED,
                    "/api/v1/incidents/" + id,
                    "GET",
                    requestId,
                    RequestContext.remoteAddress(),
                    AuthorizationCheckType.OBJECT_LEVEL,
                    RULE_INCLUDE_DELETED);
            return buildResolvedView(incident, caller, true);
        }

        auditService.recordAllowed(
                caller,
                "incident",
                id,
                "read",
                "/api/v1/incidents/" + id,
                "GET",
                requestId,
                RequestContext.remoteAddress(),
                AuthorizationCheckType.OBJECT_LEVEL,
                "incident.read");

        return buildResolvedView(incident, caller, true);
    }

    /**
     * FR-2.1, 7.2.1, 9.1: List incidents with department scoping and pagination limits.
     */
    @Transactional(readOnly = true)
    public PagedResponse<Object> listIncidents(
            IncidentStatus status,
            IncidentSeverity severity,
            UUID categoryId,
            UUID assigneeId,
            String department,
            Boolean unassignedOnly,
            int page,
            int requestedPageSize,
            String sortBy,
            String sortDirection,
            boolean includeDeleted,
            PlatformUser caller) {

        // Section 9.1: Clamp pageSize to hard maximum 100
        int pageSize = Math.min(Math.max(1, requestedPageSize), 100);

        // Section 9.1: Validate sort field against allow-list
        String validatedSortBy = (sortBy == null || sortBy.isBlank()) ? "reportedAt" : sortBy.trim();
        if (!ALLOWED_SORT_FIELDS.contains(validatedSortBy)) {
            throw new IllegalArgumentException(
                    "Invalid sort field '" + sortBy + "'. Allowed sort fields: " + ALLOWED_SORT_FIELDS);
        }

        Sort.Direction direction = "ASC".equalsIgnoreCase(sortDirection) ? Sort.Direction.ASC : Sort.Direction.DESC;
        Pageable pageable = PageRequest.of(Math.max(0, page), pageSize, Sort.by(direction, validatedSortBy));

        // Build department-scoped JPA specification (Section 7.2.1)
        //
        // 6.2 / 7.14: includeDeleted is honoured only for organisation-wide roles
        // (Admin and Auditor). The role test is repeated here rather than trusted
        // from the caller's flag alone, because this predicate is the one that
        // actually widens the result set -- the object-level guard in the guard
        // class is the second line, not the first.
        boolean canIncludeDeleted = includeDeleted
                && (caller.role() == PlatformRole.SECURITY_ADMIN || caller.role() == PlatformRole.AUDITOR);

        Specification<IncidentEntity> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            // Soft-delete filter: excluded by default for every role (6.2), and
            // included only under the opt-in above.
            if (!canIncludeDeleted) {
                predicates.add(cb.isNull(root.get("deletedAt")));
            }

            // 7.2.1 Visibility scope predicates
            VisibilityScope scope = caller.permissions().visibilityScope();
            switch (scope) {
                case OWN_INCIDENTS -> predicates.add(cb.equal(root.get("reporter").get("id"), caller.id()));
                case ASSIGNED_AND_OWN_DEPARTMENT_UNASSIGNED -> {
                    String userDept = caller.department() != null ? caller.department().trim() : "";
                    Predicate assignedToSelf = cb.equal(root.get("assignee").get("id"), caller.id());
                    Predicate unassignedInDept = cb.and(
                            cb.isNull(root.get("assignee")),
                            cb.or(
                                    cb.equal(cb.lower(root.get("affectedDepartment")), userDept.toLowerCase()),
                                    cb.and(
                                            cb.or(cb.isNull(root.get("affectedDepartment")), cb.equal(cb.trim(root.get("affectedDepartment")), "")),
                                            cb.equal(cb.lower(root.get("reporter").get("department")), userDept.toLowerCase())
                                    )
                            )
                    );
                    predicates.add(cb.or(assignedToSelf, unassignedInDept));
                }
                case LED_DEPARTMENTS -> {
                    Set<String> ledDepts = caller.permissions().ledDepartments();
                    if (ledDepts.isEmpty()) {
                        predicates.add(cb.disjunction()); // Sees nothing if no led departments configured
                    } else {
                        List<Predicate> deptPredicates = new ArrayList<>();
                        for (String led : ledDepts) {
                            deptPredicates.add(cb.equal(cb.lower(root.get("affectedDepartment")), led.toLowerCase()));
                        }
                        predicates.add(cb.or(deptPredicates.toArray(new Predicate[0])));
                    }
                }
                case ORGANIZATION -> {
                    // Admin & Auditor see organization-wide
                }
                case NONE -> predicates.add(cb.disjunction());
            }

            // Optional query filters (FR-2.1)
            if (status != null) {
                predicates.add(cb.equal(root.get("status"), status));
            }
            if (severity != null) {
                predicates.add(cb.equal(root.get("severity"), severity));
            }
            if (categoryId != null) {
                predicates.add(cb.equal(root.get("category").get("id"), categoryId));
            }
            if (assigneeId != null) {
                predicates.add(cb.equal(root.get("assignee").get("id"), assigneeId));
            }
            if (Boolean.TRUE.equals(unassignedOnly)) {
                predicates.add(cb.isNull(root.get("assignee")));
            }
            if (department != null && !department.isBlank()) {
                predicates.add(cb.equal(cb.lower(root.get("affectedDepartment")), department.trim().toLowerCase()));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        Page<IncidentEntity> pagedEntities = incidentRepository.findAll(spec, pageable);

        // Defense in depth: the query above already encodes the visibility rule,
        // and this second pass through the same authorizer exists to make the two
        // agree -- if a future predicate is added to the query and gets it wrong,
        // this still refuses to serialise the row. It is a filter rather than a
        // guard because the query has already been paginated, so at most
        // pageSize rows are held.
        List<UUID> ids = pagedEntities.getContent().stream().map(IncidentEntity::getId).toList();
        Map<UUID, IncidentSnapshot> snapshots = snapshotRepository.findAllByIds(ids);
        // canIncludeDeleted, not includeDeleted: a non-privileged caller who set
        // the flag must have the soft-deleted rows filtered out of the second pass
        // too, and passing the raw flag would let them through the authorizer.
        List<IncidentSnapshot> visibleSnapshots = accessGuard.filterVisible(
                caller, new ArrayList<>(snapshots.values()), canIncludeDeleted);
        Set<UUID> visibleIds = visibleSnapshots.stream()
                .map(IncidentSnapshot::id)
                .collect(java.util.stream.Collectors.toSet());

        List<Object> views = pagedEntities.getContent().stream()
                .filter(entity -> visibleIds.contains(entity.getId()))
                .map(entity -> buildResolvedView(entity, caller, false))
                .toList();

        // 7.2: object-level authorization applies to list/search/export endpoints
        // too, "not just single-record GETs" -- and 7.11 requires the access to be
        // recorded. This list previously wrote no audit entry at all, so an
        // Auditor sweeping the org for soft-deleted records, or a scraper walking
        // every page, left no trace. The scope-use entry is recorded when the
        // opt-in is actually honoured; the ordinary entry covers everything else.
        UUID requestId = RequestContext.requestId().orElse(UUID.randomUUID());
        boolean returnedSoftDeleted = canIncludeDeleted
                && pagedEntities.getContent().stream().anyMatch(IncidentEntity::isDeleted);
        auditService.recordAllowed(
                caller,
                "incident",
                null,
                returnedSoftDeleted ? AUDIT_ACTION_INCLUDE_DELETED : "list",
                "/api/v1/incidents",
                "GET",
                requestId,
                RequestContext.remoteAddress(),
                AuthorizationCheckType.OBJECT_LEVEL,
                returnedSoftDeleted ? RULE_INCLUDE_DELETED : "incident.list");

        // FR-1.6 on a page: the property-level outcome is recorded once for the
        // request rather than once per anonymous row on it.
        auditPropertyDecisionForPage(
                caller, (int) pagedEntities.getContent().stream().filter(IncidentEntity::isAnonymous).count());

        return PagedResponse.of(views, pageable.getPageNumber(), pageSize, pagedEntities.getTotalElements());
    }

    /**
     * Section 8.2: State machine status transition.
     *
     * <p>Also the point where FR-2.2's classification happens and where 6.3's SLA
     * recalculation happens, because those are not incidental to the transition:
     * triaging <em>is</em> classifying, and 6.3 requires the deadline follow the
     * severity it was computed for.
     */
    @Transactional
    public Object changeStatus(UUID id, ChangeStatusRequest request, PlatformUser caller) {
        // Precondition (7.2.1): authorize before the incident record is loaded.
        // The guard reads the authorization snapshot, so a caller without access
        // is refused without the row's title, reporter, or anonymous linkage ever
        // entering this transaction. What is needed first is only the current
        // status, because 8.2's reopening rule is status-dependent, and that is
        // read as a scalar projection.
        IncidentStatus currentStatus = incidentRepository.findStatusById(id).orElse(null);
        Capability requiredCapability = capabilityForTransition(currentStatus, request.status());
        accessGuard.requireWrite(caller, id, requiredCapability);

        IncidentEntity incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("incident", id));

        AppUserEntity callerEntity = userRepository.findById(caller.id()).orElse(null);

        // FR-2.2 / 12.2: severity is computed from the impact and likelihood the
        // caller supplied, never chosen. Triaging is the classification step, so
        // both inputs are required in this same request; sending an explicit
        // severity as well is refused rather than ignored, because silently
        // dropping a field the caller set is how a client ends up believing it
        // classified an incident when it did not.
        SeverityClassifier.Classification classification = null;
        if (request.status() == IncidentStatus.TRIAGED
                && incident.getStatus() == IncidentStatus.NEW) {
            if (request.severity() != null) {
                throw new IllegalArgumentException(
                        "Severity is computed from impact and likelihood, not chosen (Section 12.2). Send "
                                + "impact and likelihood; a severity override is not available on triage.");
            }
            classification = severityClassifier.classify(
                    request.impact() == null ? null : ImpactLevel.fromRank(request.impact()),
                    request.likelihood() == null ? null : LikelihoodLevel.fromRank(request.likelihood()));
        }

        // A severity value on any other transition is an override, not a
        // classification: it bypasses the matrix, so it needs its own capability,
        // a stated reason, and 7.3 attribution to the person who made it.
        boolean isSeverityOverride = request.status() != IncidentStatus.TRIAGED
                && request.severity() != null
                && request.severity() != incident.getSeverity();
        if (isSeverityOverride) {
            if (!Capability.OVERRIDE_SEVERITY.isHeldBy(caller.permissions())) {
                throw AuthorizationDeniedException.forMissingCapability(
                        Capability.OVERRIDE_SEVERITY, "incident", id);
            }
            if (request.reason() == null || request.reason().isBlank()) {
                throw new IllegalArgumentException(
                        "A reason is required to override severity (FR-2.2: rationale is analyst-only and must be "
                                + "attributable under Section 7.3)");
            }
        }

        // Preconditions check: response action count
        long responseActionCount = 0;
        if (incident.getStatus() == IncidentStatus.CONTAINED && request.status() == IncidentStatus.RESOLVED) {
            responseActionCount = responseActionRepository.countByIncidentId(id);
        }

        AppUserEntity targetAssignee = null;
        if (request.assigneeId() != null) {
            targetAssignee = userRepository.findById(request.assigneeId())
                    .orElseThrow(() -> new ResourceNotFoundException("user", request.assigneeId()));
        }

        // Validate transition through Section 8.2 State Machine
        IncidentStateMachine.TransitionContext context = new IncidentStateMachine.TransitionContext(
                classification != null ? classification.severity() : request.severity(),
                targetAssignee,
                request.reason(),
                request.resolutionSummary(),
                responseActionCount
        );
        stateMachine.validateTransition(incident, request.status(), caller, context);

        // Apply transition effects
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        IncidentStatus previousStatus = incident.getStatus();
        IncidentSeverity previousSeverity = incident.getSeverity();
        UUID previousAssigneeId = incident.getAssignee() == null ? null : incident.getAssignee().getId();
        OffsetDateTime previousResponseDue = incident.getSlaResponseDueAt();
        OffsetDateTime previousResolutionDue = incident.getSlaDueAt();

        incident.setStatus(request.status());

        if (classification != null) {
            incident.setSeverity(classification.severity());
        } else if (isSeverityOverride) {
            incident.setSeverity(request.severity());
            incident.setSeverityOverriddenBy(callerEntity);
            incident.setSeverityOverrideReason(request.reason().trim());
        }

        if (targetAssignee != null && request.status() == IncidentStatus.ASSIGNED) {
            incident.setAssignee(targetAssignee);
        }

        if (request.status() == IncidentStatus.REJECTED) {
            incident.setRejectedReason(request.reason());
        }

        if (request.status() == IncidentStatus.RESOLVED) {
            incident.setResolvedAt(now);
            incident.setResolvedBy(callerEntity);
            if (request.resolutionSummary() != null) {
                incident.setResolutionSummary(request.resolutionSummary());
            }
        }

        if (request.status() == IncidentStatus.CLOSED) {
            incident.setClosedAt(now);
            incident.setClosedBy(callerEntity);
        }

        // 6.3: the SLA target follows severity, so a classification or an
        // override moves the deadline. Recalculated from `now` rather than from
        // reportedAt, so the clock that matters is the one the analyst was
        // working to and the audit row can show the shift.
        SlaDeadlineService.Deadlines recalculated = null;
        if (previousSeverity != incident.getSeverity()) {
            recalculated = slaDeadlines.compute(
                    incident.getCategory(), incident.getSeverity(), now);
            incident.setSlaResponseDueAt(recalculated.responseDue());
            incident.setSlaDueAt(recalculated.resolutionDue());
        }

        IncidentEntity saved = incidentRepository.save(incident);

        // Record status history (7.10 transaction integrity)
        UUID requestId = RequestContext.requestId().orElse(UUID.randomUUID());
        IncidentStatusHistoryEntity history = new IncidentStatusHistoryEntity(
                UUID.randomUUID(), saved, previousStatus, request.status(),
                callerEntity, now, request.reason(), requestId
        );
        statusHistoryRepository.save(history);
        notificationOutbox.enqueue(
                IncidentLifecycleEventType.STATUS_CHANGED,
                saved,
                previousStatus,
                saved.getStatus(),
                saved.getAssignee());
        if (targetAssignee != null
                && !targetAssignee.getId().equals(previousAssigneeId)) {
            notificationOutbox.enqueue(
                    IncidentLifecycleEventType.ASSIGNED,
                    saved,
                    previousStatus,
                    saved.getStatus(),
                    targetAssignee);
        }
        if (previousSeverity != saved.getSeverity()) {
            notificationOutbox.enqueueSeverityChanged(saved, previousSeverity, saved.getSeverity());
        }
        if (request.status() == IncidentStatus.REOPENED) {
            saved.incrementSlaCycle();
        }

        // Audit status change with the before/after 7.11 requires. The
        // impact/likelihood inputs are included for a classification because 12.2
        // makes them the auditable artifact: a later reviewer of "why was this
        // HIGH" needs the two judgements, not the output.
        Map<String, Object> before = new LinkedHashMap<>();
        before.put("status", previousStatus.name());
        before.put("severity", previousSeverity == null ? null : previousSeverity.name());
        before.put("assignee_id", incident.getAssignee() == null ? null : incident.getAssignee().getId());
        before.put("sla_response_due_at", String.valueOf(previousResponseDue));
        before.put("sla_due_at", String.valueOf(previousResolutionDue));

        Map<String, Object> after = new LinkedHashMap<>();
        after.put("status", request.status().name());
        after.put("severity", saved.getSeverity() == null ? null : saved.getSeverity().name());
        after.put("assignee_id", saved.getAssignee() == null ? null : saved.getAssignee().getId());
        after.put("sla_response_due_at", String.valueOf(saved.getSlaResponseDueAt()));
        after.put("sla_due_at", String.valueOf(saved.getSlaDueAt()));
        if (classification != null) {
            after.put("impact", classification.impact().rank());
            after.put("likelihood", classification.likelihood().rank());
            after.put("severity_justification", classification.justification());
        }
        if (isSeverityOverride) {
            after.put("severity_overridden_by", callerEntity == null ? null : callerEntity.getId());
            after.put("severity_override_reason", request.reason().trim());
        }

        // The rule names the transition and, where severity was involved, the
        // exact matrix cell -- so a grid later edited under this incident still
        // leaves a row that says which cell produced its severity.
        String rule = "transition." + previousStatus + "_TO_" + request.status()
                + (classification != null ? " rule=" + classification.rule() : "");
        if (recalculated != null) {
            rule = rule + " sla=" + recalculated.rule();
        }

        auditService.recordChange(
                caller,
                "incident",
                id,
                "status_change",
                "/api/v1/incidents/" + id + "/status",
                "PATCH",
                requestId,
                RequestContext.remoteAddress(),
                AuthorizationCheckType.OBJECT_LEVEL,
                rule,
                toJson(before),
                toJson(after),
                false);

        return buildResolvedView(saved, caller, true);
    }

    /**
     * FR-2.7 / Section 8.1: Escalate an incident (attribute, NOT status).
     */
    @Transactional
    public Object escalateIncident(UUID id, EscalateRequest request, PlatformUser caller) {
        accessGuard.requireWrite(caller, id, Capability.ESCALATE);

        IncidentEntity incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("incident", id));

        if (!incident.getStatus().canBeEscalated()) {
            throw new InvalidStatusTransitionException(
                    "Incident in status " + incident.getStatus() + " cannot be escalated");
        }

        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        IncidentSeverity previousSeverity = incident.getSeverity();
        OffsetDateTime previousResponseDue = incident.getSlaResponseDueAt();
        OffsetDateTime previousResolutionDue = incident.getSlaDueAt();

        incident.setEscalated(true);
        incident.setEscalatedAt(now);
        incident.setEscalationReason(request.reason().trim());

        // FR-2.7: escalation raises severity one step so the SLA target and the
        // queue priority follow the escalation. With no severity yet, there is no
        // step to take from, and HIGH is the floor rather than MEDIUM because an
        // escalated incident is by definition one someone wants attention on.
        if (incident.getSeverity() != null) {
            incident.setSeverity(incident.getSeverity().nextHigher());
        } else {
            incident.setSeverity(IncidentSeverity.HIGH);
        }

        // 6.3: the raised severity changes which policy applies, so the deadlines
        // move with it and the move is audited rather than discovered later as a
        // "why did this breach early" question.
        SlaDeadlineService.Deadlines recalculated = slaDeadlines.compute(
                incident.getCategory(), incident.getSeverity(), now);
        incident.setSlaResponseDueAt(recalculated.responseDue());
        incident.setSlaDueAt(recalculated.resolutionDue());

        IncidentEntity saved = incidentRepository.save(incident);
        notificationOutbox.enqueue(
                IncidentLifecycleEventType.ESCALATED,
                saved,
                saved.getStatus(),
                saved.getStatus(),
                saved.getAssignee());
        notificationOutbox.enqueueSeverityChanged(saved, previousSeverity, saved.getSeverity());

        UUID requestId = RequestContext.requestId().orElse(UUID.randomUUID());
        Map<String, Object> before = new LinkedHashMap<>();
        before.put("escalated", false);
        before.put("severity", previousSeverity == null ? null : previousSeverity.name());
        before.put("sla_response_due_at", String.valueOf(previousResponseDue));
        before.put("sla_due_at", String.valueOf(previousResolutionDue));

        Map<String, Object> after = new LinkedHashMap<>();
        after.put("escalated", true);
        after.put("severity", saved.getSeverity().name());
        after.put("escalation_reason", saved.getEscalationReason());
        after.put("escalated_at", String.valueOf(saved.getEscalatedAt()));
        after.put("sla_response_due_at", String.valueOf(saved.getSlaResponseDueAt()));
        after.put("sla_due_at", String.valueOf(saved.getSlaDueAt()));

        auditService.recordChange(
                caller,
                "incident",
                id,
                "escalate",
                "/api/v1/incidents/" + id + "/escalate",
                "POST",
                requestId,
                RequestContext.remoteAddress(),
                AuthorizationCheckType.OBJECT_LEVEL,
                "capability.can_escalate sla=" + recalculated.rule(),
                toJson(before),
                toJson(after),
                false);

        return buildResolvedView(saved, caller, true);
    }

    /**
     * FR-2.3, 7.10: Assign or reassign an incident.
     */
    @Transactional
    public Object assignIncident(UUID id, AssignIncidentRequest request, PlatformUser caller) {
        // Self-assignment and reassignment are different authorities, and the
        // distinction turns on the caller's own identity rather than on the
        // incident's state, so it is settled before the guard.
        boolean isSelfAssign = caller.id().equals(request.assigneeId());
        Capability capability = isSelfAssign ? Capability.ASSIGN_SELF : Capability.REASSIGN;
        accessGuard.requireWrite(caller, id, capability);

        IncidentEntity incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("incident", id));
        AppUserEntity previousAssignee = incident.getAssignee();
        IncidentStatus previousStatus = incident.getStatus();

        AppUserEntity newAssignee = userRepository.findById(request.assigneeId())
                .orElseThrow(() -> new ResourceNotFoundException("user", request.assigneeId()));

        if (!newAssignee.isActive()) {
            // 8.2 requires the assignee to be an active user. Raised as a conflict
            // rather than a bad request: the request is well-formed, the platform
            // is telling the caller the target is not assignable right now.
            throw new ConflictException("Target assignee account is disabled");
        }

        // 8.2: assignment is what moves an incident into ASSIGNED, so the status
        // follows the assignee. On an incident already past the queue (triaging,
        // resolving), assignment changes ownership only and must not rewind the
        // workflow -- hence the same status is written back rather than cleared.
        IncidentStatus nextStatus = previousStatus == IncidentStatus.NEW
                || previousStatus == IncidentStatus.TRIAGED
                ? IncidentStatus.ASSIGNED
                : previousStatus;

        // Section 7.10 atomic update
        int rowsUpdated;
        if (previousAssignee == null) {
            rowsUpdated = incidentRepository.assignUnassignedAtomic(id, newAssignee, nextStatus);
        } else {
            rowsUpdated = incidentRepository.reassignAtomic(id, newAssignee, previousAssignee, nextStatus);
        }

        if (rowsUpdated == 0) {
            // A lost optimistic-concurrency race is a 409, not a 500. The caller
            // did nothing wrong -- somebody else took the incident first, and 7.5
            // says the response should say so. The previous IllegalStateException
            // surfaced as a 500, which would have sent an ordinary concurrent
            // self-assignment to the error queue as if the platform were broken.
            throw new ConflictException(
                    "Concurrent modification detected: incident has been assigned or updated by another user");
        }

        IncidentEntity updated = incidentRepository.findById(id).orElseThrow();
        if (updated.getStatus() != previousStatus) {
            notificationOutbox.enqueue(
                    IncidentLifecycleEventType.STATUS_CHANGED,
                    updated,
                    previousStatus,
                    updated.getStatus(),
                    newAssignee);
        }
        notificationOutbox.enqueue(
                IncidentLifecycleEventType.ASSIGNED,
                updated,
                previousStatus,
                updated.getStatus(),
                newAssignee);
        UUID requestId = RequestContext.requestId().orElse(UUID.randomUUID());

        // 7.10: the status history is part of the same transaction as the write it
        // describes. Assigning from NEW or TRIAGED changes the status, and this
        // path previously wrote no history row for it -- so the immutable timeline
        // silently lost the one transition that hands over ownership.
        if (updated.getStatus() != previousStatus) {
            statusHistoryRepository.save(new IncidentStatusHistoryEntity(
                    UUID.randomUUID(),
                    updated,
                    previousStatus,
                    updated.getStatus(),
                    userRepository.findById(caller.id()).orElse(null),
                    OffsetDateTime.now(ZoneOffset.UTC),
                    isSelfAssign ? "Self-assigned" : "Assigned to " + newAssignee.getFullName(),
                    requestId));
        }

        // The audit row carries the previous and new assignee. FR-2.3's "no two
        // analysts are assigned to the same incident" is a control someone will
        // need to evidence after the fact, and "an assign happened" is not evidence
        // of it.
        Map<String, Object> before = new LinkedHashMap<>();
        before.put("assignee_id", previousAssignee == null ? null : previousAssignee.getId());
        before.put("status", previousStatus.name());

        Map<String, Object> after = new LinkedHashMap<>();
        after.put("assignee_id", newAssignee.getId());
        after.put("status", updated.getStatus().name());

        auditService.recordChange(
                caller,
                "incident",
                id,
                "assign",
                "/api/v1/incidents/" + id + "/assign",
                "PATCH",
                requestId,
                RequestContext.remoteAddress(),
                AuthorizationCheckType.OBJECT_LEVEL,
                isSelfAssign ? "capability.can_assign_self" : "capability.can_reassign",
                toJson(before),
                toJson(after),
                false);

        return buildResolvedView(updated, caller, true);
    }

    /**
     * The function-level capability 8.2 attaches to a target status.
     *
     * <p>Reopening is the only status-dependent edge: 8.2 allows an Analyst to
     * reopen a RESOLVED incident but reserves reopening a CLOSED one for a Lead,
     * so the source state decides which capability applies. That is why
     * {@code from} is passed and why the caller reads it as a projection first.
     * A {@code null} {@code from} means the incident does not exist, and the
     * object-level guard refuses it immediately afterwards -- the stricter
     * capability is assumed so that nothing here has to reason about a missing
     * row.
     */
    private Capability capabilityForTransition(IncidentStatus from, IncidentStatus to) {
        return switch (to) {
            case TRIAGED -> Capability.CLASSIFY;
            case ASSIGNED -> Capability.REASSIGN;
            case REJECTED -> Capability.CLASSIFY;
            case INVESTIGATING -> Capability.VIEW_INCIDENT;
            case CONTAINED -> Capability.RECORD_RESPONSE_ACTION;
            case RESOLVED -> Capability.RECORD_RESPONSE_ACTION;
            case CLOSED -> Capability.APPROVE_CLOSURE;
            case REOPENED -> from == IncidentStatus.CLOSED
                    ? Capability.REOPEN_CLOSED
                    : Capability.VIEW_INCIDENT;
            case NEW -> Capability.VIEW_INCIDENT;
        };
    }

    /**
     * Builds the role-scoped DTO using {@link IncidentViewResolver}, enforcing
     * Section 7.2.3 and FR-1.6.
     *
     * @param auditPropertyDecision true when one incident is being returned to a
     *        single caller. The property-level outcome is then recorded per
     *        incident. False for list responses, where a page of 100 anonymous
     *        reports would otherwise write 100 property-level rows describing one
     *        user's request; {@link #auditPropertyDecisionForPage} records one
     *        summary row instead.
     */
    private Object buildResolvedView(IncidentEntity entity, PlatformUser caller, boolean auditPropertyDecision) {
        List<UUID> collaboratorIds = collaboratorRepository.findActiveByIncidentId(entity.getId())
                .stream().map(c -> c.getUser().getId()).toList();

        // FR-1.6 Anonymous Identity resolution
        IncidentViews.ReporterIdentityView reporterView = viewResolver.resolveReporterIdentity(
                caller,
                entity.isAnonymous(),
                entity.getReporter().getId(),
                entity.getReporter().getFullName(),
                entity.getReporter().getEmail(),
                entity.getReporter().getDepartment()
        );

        // The property-level decision is recorded, and the identity-access
        // timestamps updated, only when the identity was actually handed over.
        // Recording the withheld case too is what the resolver documents, and it
        // matters for the reason FR-1.6 gives: an audit that cannot show identity
        // was suppressed cannot evidence that it was. Skipped here for non-single
        // responses, where the page-level summary covers it.
        if (entity.isAnonymous() && auditPropertyDecision) {
            recordReporterIdentityDecision(entity, caller, reporterView);
        }

        IncidentViews.BaseView baseView = new IncidentViews.BaseView(
                entity.getId(),
                "INC-" + entity.getId().toString().substring(0, 8).toUpperCase(),
                entity.getTitle(),
                entity.getDescription(),
                entity.getCategory().getName(),
                entity.getSeverity() != null ? entity.getSeverity().name() : null,
                entity.getStatus().name(),
                entity.isEscalated(),
                entity.getAffectedSystem(),
                entity.getAffectedDepartment(),
                entity.isAnonymous(),
                entity.isContainsPii(),
                entity.getReportedAt().toString(),
                entity.getOccurredAt().toString(),
                entity.getResolvedAt() != null ? entity.getResolvedAt().toString() : null,
                reporterView.reporterId(),
                reporterView.reporterDisplayName(),
                reporterView.reporterEmail(),
                entity.getAssignee() != null ? entity.getAssignee().getId() : null,
                entity.getAssignee() != null ? entity.getAssignee().getFullName() : null,
                entity.getGroup() != null ? entity.getGroup().getId() : null,
                collaboratorIds
        );

        // Fetch investigation notes, actions, and timeline if caller holds can_view_investigation_notes
        if (caller.permissions().canViewInvestigationNotes()) {
            List<ResponseActionEntity> actions = responseActionRepository.findByIncidentIdOrderByPerformedAtAsc(entity.getId());
            List<String> actionStrings = actions.stream()
                    .map(a -> a.getActionType() + ": " + a.getOutcome())
                    .toList();

            // 7.2.3 / FR-2.4: notes are loaded only on this branch, so a role
            // without the capability never reads them -- the alternative,
            // loading and then filtering, would put investigation findings for a
            // live incident into the response path of a caller entitled to none.
            // Internal only, and never mixed into the reporter-facing summary.
            List<String> noteStrings = noteRepository.findByIncidentIdOrderByCreatedAtAsc(entity.getId())
                    .stream()
                    .map(n -> n.getAuthor().getFullName() + ": " + n.getNote())
                    .toList();

            List<IncidentStatusHistoryEntity> histories = statusHistoryRepository.findByIncidentIdOrderByChangedAtAsc(entity.getId());
            List<IncidentViews.InvestigationView.TimelineEntry> timeline = histories.stream()
                    .map(h -> new IncidentViews.InvestigationView.TimelineEntry(
                            h.getFromStatus() != null ? h.getFromStatus().name() : null,
                            h.getToStatus().name(),
                            h.getChangedBy() != null ? h.getChangedBy().getFullName() : "system",
                            h.getChangedAt().toString(),
                            h.getReason()
                    ))
                    .toList();

            IncidentViewResolver.RestrictedContent restricted = new IncidentViewResolver.RestrictedContent(
                    noteStrings,
                    actionStrings,
                    timeline
            );

            return viewResolver.resolve(caller, baseView, restricted);
        }

        return baseView;
    }

    /**
     * 7.11 / FR-1.6: writes the property-level outcome for an anonymous report,
     * and, when the identity was revealed, stamps the restricted store with who
     * looked and when.
     *
     * <p>FR-1.6 requires that "every use of the permission to view an identity is
     * its own audited event", so a granted view is a distinct action from the
     * read that carried it. The {@code identity_accessed_at} /
     * {@code identity_accessed_by} columns exist for the same reason: a permitted
     * identity lookup is exactly the event a whistleblower-protection policy is
     * most likely to be asked about, and "the report is anonymous" is the answer
     * only if nothing ever looked.
     */
    private void recordReporterIdentityDecision(
            IncidentEntity entity, PlatformUser caller, IncidentViews.ReporterIdentityView reporterView) {

        boolean withheld = reporterView.identityWithheld();
        AuthorizationDecision decision = viewResolver.recordPropertyDecision(caller, true, withheld);
        UUID requestId = RequestContext.requestId().orElse(UUID.randomUUID());
        String remoteAddress = RequestContext.remoteAddress();
        String endpoint = "/api/v1/incidents/" + entity.getId();

        if (decision.denied()) {
            auditService.recordDenied(
                    caller,
                    decision.deniedReason(),
                    "incident",
                    entity.getId(),
                    "view_reporter_identity",
                    endpoint,
                    "GET",
                    requestId,
                    remoteAddress,
                    decision.checkType(),
                    decision.rule());
            return;
        }

        auditService.recordAllowed(
                caller,
                "incident",
                entity.getId(),
                "view_reporter_identity",
                endpoint,
                "GET",
                requestId,
                remoteAddress,
                decision.checkType(),
                decision.rule());

        reporterIdentityRepository.findByIncidentId(entity.getId()).ifPresent(identity -> {
            identity.setIdentityAccessedAt(OffsetDateTime.now(ZoneOffset.UTC));
            identity.setIdentityAccessedBy(caller.id());
            reporterIdentityRepository.save(identity);
        });
    }

    /**
     * One property-level row for a page of results.
     *
     * <p>A list is one authorization event, not one per row. Writing a row per
     * incident would put a hundred lines in the audit log describing a single GET
     * and would make the denial signal of 7.12 unreadable, so the count is
     * recorded instead and the individual incidents are identified by the list
     * action already written for the request.
     */
    private void auditPropertyDecisionForPage(PlatformUser caller, int anonymousCount) {
        if (anonymousCount == 0) {
            return;
        }
        UUID requestId = RequestContext.requestId().orElse(UUID.randomUUID());
        boolean withheld = !Capability.VIEW_REPORTER_IDENTITY.isHeldBy(caller.permissions());
        AuthorizationDecision decision = viewResolver.recordPropertyDecision(caller, true, withheld);

        if (decision.denied()) {
            auditService.recordDenied(
                    caller,
                    decision.deniedReason(),
                    "incident",
                    null,
                    "view_reporter_identity",
                    "/api/v1/incidents",
                    "GET",
                    requestId,
                    RequestContext.remoteAddress(),
                    decision.checkType(),
                    decision.rule());
            return;
        }
        auditService.recordAllowed(
                caller,
                "incident",
                null,
                "view_reporter_identity",
                "/api/v1/incidents",
                "GET",
                requestId,
                RequestContext.remoteAddress(),
                decision.checkType(),
                decision.rule());
    }

    /**
     * Serialises a value for the 7.11 {@code before_value} / {@code after_value}
     * columns.
     *
     * <p>Never propagates a failure. A value that will not serialise is an audit
     * detail, and {@code AuditService} is deliberately fail-open (see its javadoc
     * on why failing closed was rejected), so letting a serialisation problem
     * abort an incident write would contradict that decision and turn a logging
     * defect into an outage. The rows are nulled and the write proceeds.
     */
    private String toJson(Map<String, Object> value) {
        try {
            return json.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            return null;
        }
    }
}
