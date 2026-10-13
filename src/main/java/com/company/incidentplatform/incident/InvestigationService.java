package com.company.incidentplatform.incident;

import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.audit.RequestContext;
import com.company.incidentplatform.authorization.AuthorizationDeniedException;
import com.company.incidentplatform.authorization.Capability;
import com.company.incidentplatform.authorization.IncidentAccessGuard;
import com.company.incidentplatform.error.ResourceNotFoundException;
import com.company.incidentplatform.identity.AppUserEntity;
import com.company.incidentplatform.identity.AppUserRepository;
import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.PlatformUser;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * FR-2.4 notes, FR-2.5 response actions, FR-1.4/FR-2.8 comments -- the three
 * channels attached to an incident, with deliberately different visibility.
 *
 * <p>Every method here follows the same shape, and the shape is the point: the
 * object-level guard runs <em>before</em> the entity is loaded, so a caller who
 * is not entitled to the incident is refused without a lookup and without
 * learning whether it exists. Each write is audited with the rule that permitted
 * it, per 7.11.
 *
 * <p>7.10: each write is a single transaction, so an audit entry, a status
 * history row, and the entity change cannot be committed apart from one another.
 */
@Service
public class InvestigationService {

    private final IncidentRepository incidentRepository;
    private final InvestigationNoteRepository noteRepository;
    private final IncidentCommentRepository commentRepository;
    private final ResponseActionRepository responseActionRepository;
    private final AppUserRepository userRepository;
    private final IncidentAccessGuard accessGuard;
    private final AuditService auditService;
    private final Clock clock;

    public InvestigationService(
            IncidentRepository incidentRepository,
            InvestigationNoteRepository noteRepository,
            IncidentCommentRepository commentRepository,
            ResponseActionRepository responseActionRepository,
            AppUserRepository userRepository,
            IncidentAccessGuard accessGuard,
            AuditService auditService,
            Clock clock) {
        this.incidentRepository = incidentRepository;
        this.noteRepository = noteRepository;
        this.commentRepository = commentRepository;
        this.responseActionRepository = responseActionRepository;
        this.userRepository = userRepository;
        this.accessGuard = accessGuard;
        this.auditService = auditService;
        this.clock = clock;
    }

    /**
     * FR-2.4: an analyst-only, timestamped, attributable note.
     *
     * <p>Function level ({@code can_add_investigation_note}) is checked before
     * object level so the recorded 7.11 reason is the true one: an Auditor holds
     * read access to every incident but no write capability, and reporting
     * "not your incident" for that would point an administrator at the wrong
     * control entirely.
     */
    @Transactional
    public InvestigationViews.NoteView addNote(
            UUID incidentId, AddInvestigationNoteRequest request, PlatformUser caller) {

        accessGuard.requireWrite(caller, incidentId, Capability.ADD_INVESTIGATION_NOTE);
        IncidentEntity incident = requireIncident(incidentId);
        AppUserEntity author = requireUser(caller.id());

        OffsetDateTime now = OffsetDateTime.now(clock.withZone(ZoneOffset.UTC));
        InvestigationNoteEntity note = noteRepository.save(new InvestigationNoteEntity(
                UUID.randomUUID(),
                incident,
                author,
                request.note().trim(),
                now,
                request.containsPii()));

        auditService.recordAllowed(
                caller,
                "investigation_note",
                note.getId(),
                "create",
                "/api/v1/incidents/" + incidentId + "/notes",
                "POST",
                requestId(),
                RequestContext.remoteAddress(),
                AuthorizationCheckType.OBJECT_LEVEL,
                Capability.ADD_INVESTIGATION_NOTE.rule());

        return toNoteView(note);
    }

    /**
     * FR-2.5: a structured action, which is also FR-3.3's precondition for
     * resolution and Section 5.5's Command object.
     */
    @Transactional
    public InvestigationViews.ActionView recordResponseAction(
            UUID incidentId, RecordResponseActionRequest request, PlatformUser caller) {

        accessGuard.requireWrite(caller, incidentId, Capability.RECORD_RESPONSE_ACTION);
        IncidentEntity incident = requireIncident(incidentId);

        if (request.actionType().requiresDescription(request.description())) {
            throw new IllegalArgumentException(
                    "Action type 'OTHER' carries no information on its own; a description is required "
                            + "(FR-2.5)");
        }

        AppUserEntity performer = requireUser(caller.id());
        OffsetDateTime now = OffsetDateTime.now(clock.withZone(ZoneOffset.UTC));

        ResponseActionEntity action = responseActionRepository.save(new ResponseActionEntity(
                UUID.randomUUID(),
                incident.getId(),
                request.actionType().name(),
                trimToNull(request.description()),
                request.outcome().trim(),
                performer,
                now));

        auditService.recordAllowed(
                caller,
                "response_action",
                action.getId(),
                "create",
                "/api/v1/incidents/" + incidentId + "/actions",
                "POST",
                requestId(),
                RequestContext.remoteAddress(),
                AuthorizationCheckType.OBJECT_LEVEL,
                Capability.RECORD_RESPONSE_ACTION.rule());

        return toActionView(action);
    }

    /**
     * FR-1.4 / FR-2.8: the shared channel. Readable by exactly the people who may
     * see the incident, which is why it takes the object-level read gate rather
     * than a separate role rule.
     */
    @Transactional
    public InvestigationViews.CommentView addComment(
            UUID incidentId, AddCommentRequest request, PlatformUser caller) {

        accessGuard.requireWrite(caller, incidentId, Capability.ADD_COMMENT);
        IncidentEntity incident = requireIncident(incidentId);
        AppUserEntity author = requireUser(caller.id());

        OffsetDateTime now = OffsetDateTime.now(clock.withZone(ZoneOffset.UTC));
        IncidentCommentEntity comment = commentRepository.save(new IncidentCommentEntity(
                UUID.randomUUID(),
                incident,
                author,
                request.comment().trim(),
                now,
                request.containsPii()));

        auditService.recordAllowed(
                caller,
                "incident_comment",
                comment.getId(),
                "create",
                "/api/v1/incidents/" + incidentId + "/comments",
                "POST",
                requestId(),
                RequestContext.remoteAddress(),
                AuthorizationCheckType.OBJECT_LEVEL,
                Capability.ADD_COMMENT.rule());

        return toCommentView(comment, incident.getReporter().getId(), caller.id());
    }

    /**
     * The comment thread, oldest first.
     *
     * <p>Read-only, so the object-level <em>read</em> gate applies -- a role that
     * may read the incident may read the conversation about it. Notes are not
     * served here at all: {@code GET /notes} is a separate, capability-gated
     * endpoint, so a Reporter's client can never be handed the note list and
     * filter it client-side.
     */
    @Transactional(readOnly = true)
    public List<InvestigationViews.CommentView> listComments(UUID incidentId, PlatformUser caller) {
        accessGuard.requireRead(caller, incidentId);
        IncidentEntity incident = requireIncident(incidentId);

        auditService.recordAllowed(
                caller,
                "incident",
                incidentId,
                "list_comments",
                "/api/v1/incidents/" + incidentId + "/comments",
                "GET",
                requestId(),
                RequestContext.remoteAddress(),
                AuthorizationCheckType.OBJECT_LEVEL,
                "incident.read.comments");

        return commentRepository.findByIncidentIdOrderByCreatedAtAsc(incidentId).stream()
                .map(comment -> toCommentView(comment, incident.getReporter().getId(), caller.id()))
                .toList();
    }

    /**
     * FR-2.4 read side, gated on the notes permission.
     *
     * <p>Present so this endpoint and the investigation view assembled by
     * {@code IncidentService} cannot disagree about who may see notes: both test
     * {@code canViewInvestigationNotes()}. The object-level read gate runs first,
     * so a caller with the notes permission but no access to this particular
     * incident is refused for the more fundamental reason and the audit rule
     * says so.
     */
    @Transactional(readOnly = true)
    public List<InvestigationViews.NoteView> listNotes(UUID incidentId, PlatformUser caller) {
        accessGuard.requireRead(caller, incidentId);

        if (!caller.permissions().canViewInvestigationNotes()) {
            // VIEW_INCIDENT is the capability bound to the can_view_investigation_notes
            // key -- one permission with two accessors, which is why the check above
            // and the guard's rule string below cannot disagree.
            throw AuthorizationDeniedException.forMissingCapability(
                    Capability.VIEW_INCIDENT, "incident", incidentId);
        }

        // 7.11: reading internal investigation findings is recorded, for the same
        // reason the write is -- a note added to a live incident is exactly the
        // content whose later disclosure a compliance review would ask about.
        auditService.recordAllowed(
                caller,
                "incident",
                incidentId,
                "list_notes",
                "/api/v1/incidents/" + incidentId + "/notes",
                "GET",
                requestId(),
                RequestContext.remoteAddress(),
                AuthorizationCheckType.OBJECT_LEVEL,
                "capability.can_view_investigation_notes");

        return noteRepository.findByIncidentIdOrderByCreatedAtAsc(incidentId).stream()
                .map(this::toNoteView)
                .toList();
    }

    private IncidentEntity requireIncident(UUID incidentId) {
        return incidentRepository.findById(incidentId)
                .orElseThrow(() -> new ResourceNotFoundException("incident", incidentId));
    }

    private AppUserEntity requireUser(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("user", userId));
    }

    private InvestigationViews.NoteView toNoteView(InvestigationNoteEntity note) {
        return new InvestigationViews.NoteView(
                note.getId(),
                note.getAuthor().getFullName(),
                note.getNote(),
                note.getCreatedAt(),
                note.isContainsPii());
    }

    private InvestigationViews.ActionView toActionView(ResponseActionEntity action) {
        String code;
        try {
            code = ResponseActionType.valueOf(action.getActionType()).code();
        } catch (IllegalArgumentException unknown) {
            // A vocabulary entry retired after the row was written. The stored
            // text is still the record of what happened, so it is returned
            // rather than the request being failed.
            code = "unrecognised";
        }
        return new InvestigationViews.ActionView(
                action.getId(),
                action.getActionType(),
                code,
                action.getDescription(),
                action.getOutcome(),
                action.getPerformedBy().getFullName(),
                action.getPerformedAt());
    }

    private InvestigationViews.CommentView toCommentView(
            IncidentCommentEntity comment, UUID reporterId, UUID readerId) {
        return new InvestigationViews.CommentView(
                comment.getId(),
                comment.getAuthor().getFullName(),
                comment.getComment(),
                comment.getCreatedAt(),
                comment.isContainsPii(),
                comment.getAuthor().getId().equals(reporterId));
    }

    private static String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static UUID requestId() {
        return RequestContext.requestId().orElse(null);
    }
}
