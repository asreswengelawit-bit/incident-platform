package com.company.incidentplatform.incident;

import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.web.CurrentUser;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Section 9: the three investigation channels hanging off an incident.
 *
 * <p>Grouped on one controller because they share a parent and a shape -- a
 * write endpoint and, where reading is allowed, its read counterpart -- but they
 * are not interchangeable, and the differences are the point:
 *
 * <ul>
 *   <li>{@code /notes} is analyst-only in both directions (FR-2.4),</li>
 *   <li>{@code /actions} is write-only here because an action list is delivered
 *       as part of the incident's investigation view, and</li>
 *   <li>{@code /comments} is the shared channel a Reporter may read and write
 *       (FR-1.4, FR-2.8).</li>
 * </ul>
 *
 * <p>Authorization is not re-decided in any of them. Each call is routed through
 * {@link InvestigationService}, which consults the 7.2 guard, and a role that
 * lacks the capability is refused there with the audit entry 7.11 requires.
 */
@RestController
@RequestMapping("/api/v1/incidents/{incidentId}")
public class InvestigationController {

    private final InvestigationService investigationService;

    public InvestigationController(InvestigationService investigationService) {
        this.investigationService = investigationService;
    }

    /** FR-2.4: record an investigation note. */
    @PostMapping("/notes")
    @ResponseStatus(HttpStatus.CREATED)
    InvestigationViews.NoteView addNote(
            @PathVariable UUID incidentId,
            @Valid @RequestBody AddInvestigationNoteRequest request,
            @CurrentUser PlatformUser caller) {

        return investigationService.addNote(incidentId, request, caller);
    }

    /** FR-2.4: the note history, for roles holding the notes capability. */
    @GetMapping("/notes")
    List<InvestigationViews.NoteView> listNotes(
            @PathVariable UUID incidentId,
            @CurrentUser PlatformUser caller) {

        return investigationService.listNotes(incidentId, caller);
    }

    /** FR-2.5: record a structured response action. */
    @PostMapping("/actions")
    @ResponseStatus(HttpStatus.CREATED)
    InvestigationViews.ActionView recordAction(
            @PathVariable UUID incidentId,
            @Valid @RequestBody RecordResponseActionRequest request,
            @CurrentUser PlatformUser caller) {

        return investigationService.recordResponseAction(incidentId, request, caller);
    }

    /** FR-1.4 / FR-2.8: the shared comment thread. */
    @PostMapping("/comments")
    @ResponseStatus(HttpStatus.CREATED)
    InvestigationViews.CommentView addComment(
            @PathVariable UUID incidentId,
            @Valid @RequestBody AddCommentRequest request,
            @CurrentUser PlatformUser caller) {

        return investigationService.addComment(incidentId, request, caller);
    }

    @GetMapping("/comments")
    List<InvestigationViews.CommentView> listComments(
            @PathVariable UUID incidentId,
            @CurrentUser PlatformUser caller) {

        return investigationService.listComments(incidentId, caller);
    }
}
