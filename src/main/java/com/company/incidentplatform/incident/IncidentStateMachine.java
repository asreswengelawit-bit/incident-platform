package com.company.incidentplatform.incident;

import com.company.incidentplatform.identity.AppUserEntity;
import com.company.incidentplatform.security.PlatformRole;
import com.company.incidentplatform.security.PlatformUser;
import org.springframework.stereotype.Component;

/**
 * Section 8.2 -- Incident status workflow state machine.
 *
 * <p>Enforces the exact transition matrix from Section 8.2: evaluates
 * (current-state, next-state, role) and all additional preconditions (maker-checker,
 * required reasons, response action count).
 *
 * <h2>Security Administrator is not in this matrix</h2>
 *
 * <p>8.2 says so explicitly: "Security Administrator is deliberately absent from
 * this table (explicit, not an oversight): Admin's role is platform
 * administration -- users, categories, SLA config, audit review -- not
 * incident-workflow execution, and 7.1/7.3 require Admin not hold blanket
 * override authority over the maker-checker gates above."
 *
 * <p>That is why no {@code assertRole} call below includes
 * {@link PlatformRole#SECURITY_ADMIN}, and why there is no "or Admin" escape
 * hatch on the Lead-only edges. 8.2 anticipates the need it is refusing --
 * "if a genuine emergency-override need surfaces later (Lead unreachable,
 * incident stuck), that requires a separate, explicitly named and
 * separately-audited override capability with its own sign-off" -- so an override
 * would be a new, logged, attributable capability, not a role added to this
 * switch. Adding Admin here would make the maker-checker self-approvable by the
 * same person who configured the roles, which is precisely the 7.3 control this
 * class exists to hold.
 */
@Component
public class IncidentStateMachine {

    public void validateTransition(
            IncidentEntity incident,
            IncidentStatus nextStatus,
            PlatformUser caller,
            TransitionContext context) {

        IncidentStatus current = incident.getStatus();
        if (current == nextStatus) {
            throw new InvalidStatusTransitionException(current, nextStatus, "Incident is already in status " + current);
        }

        switch (current) {
            case NEW -> validateFromNew(incident, nextStatus, caller, context);
            case TRIAGED -> validateFromTriaged(incident, nextStatus, caller, context);
            case ASSIGNED -> validateFromAssigned(incident, nextStatus, caller);
            case INVESTIGATING -> validateFromInvestigating(incident, nextStatus, caller);
            case CONTAINED -> validateFromContained(incident, nextStatus, caller, context);
            case RESOLVED -> validateFromResolved(incident, nextStatus, caller, context);
            case CLOSED -> validateFromClosed(nextStatus, caller, context);
            case REOPENED -> validateFromReopened(nextStatus, caller);
            case REJECTED -> throw new InvalidStatusTransitionException(
                    current, nextStatus, "Incident is in terminal state REJECTED and cannot be transitioned");
        }
    }

    private void validateFromNew(
            IncidentEntity incident, IncidentStatus next, PlatformUser caller, TransitionContext context) {
        if (next == IncidentStatus.TRIAGED) {
            // 8.2: "Analyst, Lead". No Admin -- see the class javadoc.
            assertRole(caller, PlatformRole.ANALYST, PlatformRole.SECURITY_LEAD);
            // FR-2.2 / 12.2 / 8.2: "triaging *is* the act of classifying, so this
            // is supplied atomically with the transition". newSeverity() is the
            // matrix result of the impact and likelihood the caller supplied --
            // it is computed, never chosen. Requiring it here is what makes an
            // incident unclassifiable-but-triaged impossible.
            if (context.newSeverity() == null && incident.getSeverity() == null) {
                throw new InvalidStatusTransitionException(
                        IncidentStatus.NEW, IncidentStatus.TRIAGED,
                        "Impact and likelihood are required to triage an incident: severity is computed from "
                                + "the configured matrix, not chosen (FR-2.2, Section 12.2)");
            }
            return;
        }
        throw new InvalidStatusTransitionException(
                IncidentStatus.NEW, next, "New incidents can only transition to TRIAGED");
    }

    private void validateFromTriaged(
            IncidentEntity incident, IncidentStatus next, PlatformUser caller, TransitionContext context) {
        // 8.2: "Analyst, Lead" on both edges out of TRIAGED.
        assertRole(caller, PlatformRole.ANALYST, PlatformRole.SECURITY_LEAD);

        if (next == IncidentStatus.ASSIGNED) {
            AppUserEntity assignee = context.targetAssignee();
            if (assignee == null) {
                throw new InvalidStatusTransitionException(
                        IncidentStatus.TRIAGED, IncidentStatus.ASSIGNED, "Target assignee must be specified");
            }
            if (!assignee.isActive()) {
                throw new InvalidStatusTransitionException(
                        IncidentStatus.TRIAGED, IncidentStatus.ASSIGNED, "Assignee must be an active user");
            }
            PlatformRole assigneeRole = assignee.coarseRole();
            // 8.2 says "Assignee must be an active Analyst". A Security Lead is a
            // senior analyst (Section 2: "All analyst rights + ..."), so taking
            // an assignment is consistent with the role; an Admin is not, and
            // 8.2 keeps Admin out of incident-workflow execution entirely.
            if (assigneeRole != PlatformRole.ANALYST
                    && assigneeRole != PlatformRole.SECURITY_LEAD) {
                throw new InvalidStatusTransitionException(
                        IncidentStatus.TRIAGED, IncidentStatus.ASSIGNED,
                        "Assignee must hold an Analyst or Lead role (Section 8.2)");
            }
            return;
        }

        if (next == IncidentStatus.REJECTED) {
            if (context.reason() == null || context.reason().isBlank()) {
                throw new InvalidStatusTransitionException(
                        IncidentStatus.TRIAGED, IncidentStatus.REJECTED, "Rejection reason is required");
            }
            return;
        }

        throw new InvalidStatusTransitionException(
                IncidentStatus.TRIAGED, next, "Triaged incidents can only transition to ASSIGNED or REJECTED");
    }

    private void validateFromAssigned(IncidentEntity incident, IncidentStatus next, PlatformUser caller) {
        if (next == IncidentStatus.INVESTIGATING) {
            // Section 8.2: The assigned Analyst only
            if (incident.getAssignee() == null || !incident.getAssignee().getId().equals(caller.id())) {
                throw new InvalidStatusTransitionException(
                        IncidentStatus.ASSIGNED, IncidentStatus.INVESTIGATING,
                        "Only the assigned analyst can start investigation");
            }
            return;
        }
        throw new InvalidStatusTransitionException(
                IncidentStatus.ASSIGNED, next, "Assigned incidents can only transition to INVESTIGATING");
    }

    private void validateFromInvestigating(IncidentEntity incident, IncidentStatus next, PlatformUser caller) {
        if (next == IncidentStatus.CONTAINED) {
            assertAssignedAnalystOrLead(incident, caller);
            return;
        }
        throw new InvalidStatusTransitionException(
                IncidentStatus.INVESTIGATING, next, "Investigating incidents can only transition to CONTAINED");
    }

    private void validateFromContained(
            IncidentEntity incident, IncidentStatus next, PlatformUser caller, TransitionContext context) {
        if (next == IncidentStatus.RESOLVED) {
            assertAssignedAnalystOrLead(incident, caller);
            // FR-3.3 / 8.2: >= 1 Response Action recorded + resolution summary
            if (context.responseActionCount() < 1) {
                throw new InvalidStatusTransitionException(
                        IncidentStatus.CONTAINED, IncidentStatus.RESOLVED,
                        "At least one Response Action must be recorded before an incident can be resolved (FR-3.3)");
            }
            String summary = context.resolutionSummary() != null
                    ? context.resolutionSummary() : incident.getResolutionSummary();
            if (summary == null || summary.isBlank()) {
                throw new InvalidStatusTransitionException(
                        IncidentStatus.CONTAINED, IncidentStatus.RESOLVED,
                        "Resolution summary is required to resolve an incident (FR-3.3)");
            }
            return;
        }
        throw new InvalidStatusTransitionException(
                IncidentStatus.CONTAINED, next, "Contained incidents can only transition to RESOLVED");
    }

    private void validateFromResolved(
            IncidentEntity incident, IncidentStatus next, PlatformUser caller, TransitionContext context) {
        if (next == IncidentStatus.CLOSED) {
            IncidentSeverity severity = incident.getSeverity();
            if (severity == null) {
                severity = IncidentSeverity.LOW;
            }

            if (severity.isMediumOrHigher()) {
                // 8.2: "Lead (Medium/High/Critical)". Admin is excluded on
                // purpose -- see the class javadoc.
                assertRole(caller, PlatformRole.SECURITY_LEAD);

                // Section 7.3 Maker-Checker: The analyst who investigates a Medium+
                // severity incident cannot be the sole approver of its closure.
                if (incident.getAssignee() != null && incident.getAssignee().getId().equals(caller.id())) {
                    throw new InvalidStatusTransitionException(
                            IncidentStatus.RESOLVED, IncidentStatus.CLOSED,
                            "Maker-checker violation (Section 7.3): The investigating analyst cannot approve closure of a Medium+ severity incident");
                }
            } else {
                // 8.2: "Analyst (Low)". Still no Admin: Low severity removes the
                // Lead sign-off requirement, not the role boundary.
                assertRole(caller, PlatformRole.ANALYST, PlatformRole.SECURITY_LEAD);
            }

            if (incident.getResolutionSummary() == null && (context.resolutionSummary() == null || context.resolutionSummary().isBlank())) {
                throw new InvalidStatusTransitionException(
                        IncidentStatus.RESOLVED, IncidentStatus.CLOSED, "Resolution summary is required for closure");
            }
            return;
        }

        if (next == IncidentStatus.REOPENED) {
            // 8.2: "Analyst, Lead" from RESOLVED, and it notifies Admin rather
            // than granting Admin the transition.
            assertRole(caller, PlatformRole.ANALYST, PlatformRole.SECURITY_LEAD);
            if (context.reason() == null || context.reason().isBlank()) {
                throw new InvalidStatusTransitionException(
                        IncidentStatus.RESOLVED, IncidentStatus.REOPENED, "Reopen reason is required");
            }
            return;
        }

        throw new InvalidStatusTransitionException(
                IncidentStatus.RESOLVED, next, "Resolved incidents can only transition to CLOSED or REOPENED");
    }

    private void validateFromClosed(IncidentStatus next, PlatformUser caller, TransitionContext context) {
        if (next == IncidentStatus.REOPENED) {
            // 8.2: "Closed -> Reopened: Lead only; Reopen reason required;
            // notifies Admin". The narrowest edge in the matrix, and 8.2's own
            // worked example of a role boundary being drawn on purpose.
            assertRole(caller, PlatformRole.SECURITY_LEAD);
            if (context.reason() == null || context.reason().isBlank()) {
                throw new InvalidStatusTransitionException(
                        IncidentStatus.CLOSED, IncidentStatus.REOPENED, "Reopen reason is required");
            }
            return;
        }
        throw new InvalidStatusTransitionException(
                IncidentStatus.CLOSED, next, "Closed incidents can only transition to REOPENED (Lead only)");
    }

    private void validateFromReopened(IncidentStatus next, PlatformUser caller) {
        if (next == IncidentStatus.INVESTIGATING) {
            assertRole(caller, PlatformRole.ANALYST, PlatformRole.SECURITY_LEAD);
            return;
        }
        throw new InvalidStatusTransitionException(
                IncidentStatus.REOPENED, next, "Reopened incidents can only transition to INVESTIGATING");
    }

    private void assertRole(PlatformUser caller, PlatformRole... allowed) {
        for (PlatformRole role : allowed) {
            if (caller.role() == role) {
                return;
            }
        }
        throw new InvalidStatusTransitionException(
                "Role " + caller.role() + " is not authorized to perform this status transition");
    }

    private void assertAssignedAnalystOrLead(IncidentEntity incident, PlatformUser caller) {
        // Lead only, and deliberately not Admin. The previous version of this
        // method let SECURITY_ADMIN through, which quietly re-opened the same
        // hole the rest of this class was written to close: an Admin could drive
        // a Medium+ incident to RESOLVED and then take it to CONTAINED-side
        // transitions, bypassing the maker-checker that 7.3 requires on closure.
        // Admin's authority over incidents is read access and configuration; the
        // workflow belongs to the people accountable for running it.
        if (caller.role() == PlatformRole.SECURITY_LEAD) {
            return;
        }
        if (incident.getAssignee() != null && incident.getAssignee().getId().equals(caller.id())) {
            return;
        }
        throw new InvalidStatusTransitionException(
                "Only the assigned analyst or a Security Lead can perform this transition");
    }

    public record TransitionContext(
            IncidentSeverity newSeverity,
            AppUserEntity targetAssignee,
            String reason,
            String resolutionSummary,
            long responseActionCount) {

        public static TransitionContext empty() {
            return new TransitionContext(null, null, null, null, 0);
        }
    }
}
