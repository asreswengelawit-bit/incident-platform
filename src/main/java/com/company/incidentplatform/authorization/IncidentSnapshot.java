package com.company.incidentplatform.authorization;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/**
 * The minimal projection of an incident required to make a Section 7.2
 * object-level decision.
 *
 * <p>Deliberately a plain record rather than the JPA entity. The authorizer is
 * the single most security-critical piece of logic in the platform, and it needs
 * to be exhaustively unit-testable without a container, a schema, or a database
 * -- a test that proves "Analyst A cannot read Analyst B's incident" should be
 * a five-line test, not an integration test with fixtures.
 *
 * <p>It also keeps the authorization layer honest about its own dependencies:
 * if a decision cannot be made from these fields, the decision does not belong
 * here. Anything more would mean the check is being made against data the
 * caller could have influenced.
 */
public record IncidentSnapshot(
        UUID id,
        UUID reporterId,
        String reporterDepartment,
        String affectedDepartment,
        UUID assigneeId,
        UUID groupId,
        boolean softDeleted,
        Set<UUID> collaboratorUserIds) {

    public IncidentSnapshot {
        collaboratorUserIds = collaboratorUserIds == null
                ? Set.of()
                : Collections.unmodifiableSet(new LinkedHashSet<>(collaboratorUserIds));
    }

    /**
     * The department that governs queue visibility, per the confirmed
     * department-precedence decision.
     *
     * <p>{@code affected_department} is the authority. When intake could not
     * determine it, the incident queues under the <em>reporter's</em> department
     * so it is not orphaned, and triage corrects it as an audited change. This
     * method is that fallback expressed as a single definition, so the queue
     * query and the object-level check cannot disagree about which department
     * an incident belongs to.
     */
    public String effectiveDepartment() {
        if (affectedDepartment != null && !affectedDepartment.isBlank()) {
            return affectedDepartment;
        }
        return reporterDepartment;
    }

    public boolean isUnassigned() {
        return assigneeId == null;
    }

    public boolean isCollaborator(UUID userId) {
        return userId != null && collaboratorUserIds.contains(userId);
    }
}
