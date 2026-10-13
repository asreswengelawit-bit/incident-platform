package com.company.incidentplatform.incident;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

/**
 * FR-2.3 assignment/reassignment request.
 */
public record AssignIncidentRequest(
        @NotNull(message = "Assignee user ID is required")
        UUID assigneeId
) {}
