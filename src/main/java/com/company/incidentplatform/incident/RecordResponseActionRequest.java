package com.company.incidentplatform.incident;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * FR-2.5: record a structured Response Action.
 *
 * <p>{@code outcome} is required rather than optional because an action whose
 * result was never recorded is not evidence of containment -- and FR-3.3 lets
 * the mere existence of an action gate resolution, so an unrecorded outcome
 * would let an incident be marked Resolved on the strength of an attempt nobody
 * confirmed.
 */
public record RecordResponseActionRequest(
        @NotNull(message = "Action type is required")
        ResponseActionType actionType,

        @Size(max = 4000, message = "Description exceeds the maximum length")
        String description,

        @NotBlank(message = "Outcome is required")
        @Size(max = 2000, message = "Outcome exceeds the maximum length")
        String outcome) {
}
