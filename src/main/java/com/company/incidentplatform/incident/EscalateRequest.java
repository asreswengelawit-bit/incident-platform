package com.company.incidentplatform.incident;

import jakarta.validation.constraints.NotBlank;

/**
 * FR-2.7 / Section 8.1 escalation request.
 */
public record EscalateRequest(
        @NotBlank(message = "Escalation reason is required")
        String reason
) {}
