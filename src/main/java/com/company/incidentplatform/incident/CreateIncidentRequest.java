package com.company.incidentplatform.incident;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * FR-1.1: Incident creation request.
 */
public record CreateIncidentRequest(
        @NotBlank(message = "Title is required")
        String title,

        @NotBlank(message = "Description is required")
        String description,

        @NotNull(message = "Category is required")
        UUID categoryId,

        // Optional self-assessed severity (FR-1.1)
        IncidentSeverity severity,

        OffsetDateTime occurredAt,

        String affectedSystem,

        @Size(max = 120, message = "Affected department must be at most 120 characters")
        String affectedDepartment,

        // FR-1.6 anonymous / whistleblower mode
        boolean anonymous,

        boolean containsPii
) {}
