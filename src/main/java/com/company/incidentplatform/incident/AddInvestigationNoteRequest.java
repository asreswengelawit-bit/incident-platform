package com.company.incidentplatform.incident;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * FR-2.4: record an investigation note.
 *
 * <p>Notes are append-only and have no update or delete endpoint, matching
 * FR-1.4's evidentiary-integrity principle for the report itself and FR-2.4's
 * "timestamped and attributable" requirement: a note that could be edited would
 * attribute a possibly-different thought to its author.
 */
public record AddInvestigationNoteRequest(
        @NotBlank(message = "Note text is required")
        @Size(max = 20000, message = "Note exceeds the maximum length")
        String note,

        /** 7.4: flagged for the FR-5.3 redaction option, not used to redact. */
        boolean containsPii) {
}
