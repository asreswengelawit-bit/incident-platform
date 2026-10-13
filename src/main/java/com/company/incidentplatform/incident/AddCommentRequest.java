package com.company.incidentplatform.incident;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * FR-1.4 (Reporter follow-up) / FR-2.8 (Analyst request for more information).
 *
 * <p>There is no direction field and deliberately no visibility flag. The
 * document defines one shared channel between the reporter and the investigating
 * team; inventing per-comment visibility would create a way for a comment to be
 * written that the other party cannot see, which serves no requirement and
 * invites a Reporter assuming an analyst has seen something they have not.
 */
public record AddCommentRequest(
        @NotBlank(message = "Comment text is required")
        @Size(max = 10000, message = "Comment exceeds the maximum length")
        String comment,

        boolean containsPii) {
}
