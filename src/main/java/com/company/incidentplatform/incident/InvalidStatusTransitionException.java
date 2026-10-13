package com.company.incidentplatform.incident;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Section 8.2: Any transition attempt not listed in the transition matrix is
 * rejected with 409/422 and logged as a denied action per Section 7.11.
 */
@ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
public class InvalidStatusTransitionException extends RuntimeException {

    private final IncidentStatus fromStatus;
    private final IncidentStatus toStatus;

    public InvalidStatusTransitionException(String message) {
        super(message);
        this.fromStatus = null;
        this.toStatus = null;
    }

    public InvalidStatusTransitionException(
            IncidentStatus fromStatus, IncidentStatus toStatus, String reason) {
        super(String.format("Invalid status transition from %s to %s: %s", fromStatus, toStatus, reason));
        this.fromStatus = fromStatus;
        this.toStatus = toStatus;
    }

    public IncidentStatus getFromStatus() {
        return fromStatus;
    }

    public IncidentStatus getToStatus() {
        return toStatus;
    }
}
