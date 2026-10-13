package com.company.incidentplatform.error;

/**
 * The request cannot be completed as asked because of the current state of the
 * resource, and retrying the same request unchanged will fail again.
 *
 * <p>Two distinct situations share a 409, which is what 7.10 asks for:
 * an optimistic-lock conflict ("this incident changed, please refresh") and an
 * assignment race that a second analyst won first. Both are concurrency
 * outcomes, both are expected under load, and neither is a client error worth
 * retrying blindly -- but the client must be able to tell them apart from a 422
 * (the request itself violates 8.2) and from a 400.
 */
public class ConflictException extends RuntimeException {

    public ConflictException(String message) {
        super(message);
    }

    public ConflictException(String message, Throwable cause) {
        super(message, cause);
    }
}
