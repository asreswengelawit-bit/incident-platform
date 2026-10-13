package com.company.incidentplatform.incident;

import java.util.Locale;

/**
 * FR-2.5 -- the structured Response Action vocabulary.
 *
 * <p>Section 5.5 models each recorded action as a Command with its own outcome
 * and audit trail, "making it straightforward to later trigger some of them
 * automatically (SOAR integration, Section 13)". A closed vocabulary is what
 * makes that possible: an automated responder needs to be able to key off
 * {@code ISOLATE_ENDPOINT} as a known command rather than parsing prose, and
 * analytics need a countable action type rather than free text.
 *
 * <p>{@code V6} records the matching database position: the column is free text
 * so adding a command needs no migration, "constrained to a known set by the
 * service layer". This enum is that constraint, and it is the Service layer
 * rather than a CHECK constraint so the list can grow without a schema change --
 * the extensibility 5.5 asks for, kept in one reviewable place.
 */
public enum ResponseActionType {

    /** "Blocked sender domain" -- Section 3.2 FR-2.5's own example. */
    BLOCK_SENDER_DOMAIN("Blocked sender domain"),

    /** "Reset user credentials" -- FR-2.5's example. */
    RESET_USER_CREDENTIALS("Reset user credentials"),

    /** "Isolated endpoint" -- FR-2.5's example. */
    ISOLATE_ENDPOINT("Isolated endpoint"),

    REVOKE_ACTIVE_SESSIONS("Revoke active sessions"),
    DISABLE_ACCOUNT("Disable account"),
    REMOVE_MALWARE("Remove malware from system"),
    APPLY_SECURITY_PATCH("Apply security patch"),
    NOTIFY_THIRD_PARTY("Notify third party / external contacts"),
    COLLECT_ADDITIONAL_EVIDENCE("Collect additional evidence"),

    /**
     * An action outside the vocabulary.
     *
     * <p>Permitted, but only with a description: a bare OTHER tells a reviewer
     * nothing and would let a caller sidestep the structured record FR-2.5
     * requires while still satisfying the "at least one Response Action" gate on
     * FR-3.3's closure path. {@link #requiresDescription(String)} is enforced in
     * the service layer at write time.
     */
    OTHER("Other (described)");

    private final String displayName;

    ResponseActionType(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }

    /** The wire value: the enum constant, uppercase and underscored. */
    public String code() {
        return name().toLowerCase(Locale.ROOT);
    }

    /**
     * True when a description is mandatory, because the type itself carries no
     * information.
     */
    public boolean requiresDescription(String description) {
        return this == OTHER && (description == null || description.isBlank());
    }
}
