package com.company.incidentplatform.identity;

import com.company.incidentplatform.security.PlatformRole;
import java.util.UUID;

/**
 * The result of an {@link AdminUserCommand}.
 *
 * <p>7.2 property level: an admin command is not an identity dump. This carries the
 * fields the caller just changed plus the coarse role, and deliberately omits
 * {@code email} and {@code full_name} even though the caller is an administrator --
 * 7.4 treats both as personal data, and an admin who needs to know who a user is
 * already has the directory. A write endpoint that returns the whole row teaches
 * clients to cache it.
 *
 * <p>{@code capability} and {@code capabilityGranted} are populated only for
 * GRANT/REVOKE, and {@code version} only for UPDATE_USER, so a caller can tell which
 * half of the union it received without inspecting the operation string.
 */
public record AdminUserOutcome(
        String operation,
        UUID userId,
        PlatformRole coarseRole,
        String department,
        boolean active,
        int version,
        String capability,
        boolean capabilityGranted) {
}
