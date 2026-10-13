package com.company.incidentplatform.identity;

import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.audit.RequestContext;
import com.company.incidentplatform.authorization.AuthorizationDeniedException;
import com.company.incidentplatform.authorization.Capability;
import com.company.incidentplatform.error.ConflictException;
import com.company.incidentplatform.error.LastAdministratorException;
import com.company.incidentplatform.error.ResourceNotFoundException;
import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.CurrentUserStateService;
import com.company.incidentplatform.security.PlatformRole;
import com.company.incidentplatform.security.PlatformUser;
import java.time.Clock;
import java.util.Locale;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Section 9 {@code POST /api/v1/admin/users} -- "Manage users/roles" -- restricted to
 * the fine-grained authorization layer.
 *
 * <h2>What this endpoint deliberately cannot do</h2>
 *
 * <p>It cannot change a coarse role. Section 6.2 item 4 is explicit that
 * {@code app_user.role_id} is synced from Keycloak and that the application's copy
 * follows the IdP, never the reverse, precisely so the two systems cannot drift into
 * competing sources of truth. Writing a role here would not be a missing feature; it
 * would be the failure mode the decision was taken to prevent. Requests that try are
 * refused with an explanation rather than ignored, so an admin who attempts it learns
 * where the change belongs instead of believing it succeeded.
 *
 * <p>There is no Keycloak write-through here either. The IdP's admin API needs a
 * service client and credentials this project does not carry, and inventing that is a
 * larger and separately-reviewable change than an admin endpoint. So the coarse role
 * is changed in Keycloak and picked up by the existing sync, which is the documented
 * path.
 *
 * <h2>What it does do</h2>
 *
 * <ul>
 *   <li><b>6.2.3 department scoping</b> -- a user's home department, which decides
 *       which unassigned incidents an Analyst may see.</li>
 *   <li><b>7.1 lifecycle</b> -- disable and re-enable an account, with the mandatory
 *       reason. Disabling is a per-request authorization fact, not a token problem:
 *       {@code CurrentUserStateService} consults {@code active} on every request, so
 *       the effect is immediate rather than waiting for token expiry.</li>
 *   <li><b>6.2.3 / FR-1.6 capability grants</b> -- grant or revoke one capability on
 *       one role. This is the operation Section 2's confirmed decision describes:
 *       the Security Administrator explicitly grants {@code can_view_reporter_identity}
 *       as a deliberate, audited act, because {@code V12} seeds it false for every role
 *       so it is never an implicit power of Admin.</li>
 * </ul>
 *
 * <h2>The last-administrator invariant (FR-6.1)</h2>
 *
 * <p>The active user count holding {@code can_manage_users} must never reach zero. Any
 * role change, disable, or deprovisioning that would do so is rejected outright, on
 * every path in this class that can remove a holder -- a user disable and a capability
 * revoke.
 *
 * <p>Two consequences are load-bearing, and neither is obvious:
 *
 * <ol>
 *   <li><b>It is not a count-then-write check.</b> The predicate spans rows, and
 *       row-level locking cannot help because racing operations touch <em>different</em>
 *       rows -- two admins each disabling a different remaining administrator, or the
 *       same capability revoked from two different roles. Each would pass the count
 *       and each would commit. So every authorization change here first takes a
 *       transaction-scoped advisory lock, which serialises them against each other.
 *       It is taken <em>after</em> the capability check, so a denied caller cannot
 *       block legitimate admin work.</li>
 *   <li><b>It is not a version conflict.</b> Retrying the identical request fails
 *       identically forever, so it is reported as
 *       {@link LastAdministratorException} -- 409 with its own code and a message that
 *       states the recovery step -- rather than through {@code ConflictException},
 *       whose body tells the caller to reload and reapply.</li>
 * </ol>
 *
 * <p>The check counts active users rather than hard-coding "the SECURITY_ADMIN role",
 * so it stays correct as roles and headcount change.
 *
 * <h2>7.10 conflict reporting, for the changes that are genuinely races</h2>
 *
 * <p>A stale {@code expectedVersion} is reported as a conflict and never retried. Two
 * admins editing one user's permissions is a conversation; silently winning the race
 * is how a revoked capability comes back.
 */
@Service
public class AdminUserService {

    /** 7.11 action names, kept distinct so a reviewer can filter for permission changes alone. */
    public static final String ACTION_USER_UPDATE = "admin.user.update";
    public static final String ACTION_CAPABILITY_GRANT = "admin.role.capability_grant";
    public static final String ACTION_CAPABILITY_REVOKE = "admin.role.capability_revoke";

    private static final String ENDPOINT = "/api/v1/admin/users";
    private static final String ENTITY_USER = "app_user";
    private static final String ENTITY_ROLE = "platform_role";

    /**
     * The one capability whose absence locks everyone out of this endpoint, and so the
     * one the last-holder guard watches.
     */
    private static final String MANAGE_USERS_KEY = Capability.MANAGE_USERS.permissionKey();

    private final AdminUserStore store;
    private final AuditService audit;
    private final CurrentUserStateService userState;
    private final Clock clock;

    public AdminUserService(
            AdminUserStore store, AuditService audit, CurrentUserStateService userState, Clock clock) {
        this.store = store;
        this.audit = audit;
        this.userState = userState;
        this.clock = clock;
    }

    @Transactional
    public AdminUserOutcome apply(AdminUserCommand command, PlatformUser caller) {
        String operation = normaliseOperation(command.operation());
        return switch (operation) {
            case AdminUserCommand.OP_UPDATE_USER -> updateUser(command, caller);
            case AdminUserCommand.OP_GRANT_CAPABILITY -> changeCapability(command, caller, true);
            case AdminUserCommand.OP_REVOKE_CAPABILITY -> changeCapability(command, caller, false);
            default -> throw new IllegalArgumentException(unknownOperation(operation));
        };
    }

    /**
     * 6.2.3 and 7.10 -- serialises an authorization change against every other one.
     *
     * <p>Taken after the capability check and before any state is read, so that the
     * last-administrator guard and the write that follows it are atomic with respect
     * to concurrent admin changes. Without it, two admins disabling each other, or
     * revoking the same capability from two different roles, could each pass the
     * count and each commit -- leaving a deployment that no longer has anyone who can
     * grant the capability back, and no Keycloak write-through to recover with.
     */
    private void serialiseAgainstConcurrentAdminChanges() {
        store.lockAuthorizationChanges();
    }

    // ------------------------------------------------------------------ user

    private AdminUserOutcome updateUser(AdminUserCommand command, PlatformUser caller) {
        requireManageUsers(caller, ENTITY_USER, command.userId());
        // Refused, not ignored. See AdminUserCommand: an undeclared field would be
        // dropped silently and the admin would think a role had changed.
        if (command.role() != null && !command.role().isBlank()) {
            throw new IllegalArgumentException(
                    "The coarse role cannot be changed through this endpoint. Section 6.2.1 makes Keycloak the "
                            + "source of truth for the coarse role and app_user.role_id a projection synced from "
                            + "it, so writing it here would create the second source of truth that decision "
                            + "exists to prevent. Change the role in Keycloak and it will be picked up by the "
                            + "existing sync. Department, lifecycle and fine-grained capabilities are managed "
                            + "here.");
        }

        UUID userId = command.userId();
        if (userId == null) {
            throw new IllegalArgumentException("userId is required for " + AdminUserCommand.OP_UPDATE_USER);
        }
        if (command.expectedVersion() == null) {
            // 7.10. Not optional: a user update is a security change, and an
            // unversioned one silently discards a concurrent admin's decision.
            throw new IllegalArgumentException(
                    "expectedVersion is required for " + AdminUserCommand.OP_UPDATE_USER
                            + " (Section 7.10 optimistic locking)");
        }
        if (command.department() == null && command.active() == null) {
            throw new IllegalArgumentException(
                    "Nothing to change: supply department and/or active");
        }

        // After validation, before the state is read: the invariant below spans rows,
        // so it must be evaluated under a lock that also covers the write.
        serialiseAgainstConcurrentAdminChanges();

        AdminUserStore.UserState before = store.findUser(userId)
                .orElseThrow(() -> new ResourceNotFoundException("user", userId));

        boolean active = command.active() == null ? before.active() : command.active();
        String disabledReason = effectiveDisabledReason(command, before, active);

        if (!active && before.active() && store.userHoldsManageUsers(userId)
                && store.countActiveUsersWithManageUsersExcluding(userId) == 0) {
            throw lastAdministratorRefusal("disable this account");
        }

        boolean changed = store.updateUser(
                userId,
                command.expectedVersion(),
                command.department(),
                active,
                // Null on an active account: ck_app_user_active_disabled_consistent
                // requires disabled_at to be null there, and a surviving reason would
                // misrepresent an active user as disabled.
                disabledReason,
                clock.instant());

        if (!changed) {
            // 7.10. The row may be gone or merely bumped; either way the caller's
            // view was stale and reapplying blindly is how a lost edit happens.
            throw new ConflictException(
                    "User " + userId + " changed since version " + command.expectedVersion());
        }

        AdminUserStore.UserState after = store.findUser(userId)
                .orElseThrow(() -> new ResourceNotFoundException("user", userId));

        // 7.1/7.9: the change must take effect on the next request, not at token
        // expiry. The cache is keyed by Keycloak subject, so the targeted
        // invalidate() is what CurrentUserStateService's own contract expects.
        userState.invalidate(userId);

        recordUserChange(caller, before, after, disabledReason, command.reason());

        return new AdminUserOutcome(
                AdminUserCommand.OP_UPDATE_USER,
                userId,
                after.coarseRole(),
                after.department(),
                after.active(),
                after.version(),
                null,
                false);
    }

    // ------------------------------------------------------------ capability

    /**
     * 7.1 -- decides the {@code disabled_reason} column for a given target state.
     *
     * <p>A reason is required only on the <em>transition</em> into disabled, not
     * whenever the account happens to be disabled. Otherwise editing the department of
     * an account that was disabled months ago would demand a fresh reason and fail,
     * which would make the user impossible to maintain without first re-enabling them
     * -- and the error would misdescribe what the admin was doing.
     *
     * <p>When the account is already disabled the existing reason is carried forward,
     * unless the command supplies a new one -- so a reason can still be corrected
     * without cycling the account.
     */
    private static String effectiveDisabledReason(
            AdminUserCommand command, AdminUserStore.UserState before, boolean active) {
        if (active) {
            return null;
        }
        boolean transitioningIntoDisabled = before.active();
        String supplied = command.disabledReason();

        if (supplied != null && !supplied.isBlank()) {
            return supplied;
        }
        if (transitioningIntoDisabled) {
            // ck_app_user_disabled_reason enforces this at the database level. Checking
            // it here turns an opaque constraint violation into a message that says
            // what is missing.
            throw new IllegalArgumentException(
                    "disabledReason is required when disabling an account (7.1: a disable must always carry a "
                            + "reason)");
        }
        return before.disabledReason();
    }

    private AdminUserOutcome changeCapability(AdminUserCommand command, PlatformUser caller, boolean grant) {
        // Authorization before validation, as in updateUser. An unauthorized caller
        // must get the same 403 whatever the body contains, or the difference
        // between "unknown role" and "unknown capability" becomes a way to probe
        // which names exist before anyone is entitled to ask.
        requireManageUsers(caller, ENTITY_ROLE, null);

        PlatformRole role = parseRole(command.role());
        String permissionKey = parseCapability(command.capability());

        // Before the invariant check below, and before the row lock: two admins
        // revoking the same capability from two different roles touch two different
        // rows, so the per-role lock cannot serialise them and each would otherwise
        // pass the count and leave nobody holding it.
        serialiseAgainstConcurrentAdminChanges();

        if (!grant && MANAGE_USERS_KEY.equals(permissionKey)
                && store.roleHoldsManageUsers(role)
                && store.countActiveUsersWithManageUsersExcludingRole(role) == 0) {
            throw lastAdministratorRefusal("revoke " + permissionKey + " from " + role);
        }

        boolean heldBefore = store.lockCapabilityFlag(role, permissionKey)
                .orElseThrow(() -> new ResourceNotFoundException("role", role));

        if (grant) {
            store.grantCapability(role, permissionKey);
        } else {
            store.revokeCapability(role, permissionKey);
        }

        // A role change affects every user of that role, and the cache is keyed by
        // user. invalidateAll() rather than a per-user sweep: the set of affected
        // users is exactly the question the cache cannot answer cheaply, and a
        // stale capability is a security defect rather than a performance edge.
        userState.invalidateAll();

        recordCapabilityChange(caller, role, permissionKey, grant, heldBefore, command.reason());

        return new AdminUserOutcome(
                grant ? AdminUserCommand.OP_GRANT_CAPABILITY : AdminUserCommand.OP_REVOKE_CAPABILITY,
                null,
                role,
                null,
                false,
                0,
                permissionKey,
                grant);
    }

    // --------------------------------------------------------------- helpers

    /**
     * 7.2 function level. Every operation here is gated on {@code can_manage_users},
     * the flag {@code V10} grants to SECURITY_ADMIN and to nobody else.
     */
    private void requireManageUsers(PlatformUser caller, String resourceType, UUID resourceId) {
        if (!Capability.MANAGE_USERS.isHeldBy(caller.permissions())) {
            throw AuthorizationDeniedException.forMissingCapability(
                    Capability.MANAGE_USERS, resourceType, resourceId);
        }
    }

    /**
     * Resolves a permission key to a known {@link Capability}.
     *
     * <p>Resolved against the enum rather than written into the jsonb as a bare
     * string, so a typo cannot create a flag that no code path reads -- a key
     * nothing checks is indistinguishable from a grant that did not happen, and
     * would look like success.
     */
    private static String parseCapability(String capability) {
        if (capability == null || capability.isBlank()) {
            throw new IllegalArgumentException(
                    "capability is required for a capability change; expected one of the "
                            + Capability.MANAGE_USERS.permissionKey() + "-style permission keys");
        }
        String candidate = capability.trim();
        for (Capability known : Capability.values()) {
            if (known.permissionKey().equalsIgnoreCase(candidate)) {
                return known.permissionKey();
            }
        }
        throw new IllegalArgumentException(
                "Unrecognised capability '" + candidate + "'. It must match a known permission key exactly, "
                        + "so that a flag nothing reads cannot be created by mistake.");
    }

    /** Fails closed on an unknown role, as {@code PlatformRole} does for a token claim. */
    private static PlatformRole parseRole(String role) {
        if (role == null || role.isBlank()) {
            throw new IllegalArgumentException("role is required for a capability change");
        }
        try {
            return PlatformRole.fromKeycloakRole(role.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Unrecognised role '" + role + "'. Section 6.2.1 requires an exact match to a coarse role "
                            + "name; this endpoint manages the fine-grained capabilities of an existing role and "
                            + "does not create roles.");
        }
    }

    private static String normaliseOperation(String operation) {
        if (operation == null || operation.isBlank()) {
            throw new IllegalArgumentException(
                    "operation is required: one of " + AdminUserCommand.OP_UPDATE_USER + ", "
                            + AdminUserCommand.OP_GRANT_CAPABILITY + ", "
                            + AdminUserCommand.OP_REVOKE_CAPABILITY);
        }
        return operation.trim().toUpperCase(Locale.ROOT);
    }

    private static String unknownOperation(String operation) {
        return "Unknown operation '" + operation + "'. Expected one of "
                + AdminUserCommand.OP_UPDATE_USER + ", " + AdminUserCommand.OP_GRANT_CAPABILITY + ", "
                + AdminUserCommand.OP_REVOKE_CAPABILITY + ".";
    }

    /**
     * FR-6.1 -- the one place a change is refused for the last-administrator reason.
     *
     * <p>Returns the dedicated {@link LastAdministratorException} rather than a plain
     * {@code IllegalArgumentException} or a {@code ConflictException}. Both of those
     * tell the caller to reload and reapply, which is the wrong instruction twice
     * over: the request is refused rather than stale, and retrying it unchanged fails
     * identically forever. The recovery step is to grant the capability to somebody
     * else first, which the exception's message says.
     *
     * <p>The action string must be composed from a fixed vocabulary, since it is
     * reflected to the client -- hence no user id at the disable site, where
     * "this account" is both accurate and inert.
     */
    private static LastAdministratorException lastAdministratorRefusal(String action) {
        return new LastAdministratorException(action);
    }

    // ----------------------------------------------------------------- audit

    /**
     * 7.11 before/after for a user change, with {@code pii_redacted = true}.
     *
     * <p>True because the fields deliberately absent are exactly the personal data:
     * {@code email} and {@code full_name} are never read into the entry. The
     * department is included because a department move is the change being reviewed
     * and without it the entry would say only that "something about a user changed".
     * The Keycloak subject is included because attributing the change to an account
     * is the point, and it is an opaque id rather than personal data.
     */
    private void recordUserChange(
            PlatformUser caller,
            AdminUserStore.UserState before,
            AdminUserStore.UserState after,
            String disabledReason,
            String reason) {

        StringBuilder afterValue = new StringBuilder("{");
        appendField(afterValue, "department", after.department());
        appendField(afterValue, "active", after.active());
        appendField(afterValue, "version", after.version());
        appendField(afterValue, "coarse_role", after.coarseRole().name());
        if (!after.active()) {
            appendField(afterValue, "disabled_reason", disabledReason);
        }
        if (reason != null && !reason.isBlank()) {
            appendField(afterValue, "reason", reason.trim());
        }
        afterValue.append('}');

        audit.recordChange(
                caller,
                ENTITY_USER,
                after.id(),
                ACTION_USER_UPDATE,
                RequestContext.endpoint(),
                RequestContext.method(),
                RequestContext.requestId().orElseGet(RequestContext::newRequestId),
                RequestContext.remoteAddress(),
                AuthorizationCheckType.FUNCTION_LEVEL,
                Capability.MANAGE_USERS.rule(),
                "{\"department\":" + quote(before.department())
                        + ",\"active\":" + before.active()
                        + ",\"version\":" + before.version() + "}",
                afterValue.toString(),
                true);
    }

    /**
     * 7.11 before/after for a capability change.
     *
     * <p>Records the single affected flag rather than the whole permissions document,
     * so the entry says "can_manage_retention: false -&gt; true" instead of embedding
     * two copies of a configuration blob that also contains unrelated scoping detail.
     * The prior value comes from the row lock above, so it is the value that was
     * actually overwritten.
     */
    private void recordCapabilityChange(
            PlatformUser caller,
            PlatformRole role,
            String permissionKey,
            boolean grant,
            boolean heldBefore,
            String reason) {

        StringBuilder afterValue = new StringBuilder("{");
        appendField(afterValue, "role", role.name());
        appendField(afterValue, "capability", permissionKey);
        appendField(afterValue, "value", grant);
        if (reason != null && !reason.isBlank()) {
            appendField(afterValue, "reason", reason.trim());
        }
        afterValue.append('}');

        audit.recordChange(
                caller,
                ENTITY_ROLE,
                null,
                grant ? ACTION_CAPABILITY_GRANT : ACTION_CAPABILITY_REVOKE,
                RequestContext.endpoint(),
                RequestContext.method(),
                RequestContext.requestId().orElseGet(RequestContext::newRequestId),
                RequestContext.remoteAddress(),
                AuthorizationCheckType.FUNCTION_LEVEL,
                Capability.MANAGE_USERS.rule(),
                "{\"role\":" + quote(role.name())
                        + ",\"" + permissionKey + "\":" + heldBefore + "}",
                afterValue.toString(),
                false);
    }

    private static void appendField(StringBuilder json, String name, Object value) {
        if (json.length() > 1) {
            json.append(',');
        }
        json.append('"').append(name).append("\":");
        if (value instanceof Number || value instanceof Boolean) {
            json.append(value);
        } else {
            json.append('"').append(escape(String.valueOf(value))).append('"');
        }
    }

    private static String quote(String value) {
        return value == null ? "null" : "\"" + escape(value) + "\"";
    }

    /**
     * These values land in a {@code jsonb} column, so a department or reason
     * containing a quote must not be able to terminate its own JSON string and inject
     * a key into the audit row. A free-text {@code disabledReason} is exactly the
     * kind of value a user types quotes into.
     */
    private static String escape(String value) {
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }
}
