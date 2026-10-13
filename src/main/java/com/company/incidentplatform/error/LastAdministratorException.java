package com.company.incidentplatform.error;

/**
 * FR-6.1: a change was refused because it would leave no active user holding
 * {@code can_manage_users}.
 *
 * <p><b>Deliberately not a subclass of {@link ConflictException}.</b> Both answer 409,
 * but they are opposite instructions to a client, and the spec now requires this one
 * to be distinguishable:
 *
 * <ul>
 *   <li>A {@code ConflictException} means "this record changed while you were editing
 *       it -- reload and reapply". The fix is to <em>refetch and try again</em>, and
 *       the retry is expected to succeed.</li>
 *   <li>This means "this change is refused, and retrying the identical request will
 *       fail identically forever". The only way forward is a different change --
 *       grant the capability to somebody else first.</li>
 * </ul>
 *
 * <p>Returning the version-conflict body for this case would tell the admin to
 * reload and reapply, which cannot help and reads as a platform fault. Extending
 * {@code ConflictException} would also leave the generic handler one annotation
 * reordering away from swallowing it, so the types are kept apart in the hierarchy
 * rather than only in the response body.
 *
 * <p>The state is unrecoverable through the API if it is ever reached: there is no
 * Keycloak write-through, and a capability grant is the only way to get
 * {@code can_manage_users} back. That is why the invariant is enforced on every path
 * that could remove a holder, and why {@code AdminUserService} serialises those paths
 * against each other rather than counting and writing.
 *
 * <p>The message is composed here, in the application, from the refused action --
 * never from caller-supplied free text and never an identifier. It is therefore safe
 * to return to an administrator, who is by definition entitled to know the request
 * was refused and why.
 */
public class LastAdministratorException extends RuntimeException {

    private final String attemptedAction;

    /**
     * @param attemptedAction a short description of what was refused, e.g.
     *        {@code "disable this account"} or
     *        {@code "revoke can_manage_users from SECURITY_ADMIN"}. Must be composed
     *        by the caller from a fixed vocabulary -- it is reflected to the client,
     *        so it must not carry an identifier or anything the caller typed.
     */
    public LastAdministratorException(String attemptedAction) {
        super(buildMessage(attemptedAction));
        this.attemptedAction = attemptedAction;
    }

    public String getAttemptedAction() {
        return attemptedAction;
    }

    /**
     * The explanation lives here rather than at each call site so the two refusals --
     * disabling the last holder, and revoking the capability from the last role that
     * has it -- cannot drift into describing the problem differently. The recovery
     * step is the part that matters most, and a caller who is not told it is stuck.
     */
    private static String buildMessage(String attemptedAction) {
        return "Refusing to " + attemptedAction + ": it would leave no active user able to manage users, and "
                + "this deployment has no other path to grant the capability back. Grant "
                + "can_manage_users to another administrator first, then reapply this change.";
    }
}
