package com.company.incidentplatform.authorization;

import com.company.incidentplatform.security.PlatformUser;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * The single call site through which incident access is granted.
 *
 * <p>7.2 is deliberately a three-layer chain, and the value of enforcing it
 * through one class is that the layers cannot be reordered or skipped. Every
 * controller obtains an incident through this guard rather than through a
 * repository, so there is exactly one place where "can this user touch this
 * object?" is answered.
 *
 * <p>Two things this class deliberately does <em>not</em> do:
 *
 * <ul>
 *   <li>It does not filter lists. Doing pagination filtering here would mean
 *       loading rows the user may not see and discarding them afterwards, which
 *       leaks existence through page counts and is unbounded in memory. List
 *       visibility is expressed in the query itself (7.2.1 plus 9.1), and
 *       {@link #filterVisible} exists to make the two agree rather than to
 *       reimplement the rule.</li>
 *   <li>It does not make property-level decisions. Those are made when the
 *       response view is built, so that a suppressed field is never loaded in
 *       the first place.</li>
 * </ul>
 */
@Component
public class IncidentAccessGuard {

    private final IncidentSnapshotRepository snapshots;
    private final IncidentObjectAuthorizer objectAuthorizer;

    public IncidentAccessGuard(
            IncidentSnapshotRepository snapshots, IncidentObjectAuthorizer objectAuthorizer) {
        this.snapshots = snapshots;
        this.objectAuthorizer = objectAuthorizer;
    }

    /** 7.2 object level: read access to one incident. */
    public IncidentSnapshot requireRead(PlatformUser user, UUID incidentId) {
        return requireRead(user, incidentId, false);
    }

    /**
     * 7.2 / 7.14 object level: read access to one incident, with opt-in
     * {@code includeDeleted} scope for Admin and Auditor compliance review.
     */
    public IncidentSnapshot requireRead(PlatformUser user, UUID incidentId, boolean includeDeleted) {
        return require(user, incidentId, includeDeleted);
    }

    /**
     * 7.2 function + object level: a mutation requiring {@code capability}.
     *
     * <p>Function level is checked first. It is the cheaper test, and more
     * importantly it is the one that must be satisfied regardless of the object:
     * an Analyst assigned to incident #7 still may not call a bulk reassign
     * endpoint on it, and checking the object first would let the object check
     * "succeed" and mask the missing capability.
     *
     * <p>All three decisions are made in
     * {@link IncidentObjectAuthorizer#authorizeWrite} rather than by composing
     * {@link #requireRead} with a capability test here. That method also refuses
     * writes to a soft-deleted incident (6.2/7.14: a soft-deleted record is
     * immutable, and "immutable" has to be enforced on the write path -- the read
     * rule cannot refuse it, since oversight roles are allowed to read them).
     * It also means a granted write is audited under a write rule rather than a
     * read rule, so 7.11 rows for mutations do not cite {@code incident.read.*}.
     */
    public IncidentSnapshot requireWrite(
            PlatformUser user, UUID incidentId, Capability capability) {
        // Read-only is checked BEFORE the capability, so the recorded 7.11 reason
        // is the true one. A read-only role is refused every write because of
        // its read-only nature; reporting "lacks capability.can_classify" instead
        // would be a misleading audit entry that an administrator would then act
        // on -- granting the capability -- and the write would still be refused.
        if (user.permissions().isReadOnly()) {
            // 7.2.1: the Auditor is organisation-wide read-only. Enforced as a
            // blanket write refusal rather than per-capability, so that granting
            // an Auditor a capability later cannot accidentally make it writable.
            throw AuthorizationDeniedException.forReadOnlyRole("incident", incidentId);
        }
        boolean capabilityHeld = capability.isHeldBy(user.permissions());
        IncidentSnapshot snapshot = snapshots.findById(incidentId).orElse(null);
        AuthorizationDecision decision = objectAuthorizer.authorizeWrite(
                user, snapshot, capabilityHeld, capability.rule());
        if (decision.denied()) {
            throw new AuthorizationDeniedException(decision, "incident", incidentId);
        }
        return snapshot;
    }

    private IncidentSnapshot require(PlatformUser user, UUID incidentId, boolean includeDeleted) {
        IncidentSnapshot snapshot = snapshots.findById(incidentId).orElse(null);
        AuthorizationDecision decision = objectAuthorizer.authorizeRead(user, snapshot, includeDeleted);
        if (decision.denied()) {
            throw new AuthorizationDeniedException(decision, "incident", incidentId);
        }
        return snapshot;
    }

    /**
     * Applies 7.2.1 to an already-paged result set.
     */
    public java.util.List<IncidentSnapshot> filterVisible(
            PlatformUser user, java.util.List<IncidentSnapshot> candidates) {
        return filterVisible(user, candidates, false);
    }

    /**
     * Applies 7.2.1 to an already-paged result set, supporting opt-in
     * {@code includeDeleted} for Admin/Auditor compliance queries.
     */
    public java.util.List<IncidentSnapshot> filterVisible(
            PlatformUser user, java.util.List<IncidentSnapshot> candidates, boolean includeDeleted) {
        return candidates.stream()
                .filter(snapshot -> objectAuthorizer.authorizeRead(user, snapshot, includeDeleted).allowed())
                .toList();
    }
}
