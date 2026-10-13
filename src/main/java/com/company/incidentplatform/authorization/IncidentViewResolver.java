package com.company.incidentplatform.authorization;

import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.DeniedReason;
import com.company.incidentplatform.security.PlatformUser;

/**
 * Section 7.2.3 -- property-level authorization.
 *
 * <p>The rule this class exists to enforce: a field must be <em>unavailable</em>
 * to a role, not merely hidden from it. Two implementations of "Analysts cannot
 * see reporter identity for anonymous reports" are possible -- omit the field
 * from the serialised response, or return it and trust the UI -- and only the
 * first is a security control. The second is a UI convention, defeated by
 * devtools, and it fails silently when someone adds a new endpoint.
 *
 * <p>So each method returns a <em>different type</em> per authorization outcome.
 * There is no code path by which a caller without the permission can obtain the
 * restricted value, because the accessors returning it live on a type they never
 * receive.
 *
 * <p>FR-1.6 is the concrete case: for an anonymous report, the reporter's real
 * identity is available only to a role holding {@code can_view_reporter_identity},
 * which is granted to nobody at deployment. Withholding is recorded as a
 * {@link AuthorizationCheckType#PROPERTY_LEVEL} decision so 7.11 can log that
 * the suppression happened -- an audit that cannot show that identity was
 * suppressed cannot evidence that it was.
 */
public final class IncidentViewResolver {

    static final String ANONYMOUS_REPORTER_LABEL = "Anonymous reporter";
    static final String ANONYMOUS_REPORTER_NOTICE =
            "Reporter identity is withheld for an anonymous report (FR-1.6). "
                    + "A Security Administrator may grant permission to view it, and every such view is audited.";

    private final Capability identityCapability;
    private final Capability notesCapability;

    public IncidentViewResolver() {
        this(Capability.VIEW_REPORTER_IDENTITY, Capability.VIEW_INCIDENT);
    }

    public IncidentViewResolver(Capability identityCapability, Capability notesCapability) {
        this.identityCapability = identityCapability;
        this.notesCapability = notesCapability;
    }

    /**
     * 7.2.3: investigation notes, response actions, and the timeline are visible
     * only to roles holding the corresponding permission.
     *
     * <p>Callers without it receive the base view only. The restricted
     * collections are never populated and never serialised -- they are not
     * emptied after the fact, which would still have loaded them from the
     * database.
     */
    public Object resolve(PlatformUser user, IncidentViews.BaseView base, RestrictedContent restricted) {
        if (restricted == null) {
            return base;
        }
        if (!notesCapability.isHeldBy(user.permissions())) {
            return base;
        }
        return new IncidentViews.InvestigationView(
                base, restricted.notes(), restricted.actions(), restricted.timeline());
    }

    /**
     * FR-1.6: the identity behind an anonymous report.
     *
     * <p>For a non-anonymous incident, the reporter's name and department are
     * ordinary business data and are not gated -- withholding them would break
     * the normal reporting workflow. The gate applies only when
     * {@code anonymous} is set, which is precisely the case FR-1.6 is about.
     *
     * @param realId           the reporter's user id, or null
     * @param realDisplayName  the reporter's name
     * @param realEmail        the reporter's email
     * @param reporterDept     the reporter's home department
     */
    public IncidentViews.ReporterIdentityView resolveReporterIdentity(
            PlatformUser user, boolean anonymous, java.util.UUID realId, String realDisplayName,
            String realEmail, String reporterDept) {

        if (!anonymous) {
            return new IncidentViews.ReporterIdentityView(
                    realId, realDisplayName, realEmail, reporterDept, false, null);
        }
        if (identityCapability.isHeldBy(user.permissions())) {
            return new IncidentViews.ReporterIdentityView(
                    realId, realDisplayName, realEmail, reporterDept, false, null);
        }
        return new IncidentViews.ReporterIdentityView(
                null,
                ANONYMOUS_REPORTER_LABEL,
                null,
                null,
                true,
                ANONYMOUS_REPORTER_NOTICE);
    }

    /**
     * Records the property-level outcome for the 7.11 audit trail.
     *
     * <p>Both outcomes are logged, not just the suppression. A grant that is
     * never exercised and a grant that is exercised constantly look identical in
     * the ALLOWED column, and 7.12's anomaly detection needs to distinguish
     * them.
     */
    public AuthorizationDecision recordPropertyDecision(
            PlatformUser user, boolean anonymous, boolean identityWithheld) {
        if (!anonymous) {
            return AuthorizationDecision.allow(
                    AuthorizationCheckType.PROPERTY_LEVEL, "property.reporter_identity.not_applicable");
        }
        if (identityWithheld) {
            return AuthorizationDecision.deny(
                    AuthorizationCheckType.PROPERTY_LEVEL,
                    "property.reporter_identity.withheld",
                    DeniedReason.PROPERTY_SUPPRESSION);
        }
        return AuthorizationDecision.allow(
                AuthorizationCheckType.PROPERTY_LEVEL, "property.reporter_identity.granted");
    }

    /** Content only loadable by roles holding the notes capability. */
    public record RestrictedContent(
            java.util.List<String> notes,
            java.util.List<String> actions,
            java.util.List<IncidentViews.InvestigationView.TimelineEntry> timeline) {
    }
}
