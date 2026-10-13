package com.company.incidentplatform.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static com.company.incidentplatform.TestFixtures.ENGINEERING;
import static com.company.incidentplatform.TestFixtures.FINANCE;

import com.company.incidentplatform.TestFixtures;
import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.DeniedReason;
import com.company.incidentplatform.security.PlatformUser;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Section 7.2.3 property-level authorization, the Section 10
 * "property-level restriction" row of the test matrix.
 *
 * <p>The central assertion in this class is a negative one about the return
 * <em>type</em>: a caller without the permission is not merely given a view with
 * the field blanked, but is given a different type on which the restricted
 * accessors do not exist. That is what makes the restriction structural rather
 * than a convention.
 */
class IncidentViewResolverTest {

    private static final UUID INCIDENT = UUID.fromString("00000000-0000-0000-0000-0000000000c1");
    private static final UUID REPORTER = UUID.fromString("00000000-0000-0000-0000-0000000000a1");
    private static final UUID ANALYST = UUID.fromString("00000000-0000-0000-0000-0000000000b2");
    private static final UUID ADMIN = UUID.fromString("00000000-0000-0000-0000-0000000000f6");
    private static final UUID AUDITOR = UUID.fromString("00000000-0000-0000-0000-0000000000a7");

    private final IncidentViewResolver resolver = new IncidentViewResolver();

    private static IncidentViews.BaseView baseView() {
        return new IncidentViews.BaseView(
                INCIDENT, "INC-2026-0001", "Suspicious login", "Description", "Phishing",
                "HIGH", "NEW", false, "mail.example", ENGINEERING, false, false,
                "2026-09-01T10:00:00Z", "2026-08-31T22:00:00Z", null,
                REPORTER, "Alice Reporter", "alice@example.test", null, null, null, List.of());
    }

    private static IncidentViewResolver.RestrictedContent restricted() {
        return new IncidentViewResolver.RestrictedContent(
                List.of("Indicator 10.0.0.5 is a known bad host"),
                List.of("Blocked sender domain"),
                List.of(new IncidentViews.InvestigationView.TimelineEntry(
                        "NEW", "TRIAGED", "analyst", "2026-09-01T11:00:00Z", "classified")));
    }

    @Nested
    @DisplayName("investigation notes and timeline")
    class InvestigationContent {

        @Test
        @DisplayName("a role without the capability receives the base view and no restricted type")
        void reporterGetsBaseViewOnly() {
            PlatformUser reporter = TestFixtures.reporter(REPORTER, ENGINEERING);

            Object view = resolver.resolve(reporter, baseView(), restricted());

            // Not just "the notes are empty" -- the returned object simply has
            // no way to express them.
            assertThat(view).isInstanceOf(IncidentViews.BaseView.class);
            assertThat(view).isNotInstanceOf(IncidentViews.InvestigationView.class);
        }

        @Test
        @DisplayName("a role with the capability receives the investigation view")
        void analystGetsInvestigationView() {
            PlatformUser analyst = TestFixtures.analyst(ANALYST, ENGINEERING);

            Object view = resolver.resolve(analyst, baseView(), restricted());

            assertThat(view).isInstanceOf(IncidentViews.InvestigationView.class);
            var investigation = (IncidentViews.InvestigationView) view;
            assertThat(investigation.notes()).hasSize(1);
            assertThat(investigation.timeline()).hasSize(1);
        }

        @Test
        @DisplayName("null restricted content never produces a null view")
        void nullRestrictedContent() {
            PlatformUser analyst = TestFixtures.analyst(ANALYST, ENGINEERING);

            assertThat(resolver.resolve(analyst, baseView(), null))
                    .isInstanceOf(IncidentViews.BaseView.class);
        }

        @Test
        @DisplayName("an Auditor with the notes capability receives the investigation view")
        void auditorWithCapabilityGetsNotes() {
            // 7.2.1 grants the Auditor organisation-wide read-only access, which
            // includes reading what was done. Read-only is a write restriction,
            // not a read restriction.
            var view = resolver.resolve(TestFixtures.auditor(AUDITOR), baseView(), restricted());

            assertThat(view).isInstanceOf(IncidentViews.InvestigationView.class);
        }
    }

    @Nested
    @DisplayName("FR-1.6 anonymous reporter identity")
    class AnonymousReporterIdentity {

        @Test
        @DisplayName("identity is withheld from a role without the grant")
        void withheldWithoutGrant() {
            PlatformUser admin = TestFixtures.admin(ADMIN);

            var view = resolver.resolveReporterIdentity(
                    admin, true, REPORTER, "Alice Reporter", "alice@example.test", FINANCE);

            assertThat(view.identityWithheld()).isTrue();
            assertThat(view.reporterDisplayName())
                    .isEqualTo(IncidentViewResolver.ANONYMOUS_REPORTER_LABEL);
            assertThat(view.reporterId()).as("the id must not leak either").isNull();
            assertThat(view.reporterEmail()).isNull();
            assertThat(view.reporterDepartment()).isNull();
        }

        @Test
        @DisplayName("no value in the withheld view equals the real value")
        void noRealValueSurvives() {
            // A subtle leak: leaving the email populated and only blanking the
            // display name would still identify the reporter.
            var view = resolver.resolveReporterIdentity(
                    TestFixtures.admin(ADMIN), true, REPORTER, "Alice Reporter",
                    "alice@example.test", FINANCE);

            assertThat(view.reporterEmail()).isNull();
            assertThat(view.reporterId()).isNull();
            assertThat(view.reporterDepartment()).isNull();
            assertThat(view.reporterDisplayName()).doesNotContain("Alice");
            assertThat(view.withheldNotice()).doesNotContain("Alice");
        }

        @Test
        @DisplayName("identity is revealed to a role holding the grant")
        void revealedWithGrant() {
            PlatformUser granted = TestFixtures.adminWithReporterIdentity(ADMIN);

            var view = resolver.resolveReporterIdentity(
                    granted, true, REPORTER, "Alice Reporter", "alice@example.test", FINANCE);

            assertThat(view.identityWithheld()).isFalse();
            assertThat(view.reporterId()).isEqualTo(REPORTER);
            assertThat(view.reporterEmail()).isEqualTo("alice@example.test");
        }

        @Test
        @DisplayName("a non-anonymous incident is not gated")
        void nonAnonymousNotGated() {
            // Withholding ordinary reporter details would break the normal
            // reporting workflow. FR-1.6 is about anonymous submission only.
            var view = resolver.resolveReporterIdentity(
                    TestFixtures.reporter(REPORTER, ENGINEERING), false,
                    REPORTER, "Alice Reporter", "alice@example.test", ENGINEERING);

            assertThat(view.identityWithheld()).isFalse();
            assertThat(view.reporterDisplayName()).isEqualTo("Alice Reporter");
        }

        @Test
        @DisplayName("the response shape is identical whether or not identity is withheld")
        void shapeIsConstant() {
            // A view that gained or lost fields based on authorization would be a
            // signal in itself. The record is always present; only its values
            // change.
            var withheld = resolver.resolveReporterIdentity(
                    TestFixtures.admin(ADMIN), true, REPORTER, "Alice", "a@b.c", FINANCE);
            var revealed = resolver.resolveReporterIdentity(
                    TestFixtures.adminWithReporterIdentity(ADMIN), true, REPORTER, "Alice", "a@b.c", FINANCE);

            assertThat(withheld.getClass()).isEqualTo(revealed.getClass());
        }
    }

    @Nested
    @DisplayName("7.11 audit record of a property-level decision")
    class PropertyAudit {

        @ParameterizedTest
        @EnumSource(
                value = PlatformRoleName.class,
                names = {"REPORTER", "ANALYST", "SECURITY_ADMIN", "AUDITOR"})
        @DisplayName("both outcomes are classifiable so 7.12 can distinguish them")
        void bothOutcomesRecorded(PlatformRoleName role) {
            // Recording only suppressions would make "never granted" and
            // "granted and never used" indistinguishable, which is exactly the
            // difference 7.12 anomaly detection needs.
            PlatformUser user = userForRole(role);

            var withheld = resolver.recordPropertyDecision(user, true, true);
            var granted = resolver.recordPropertyDecision(user, true, false);
            var notApplicable = resolver.recordPropertyDecision(user, false, false);

            assertThat(withheld.checkType()).isEqualTo(AuthorizationCheckType.PROPERTY_LEVEL);
            assertThat(withheld.deniedReason()).isEqualTo(DeniedReason.PROPERTY_SUPPRESSION);
            assertThat(granted.allowed()).isTrue();
            assertThat(granted.rule()).isEqualTo("property.reporter_identity.granted");
            assertThat(notApplicable.rule()).isEqualTo("property.reporter_identity.not_applicable");
        }

        private PlatformUser userForRole(PlatformRoleName role) {
            return switch (role) {
                case REPORTER -> TestFixtures.reporter(REPORTER, ENGINEERING);
                case ANALYST -> TestFixtures.analyst(ANALYST, ENGINEERING);
                case AUDITOR -> TestFixtures.auditor(AUDITOR);
                default -> TestFixtures.admin(ADMIN);
            };
        }
    }

    /** Enum source for the parameterised audit test. */
    enum PlatformRoleName {
        REPORTER,
        ANALYST,
        SECURITY_ADMIN,
        AUDITOR
    }
}
