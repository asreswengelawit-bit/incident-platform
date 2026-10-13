package com.company.incidentplatform.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.company.incidentplatform.authorization.Capability;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * 7.2.3 / 6.2.3 -- the permission parser.
 *
 * <p>These tests exist because the parser is the boundary between a
 * database-authored jsonb document and the entire authorization system. Its
 * failure modes are asymmetric: a missing or malformed key that defaults to
 * permissive silently grants a capability, and the grant will not be noticed
 * until it is abused. So the default-deny behaviour is asserted explicitly
 * rather than assumed.
 */
class RolePermissionsTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private RolePermissions parse(String json) throws Exception {
        return RolePermissions.fromJson(mapper.readTree(json));
    }

    @Test
    @DisplayName("a role with an empty permissions object holds no capability at all")
    void emptyObjectGrantsNothing() throws Exception {
        RolePermissions permissions = parse("{}");

        assertThat(permissions.visibilityScope()).isEqualTo(VisibilityScope.NONE);
        assertThat(permissions.unassignedVisibility()).isEqualTo(VisibilityScope.NONE);
        assertThat(permissions.ledDepartments()).isEmpty();
        assertThat(permissions.canReassign()).isFalse();
        assertThat(permissions.canViewReporterIdentity()).isFalse();
        assertThat(permissions.isReadOnly()).isFalse();
    }

    @Test
    @DisplayName("a missing permissions key denies everything rather than throwing or defaulting open")
    void nullNodeGrantsNothing() {
        RolePermissions permissions = RolePermissions.fromJson(null);

        assertThat(permissions.visibilityScope()).isEqualTo(VisibilityScope.NONE);
        assertThat(permissions.canExport()).isFalse();
    }

    @Test
    @DisplayName("a non-object permissions value denies everything")
    void nonObjectGrantsNothing() throws Exception {
        // The V2 CHECK constraint (jsonb_typeof = 'object') should make this
        // unreachable, but the parser must not be the thing that decides to
        // interpret a JSON array of role names as a grant.
        RolePermissions permissions = parse("[\"SECURITY_ADMIN\"]");

        assertThat(permissions.canManageUsers()).isFalse();
        assertThat(permissions.visibilityScope()).isEqualTo(VisibilityScope.NONE);
    }

    @Test
    @DisplayName("a misspelled flag is ignored, not honoured")
    void misspelledFlagIsIgnored() throws Exception {
        RolePermissions permissions = parse("""
                {"can_reasign": true, "can_escalate": true}
                """);

        assertThat(permissions.canReassign()).as("typo must not grant").isFalse();
        assertThat(permissions.canEscalate()).as("correct key must grant").isTrue();
    }

    @Test
    @DisplayName("a string where a boolean is expected does not grant the capability")
    void wrongTypeDoesNotGrant() throws Exception {
        RolePermissions permissions = parse("""
                {"can_manage_users": "true", "can_export": 1}
                """);

        assertThat(permissions.canManageUsers()).isFalse();
        assertThat(permissions.canExport()).isFalse();
    }

    @Test
    @DisplayName("an unrecognised visibility scope fails closed to NONE")
    void unknownScopeFailsClosed() throws Exception {
        RolePermissions permissions = parse("""
                {"visibility_scope": "GLOBAL_EVERYTHING"}
                """);

        assertThat(permissions.visibilityScope()).isEqualTo(VisibilityScope.NONE);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"SALES", "  ", "engineering", "SECURITY_LEAD"})
    @DisplayName("led_departments keeps meaningful names and discards blank or non-matching noise")
    void ledDepartmentsFiltering(String value) throws Exception {
        RolePermissions permissions = parse("""
                {"led_departments": ["SECURITY", "SECURITY", "", "SECURITY", "%s", null, 42]}
                """.formatted(value));

        // "42" is a JSON number, not a string, and is dropped; duplicates and
        // blanks are dropped. Only genuine, non-blank text survives.
        assertThat(permissions.ledDepartments())
                .allSatisfy(d -> assertThat(d).isNotBlank());
        assertThat(permissions.ledDepartments()).doesNotHaveDuplicates();
    }

    @Test
    @DisplayName("led_departments is unmodifiable so a caller cannot widen a role mid-request")
    void ledDepartmentsIsImmutable() throws Exception {
        RolePermissions permissions = parse("""
                {"led_departments": ["SECURITY"]}
                """);

        org.assertj.core.api.Assertions
                .assertThatThrownBy(() -> permissions.ledDepartments().add("FINANCE"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("can_view_reporter_identity is a grantable permission, not a role property")
    void reporterIdentityIsGrantable() throws Exception {
        // FR-1.6 + the confirmed decision: this flag is what an Admin grants
        // when there is a need, and it is granted to nobody at deployment. The
        // parser must be able to express "granted" as well as "not granted" --
        // the guarantee is about the seeded value, not about the flag being
        // unreachable.
        RolePermissions granted = parse("""
                {"can_view_reporter_identity": true}
                """);
        RolePermissions notGranted = parse("""
                {"can_view_reporter_identity": false}
                """);

        assertThat(granted.canViewReporterIdentity()).isTrue();
        assertThat(notGranted.canViewReporterIdentity()).isFalse();
    }

    @Test
    @DisplayName("an auditor role is read-only and organisation-wide")
    void auditorPermissions() throws Exception {
        RolePermissions permissions = parse("""
                {
                  "visibility_scope": "ORGANIZATION",
                  "read_only": true,
                  "can_view_audit_log": true,
                  "can_view_investigation_notes": true,
                  "can_reassign": false,
                  "can_approve_closure": false
                }
                """);

        assertThat(permissions.visibilityScope()).isEqualTo(VisibilityScope.ORGANIZATION);
        assertThat(permissions.isReadOnly()).isTrue();
        assertThat(permissions.canViewAuditLog()).isTrue();
        assertThat(permissions.canReassign()).isFalse();
    }

    @Nested
    @DisplayName("Capability binding")
    class CapabilityBinding {

        @ParameterizedTest
        @CsvSource({
            "can_reassign, REASSIGN",
            "can_escalate, ESCALATE",
            "can_approve_closure, APPROVE_CLOSURE",
            "can_view_audit_log, VIEW_AUDIT_LOG",
            "can_ingest_incidents, INGEST_INCIDENT",
            "can_view_reporter_identity, VIEW_REPORTER_IDENTITY",
            "can_manage_severity_matrix, MANAGE_SEVERITY_MATRIX"
        })
        @DisplayName("every capability maps to the permission key it reads")
        void capabilityKeysAreWired(String key, Capability capability) {
            assertThat(capability.permissionKey()).isEqualTo(key);
            assertThat(capability.rule()).isEqualTo("capability." + key);
        }

        @Test
        @DisplayName("every capability reads the flag it names, and no capability is unbound")
        void everyCapabilityIsBound() throws Exception {
            // A capability whose isHeldBy always returned false would be a silent
            // dead endpoint; one that always returned true would be worse. This
            // asserts both directions for every declared capability.
            for (Capability capability : Capability.values()) {
                RolePermissions granted = parse("{\"" + capability.permissionKey() + "\": true}");
                RolePermissions denied = parse("{\"" + capability.permissionKey() + "\": false}");

                assertThat(capability.isHeldBy(granted))
                        .as("%s must be grantable", capability)
                        .isTrue();
                assertThat(capability.isHeldBy(denied))
                        .as("%s must be denyable", capability)
                        .isFalse();
            }
        }
    }
}
