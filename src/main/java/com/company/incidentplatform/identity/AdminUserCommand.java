package com.company.incidentplatform.identity;

import jakarta.validation.constraints.NotBlank;
import java.util.UUID;

/**
 * The single request body for {@code POST /api/v1/admin/users} (Section 9, "Manage
 * users/roles").
 *
 * <p>One endpoint with an explicit {@code operation} discriminator rather than three
 * paths, because Section 9's inventory lists exactly one admin users path and 7.7
 * requires the documented API and the implemented API to be the same set. The
 * discriminator is mandatory and validated, so an unrecognised operation is a 400
 * rather than a silently ignored body.
 *
 * <h2>Why there is no coarse-role field that works</h2>
 *
 * <p>{@code role} appears in this record for two different operations, and for
 * {@code UPDATE_USER} it exists only to be <em>refused</em>. That is intentional.
 * Section 6.2 item 4 is explicit that {@code app_user.role_id} is synced from
 * Keycloak and that Admins change a coarse role in the IdP, so an admin UI that
 * appears to set a role in this API would be creating exactly the dual source of
 * truth 6.2 rejects. Declaring the field means such a request is <b>rejected with an
 * explanation</b> instead of being dropped as an unknown property -- which matters,
 * because Spring Boot leaves {@code FAIL_ON_UNKNOWN_PROPERTIES} off by default, so
 * an undeclared field would otherwise be ignored and the admin would believe a role
 * had changed when nothing had.
 *
 * <p>That silent-ignore hazard is not confined to this field. It is a property of
 * the whole JSON binding, and the general fix (rejecting unknown properties
 * globally) is a cross-cutting change to every controller's contract, so it is
 * raised rather than made here.
 *
 * @param userId          UPDATE_USER target
 * @param expectedVersion UPDATE_USER, mandatory -- 7.10 optimistic locking
 * @param department      UPDATE_USER, null leaves unchanged; 6.2.3 scoping detail
 * @param active          UPDATE_USER, null leaves unchanged; 7.1 lifecycle
 * @param disabledReason  UPDATE_USER, mandatory when this call disables an account; an
 *                        account that is already disabled keeps its existing reason
 * @param role            GRANT/REVOKE target role; for UPDATE_USER, always refused
 * @param capability      GRANT/REVOKE, a {@code Capability} permission key
 * @param reason          optional, recorded in the 7.11 entry when supplied
 */
public record AdminUserCommand(
        @NotBlank String operation,
        UUID userId,
        Integer expectedVersion,
        String department,
        Boolean active,
        String disabledReason,
        String role,
        String capability,
        String reason) {

    public static final String OP_UPDATE_USER = "UPDATE_USER";
    public static final String OP_GRANT_CAPABILITY = "GRANT_CAPABILITY";
    public static final String OP_REVOKE_CAPABILITY = "REVOKE_CAPABILITY";
}
