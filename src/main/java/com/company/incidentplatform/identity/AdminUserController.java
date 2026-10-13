package com.company.incidentplatform.identity;

import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.web.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Section 9 -- {@code POST /api/v1/admin/users}, "Manage users/roles", Admin only.
 *
 * <p>Thin, like the other controllers: no authorization logic here, because 7.2's
 * function-level check lives in {@link AdminUserService} against
 * {@code can_manage_users} and must be enforced identically however the service is
 * reached.
 *
 * <p>{@code POST} returning {@code 200} rather than {@code 201}: the operation
 * updates an existing user or role rather than creating one, and the spec lists no
 * resource to point a {@code Location} header at. A 201 here would claim a creation
 * that did not happen.
 *
 * <p>There is deliberately no companion GET. Section 9's inventory lists only this
 * path, and 7.7 requires the documented and implemented APIs to be the same set, so
 * adding list endpoints is a change to the spec rather than to the code. The
 * consequence is real and worth stating: an admin must already know a user's id to
 * act on them.
 */
@RestController
@RequestMapping("/api/v1/admin")
public class AdminUserController {

    private final AdminUserService adminUserService;

    public AdminUserController(AdminUserService adminUserService) {
        this.adminUserService = adminUserService;
    }

    @PostMapping("/users")
    ResponseEntity<AdminUserOutcome> manageUser(
            @Valid @RequestBody AdminUserCommand command,
            @CurrentUser PlatformUser caller) {

        return ResponseEntity.ok(adminUserService.apply(command, caller));
    }
}
