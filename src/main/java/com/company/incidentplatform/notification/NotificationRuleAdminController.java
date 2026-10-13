package com.company.incidentplatform.notification;

import com.company.incidentplatform.incident.PagedResponse;
import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.web.CurrentUser;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/notification-rules")
public class NotificationRuleAdminController {

    private final NotificationRuleAdminService service;

    public NotificationRuleAdminController(NotificationRuleAdminService service) {
        this.service = service;
    }

    @GetMapping
    public PagedResponse<NotificationRuleView> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int pageSize,
            @RequestParam(defaultValue = "false") boolean includeDeleted,
            @CurrentUser PlatformUser caller) {
        return service.list(page, pageSize, includeDeleted, caller);
    }

    @GetMapping("/{id}")
    public NotificationRuleView get(
            @PathVariable UUID id,
            @RequestParam(defaultValue = "false") boolean includeDeleted,
            @CurrentUser PlatformUser caller) {
        return service.get(id, includeDeleted, caller);
    }

    @PostMapping
    public ResponseEntity<NotificationRuleAdminService.RuleMutation> create(
            @Valid @RequestBody NotificationRuleAdminService.RuleCommand command,
            @CurrentUser PlatformUser caller) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.create(command, caller));
    }

    @PutMapping("/{id}")
    public NotificationRuleAdminService.RuleMutation update(
            @PathVariable UUID id,
            @RequestParam int expectedVersion,
            @Valid @RequestBody NotificationRuleAdminService.RuleCommand command,
            @CurrentUser PlatformUser caller) {
        return service.update(id, expectedVersion, command, caller);
    }

    @DeleteMapping("/{id}")
    public NotificationRuleAdminService.RuleMutation delete(
            @PathVariable UUID id,
            @RequestParam int expectedVersion,
            @CurrentUser PlatformUser caller) {
        return service.delete(id, expectedVersion, caller);
    }
}
