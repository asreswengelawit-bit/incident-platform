package com.company.incidentplatform.identity;

import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.web.CurrentUser;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin")
public class AdminConfigurationController {

    private final AdminConfigurationService service;

    public AdminConfigurationController(AdminConfigurationService service) {
        this.service = service;
    }

    @GetMapping("/categories")
    public List<Map<String, Object>> categories(@CurrentUser PlatformUser caller) {
        return service.categories(caller);
    }

    @PostMapping("/categories")
    public ResponseEntity<Map<String, Object>> createCategory(
            @Valid @RequestBody AdminConfigurationService.CategoryCommand command,
            @CurrentUser PlatformUser caller) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.createCategory(command, caller));
    }

    @PutMapping("/categories/{id}")
    public Map<String, Object> updateCategory(
            @PathVariable UUID id,
            @RequestParam int expectedVersion,
            @Valid @RequestBody AdminConfigurationService.CategoryCommand command,
            @CurrentUser PlatformUser caller) {
        return service.updateCategory(id, command, expectedVersion, caller);
    }

    @DeleteMapping("/categories/{id}")
    public ResponseEntity<Void> deleteCategory(
            @PathVariable UUID id,
            @RequestParam int expectedVersion,
            @CurrentUser PlatformUser caller) {
        service.deleteCategory(id, expectedVersion, caller);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/categories/{id}/allowed-types")
    public List<Map<String, Object>> allowedTypes(
            @PathVariable UUID id, @CurrentUser PlatformUser caller) {
        return service.allowedTypes(id, caller);
    }

    @PutMapping("/categories/{id}/allowed-types")
    public List<Map<String, Object>> replaceAllowedTypes(
            @PathVariable UUID id,
            @Valid @RequestBody List<AdminConfigurationService.AllowedTypeCommand> commands,
            @CurrentUser PlatformUser caller) {
        return service.replaceAllowedTypes(id, commands, caller);
    }

    @GetMapping("/categories/{id}/translations")
    public List<Map<String, Object>> translations(
            @PathVariable UUID id, @CurrentUser PlatformUser caller) {
        return service.translations(id, caller);
    }

    @PutMapping("/categories/{id}/translations")
    public List<Map<String, Object>> replaceTranslations(
            @PathVariable UUID id,
            @Valid @RequestBody List<AdminConfigurationService.CategoryTranslationCommand> commands,
            @CurrentUser PlatformUser caller) {
        return service.replaceTranslations(id, commands, caller);
    }

    @GetMapping("/severity-matrix")
    public List<Map<String, Object>> severityMatrix(@CurrentUser PlatformUser caller) {
        return service.severityMatrix(caller);
    }

    @PutMapping("/severity-matrix")
    public Map<String, Object> upsertSeverityRule(
            @Valid @RequestBody AdminConfigurationService.SeverityRuleCommand command,
            @CurrentUser PlatformUser caller) {
        return service.upsertSeverityRule(command, caller);
    }

    @GetMapping("/sla-policies")
    public List<Map<String, Object>> slaPolicies(@CurrentUser PlatformUser caller) {
        return service.slaPolicies(caller);
    }

    @PutMapping("/sla-policies")
    public Map<String, Object> upsertSlaPolicy(
            @Valid @RequestBody AdminConfigurationService.SlaPolicyCommand command,
            @CurrentUser PlatformUser caller) {
        return service.upsertSlaPolicy(command, caller);
    }

    @PutMapping("/incidents/{incidentId}/legal-hold")
    public Map<String, Object> legalHold(
            @PathVariable UUID incidentId,
            @Valid @RequestBody LegalHoldCommand command,
            @CurrentUser PlatformUser caller) {
        return service.legalHold(
                incidentId, command.hold(), command.reason(), command.expectedVersion(), caller);
    }

    public record LegalHoldCommand(boolean hold, String reason,
            @jakarta.validation.constraints.NotNull Integer expectedVersion) {
    }
}
