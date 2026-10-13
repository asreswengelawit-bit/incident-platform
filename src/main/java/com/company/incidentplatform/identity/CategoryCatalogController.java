package com.company.incidentplatform.identity;

import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Authenticated category catalog used by incident reporters.
 */
@RestController
@RequestMapping("/api/v1/categories")
public class CategoryCatalogController {

    private final AdminConfigurationService service;

    public CategoryCatalogController(AdminConfigurationService service) {
        this.service = service;
    }

    @GetMapping
    public List<Map<String, Object>> listActiveCategories() {
        return service.activeCategories();
    }
}
