package com.company.incidentplatform.identity;

import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.audit.RequestContext;
import com.company.incidentplatform.authorization.AuthorizationDeniedException;
import com.company.incidentplatform.authorization.Capability;
import com.company.incidentplatform.incident.IncidentSeverity;
import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.PlatformUser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AdminConfigurationService {

    private final JdbcTemplate jdbc;
    private final AuditService audit;
    private final ObjectMapper json;

    public AdminConfigurationService(JdbcTemplate jdbc, AuditService audit, ObjectMapper json) {
        this.jdbc = jdbc;
        this.audit = audit;
        this.json = json;
    }

    @Transactional(readOnly = true)
    public List<Map<String, Object>> categories(PlatformUser caller) {
        require(caller, Capability.MANAGE_CATEGORIES, "incident_category", null);
        return jdbc.queryForList("""
                SELECT id, name, description, default_sla_hours, retention_months,
                       max_evidence_size_bytes, max_evidence_files, is_active, version
                  FROM incident_platform.incident_category
                 WHERE deleted_at IS NULL
                 ORDER BY name
                """);
    }

    @Transactional(readOnly = true)
    public List<Map<String, Object>> activeCategories() {
        return jdbc.queryForList("""
                SELECT id, name, description
                  FROM incident_platform.incident_category
                 WHERE deleted_at IS NULL AND is_active = true
                 ORDER BY name
                """);
    }

    @Transactional
    public Map<String, Object> createCategory(CategoryCommand command, PlatformUser caller) {
        require(caller, Capability.MANAGE_CATEGORIES, "incident_category", null);
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO incident_platform.incident_category
                    (id, name, description, default_sla_hours, retention_months,
                     max_evidence_size_bytes, max_evidence_files, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, coalesce(?, true))
                """,
                id,
                command.name().trim(),
                blankToNull(command.description()),
                command.defaultSlaHours(),
                command.retentionMonths(),
                command.maxEvidenceSizeBytes(),
                command.maxEvidenceFiles(),
                command.active());
        audit(caller, "incident_category", id, "admin.category.create", null,
                categoryAudit(command, true));
        return category(id);
    }

    @Transactional
    public Map<String, Object> updateCategory(UUID id, CategoryCommand command, Integer expectedVersion,
            PlatformUser caller) {
        require(caller, Capability.MANAGE_CATEGORIES, "incident_category", id);
        Map<String, Object> before = findCategory(id);
        int changed = jdbc.update("""
                UPDATE incident_platform.incident_category
                   SET name = ?, description = ?, default_sla_hours = ?, retention_months = ?,
                       max_evidence_size_bytes = ?, max_evidence_files = ?,
                       is_active = coalesce(?, is_active), version = version + 1
                 WHERE id = ? AND deleted_at IS NULL AND version = ?
                """,
                command.name().trim(),
                blankToNull(command.description()),
                command.defaultSlaHours(),
                command.retentionMonths(),
                command.maxEvidenceSizeBytes(),
                command.maxEvidenceFiles(),
                command.active(),
                id,
                expectedVersion);
        if (changed != 1) {
            throw new com.company.incidentplatform.error.ConflictException(
                    "Category changed since it was read; reload and reapply the change");
        }
        Map<String, Object> after = findCategory(id);
        audit(caller, "incident_category", id, "admin.category.update", before, after);
        return after;
    }

    @Transactional
    public void deleteCategory(UUID id, Integer expectedVersion, PlatformUser caller) {
        require(caller, Capability.MANAGE_CATEGORIES, "incident_category", id);
        Map<String, Object> before = findCategory(id);
        int changed = jdbc.update("""
                UPDATE incident_platform.incident_category
                   SET is_active = false, deleted_at = now(), version = version + 1
                 WHERE id = ? AND deleted_at IS NULL AND version = ?
                """, id, expectedVersion);
        if (changed != 1) {
            throw new com.company.incidentplatform.error.ConflictException(
                    "Category changed since it was read; reload and reapply the change");
        }
        audit(caller, "incident_category", id, "admin.category.soft_delete", before,
                Map.of("is_active", false, "deleted_at", "set"));
    }

    @Transactional(readOnly = true)
    public List<Map<String, Object>> allowedTypes(UUID categoryId, PlatformUser caller) {
        require(caller, Capability.MANAGE_CATEGORIES, "incident_category_allowed_type", categoryId);
        findCategory(categoryId);
        return jdbc.queryForList("""
                SELECT mime_type, extension FROM incident_platform.incident_category_allowed_type
                 WHERE category_id = ? ORDER BY mime_type
                """, categoryId);
    }

    @Transactional
    public List<Map<String, Object>> replaceAllowedTypes(
            UUID categoryId, List<AllowedTypeCommand> commands, PlatformUser caller) {
        require(caller, Capability.MANAGE_CATEGORIES, "incident_category_allowed_type", categoryId);
        findCategory(categoryId);
        if (commands.size() > 32) {
            throw new IllegalArgumentException("At most 32 allowed evidence MIME types may be configured");
        }
        List<Map<String, Object>> before = allowedTypes(categoryId, caller);
        jdbc.update("DELETE FROM incident_platform.incident_category_allowed_type WHERE category_id = ?",
                categoryId);
        for (AllowedTypeCommand command : commands) {
            String extension = command.extension() == null ? null
                    : command.extension().trim().replaceFirst("^\\.", "").toLowerCase(java.util.Locale.ROOT);
            jdbc.update("""
                    INSERT INTO incident_platform.incident_category_allowed_type
                        (category_id, mime_type, extension)
                    VALUES (?, ?, ?)
                    """, categoryId, command.mimeType().trim().toLowerCase(java.util.Locale.ROOT), extension);
        }
        List<Map<String, Object>> after = allowedTypes(categoryId, caller);
        audit(caller, "incident_category", categoryId, "admin.category.allowed_types.replace", before, after);
        return after;
    }

    @Transactional(readOnly = true)
    public List<Map<String, Object>> translations(UUID categoryId, PlatformUser caller) {
        require(caller, Capability.MANAGE_CATEGORIES, "incident_category_translation", categoryId);
        findCategory(categoryId);
        return jdbc.queryForList("""
                SELECT locale, name, description FROM incident_platform.incident_category_translation
                 WHERE category_id = ? ORDER BY locale
                """, categoryId);
    }

    @Transactional
    public List<Map<String, Object>> replaceTranslations(
            UUID categoryId, List<CategoryTranslationCommand> commands, PlatformUser caller) {
        require(caller, Capability.MANAGE_CATEGORIES, "incident_category_translation", categoryId);
        findCategory(categoryId);
        if (commands.size() > 32) {
            throw new IllegalArgumentException("At most 32 category translations may be configured");
        }
        List<Map<String, Object>> before = translations(categoryId, caller);
        jdbc.update("DELETE FROM incident_platform.incident_category_translation WHERE category_id = ?",
                categoryId);
        for (CategoryTranslationCommand command : commands) {
            jdbc.update("""
                    INSERT INTO incident_platform.incident_category_translation
                        (category_id, locale, name, description)
                    VALUES (?, ?, ?, ?)
                    """, categoryId, command.locale(), command.name().trim(), blankToNull(command.description()));
        }
        List<Map<String, Object>> after = translations(categoryId, caller);
        audit(caller, "incident_category", categoryId, "admin.category.translations.replace", before, after);
        return after;
    }

    @Transactional(readOnly = true)
    public List<Map<String, Object>> severityMatrix(PlatformUser caller) {
        require(caller, Capability.MANAGE_SEVERITY_MATRIX, "severity_matrix_rule", null);
        return jdbc.queryForList("""
                SELECT id, impact, likelihood, severity, justification, is_active, updated_at
                  FROM incident_platform.severity_matrix_rule
                 ORDER BY impact, likelihood
                """);
    }

    @Transactional
    public Map<String, Object> upsertSeverityRule(SeverityRuleCommand command, PlatformUser caller) {
        require(caller, Capability.MANAGE_SEVERITY_MATRIX, "severity_matrix_rule", null);
        validateRank(command.impact(), "impact");
        validateRank(command.likelihood(), "likelihood");
        Map<String, Object> before = jdbc.query("""
                SELECT id, impact, likelihood, severity, justification, is_active
                  FROM incident_platform.severity_matrix_rule
                 WHERE impact = ? AND likelihood = ?
                """,
                rs -> rs.next() ? rowMap(rs) : null,
                command.impact(), command.likelihood());
        UUID id = jdbc.query("""
                INSERT INTO incident_platform.severity_matrix_rule
                    (impact, likelihood, severity, justification, is_active)
                VALUES (?, ?, ?::incident_platform.incident_severity, ?, ?)
                ON CONFLICT (impact, likelihood) DO UPDATE
                   SET severity = EXCLUDED.severity,
                       justification = EXCLUDED.justification,
                       is_active = EXCLUDED.is_active
                RETURNING id
                """,
                rs -> rs.next() ? rs.getObject(1, UUID.class) : null,
                command.impact(),
                command.likelihood(),
                command.severity().name(),
                blankToNull(command.justification()),
                command.active());
        Map<String, Object> after = jdbc.queryForMap("""
                SELECT id, impact, likelihood, severity, justification, is_active
                  FROM incident_platform.severity_matrix_rule WHERE id = ?
                """, id);
        audit(caller, "severity_matrix_rule", id, "admin.severity_matrix.upsert", before, after);
        return after;
    }

    @Transactional(readOnly = true)
    public List<Map<String, Object>> slaPolicies(PlatformUser caller) {
        require(caller, Capability.MANAGE_SLA, "incident_sla_policy", null);
        return jdbc.queryForList("""
                SELECT id, category_id, severity, response_sla_minutes, resolution_sla_minutes,
                       business_hours_only, is_active, updated_at
                  FROM incident_platform.incident_sla_policy
                 ORDER BY category_id NULLS FIRST, severity
                """);
    }

    @Transactional
    public Map<String, Object> upsertSlaPolicy(SlaPolicyCommand command, PlatformUser caller) {
        require(caller, Capability.MANAGE_SLA, "incident_sla_policy", null);
        if (command.categoryId() != null) {
            findCategory(command.categoryId());
        }
        Map<String, Object> before = jdbc.query("""
                SELECT id, category_id, severity, response_sla_minutes, resolution_sla_minutes,
                       business_hours_only, is_active
                  FROM incident_platform.incident_sla_policy
                 WHERE category_id IS NOT DISTINCT FROM ?
                   AND severity = ?::incident_platform.incident_severity
                   AND is_active
                """,
                rs -> rs.next() ? rowMap(rs) : null,
                command.categoryId(), command.severity().name());
        UUID id = jdbc.query("""
                INSERT INTO incident_platform.incident_sla_policy
                    (category_id, severity, response_sla_minutes, resolution_sla_minutes,
                     business_hours_only, is_active)
                VALUES (?, ?::incident_platform.incident_severity, ?, ?, ?, ?)
                ON CONFLICT (
                    (COALESCE(category_id, '00000000-0000-0000-0000-000000000000'::uuid)), severity
                ) WHERE is_active
                DO UPDATE SET response_sla_minutes = EXCLUDED.response_sla_minutes,
                              resolution_sla_minutes = EXCLUDED.resolution_sla_minutes,
                              business_hours_only = EXCLUDED.business_hours_only
                RETURNING id
                """,
                rs -> rs.next() ? rs.getObject(1, UUID.class) : null,
                command.categoryId(),
                command.severity().name(),
                command.responseSlaMinutes(),
                command.resolutionSlaMinutes(),
                command.businessHoursOnly(),
                true);
        Map<String, Object> after = jdbc.queryForMap("""
                SELECT id, category_id, severity, response_sla_minutes, resolution_sla_minutes,
                       business_hours_only, is_active
                  FROM incident_platform.incident_sla_policy WHERE id = ?
                """, id);
        audit(caller, "incident_sla_policy", id, "admin.sla_policy.upsert", before, after);
        return after;
    }

    @Transactional
    public Map<String, Object> legalHold(UUID incidentId, boolean hold, String reason,
            Integer expectedVersion, PlatformUser caller) {
        require(caller, Capability.MANAGE_RETENTION, "incident", incidentId);
        Map<String, Object> before = jdbc.queryForMap("""
                SELECT id, legal_hold, legal_hold_reason, legal_hold_set_at, version
                  FROM incident_platform.incident WHERE id = ? AND deleted_at IS NULL
                """, incidentId);
        if (hold && (reason == null || reason.isBlank())) {
            throw new IllegalArgumentException("A reason is required to set a legal hold");
        }
        int changed = jdbc.update("""
                UPDATE incident_platform.incident
                   SET legal_hold = ?,
                       legal_hold_reason = CASE WHEN ? THEN ? ELSE NULL END,
                       legal_hold_set_at = CASE WHEN ? THEN now() ELSE NULL END,
                       version = version + 1
                 WHERE id = ? AND version = ?
                """,
                hold, hold, blankToNull(reason), hold, incidentId, expectedVersion);
        if (changed != 1) {
            throw new com.company.incidentplatform.error.ConflictException(
                    "Incident changed since it was read; reload and reapply the legal-hold change");
        }
        Map<String, Object> after = jdbc.queryForMap("""
                SELECT id, legal_hold, legal_hold_reason, legal_hold_set_at, version
                  FROM incident_platform.incident WHERE id = ?
                """, incidentId);
        audit(caller, "incident", incidentId, hold ? "admin.retention.legal_hold_set"
                : "admin.retention.legal_hold_released", before, after);
        return after;
    }

    private Map<String, Object> category(UUID id) {
        return findCategory(id);
    }

    private Map<String, Object> findCategory(UUID id) {
        try {
            return jdbc.queryForMap("""
                    SELECT id, name, description, default_sla_hours, retention_months,
                           max_evidence_size_bytes, max_evidence_files, is_active, version
                      FROM incident_platform.incident_category
                     WHERE id = ? AND deleted_at IS NULL
                    """, id);
        } catch (org.springframework.dao.EmptyResultDataAccessException e) {
            throw new com.company.incidentplatform.error.ResourceNotFoundException("incident_category", id);
        }
    }

    private void require(PlatformUser caller, Capability capability, String type, UUID id) {
        if (caller.permissions().isReadOnly()) {
            throw AuthorizationDeniedException.forReadOnlyRole(type, id);
        }
        if (!capability.isHeldBy(caller.permissions())) {
            throw AuthorizationDeniedException.forMissingCapability(capability, type, id);
        }
    }

    private void audit(PlatformUser caller, String type, UUID id, String action,
            Object before, Object after) {
        audit.recordChange(caller, type, id, action, RequestContext.endpoint(), RequestContext.method(),
                RequestContext.requestId().orElse(null), RequestContext.remoteAddress(),
                AuthorizationCheckType.FUNCTION_LEVEL, "capability.configuration_write",
                serialize(before), serialize(after), false);
    }

    private String serialize(Object value) {
        if (value == null) {
            return null;
        }
        try {
            return json.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not serialize configuration for audit", e);
        }
    }

    private static Map<String, Object> rowMap(java.sql.ResultSet rs) throws java.sql.SQLException {
        Map<String, Object> row = new java.util.LinkedHashMap<>();
        java.sql.ResultSetMetaData metadata = rs.getMetaData();
        for (int column = 1; column <= metadata.getColumnCount(); column++) {
            row.put(metadata.getColumnLabel(column), rs.getObject(column));
        }
        return row;
    }

    private static Map<String, Object> categoryAudit(CategoryCommand c, boolean active) {
        return Map.of(
                "name", c.name().trim(),
                "defaultSlaHours", c.defaultSlaHours(),
                "retentionMonths", c.retentionMonths(),
                "maxEvidenceSizeBytes", c.maxEvidenceSizeBytes(),
                "maxEvidenceFiles", c.maxEvidenceFiles(),
                "active", c.active() == null ? active : c.active());
    }

    private static void validateRank(int rank, String label) {
        if (rank < 1 || rank > 5) {
            throw new IllegalArgumentException(label + " rank must be in range 1..5");
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    public record CategoryCommand(
            @jakarta.validation.constraints.NotBlank @jakarta.validation.constraints.Size(max = 120) String name,
            @jakarta.validation.constraints.Size(max = 4000) String description,
            @jakarta.validation.constraints.Positive int defaultSlaHours,
            @jakarta.validation.constraints.Positive int retentionMonths,
            @jakarta.validation.constraints.Positive long maxEvidenceSizeBytes,
            @jakarta.validation.constraints.Positive int maxEvidenceFiles,
            Boolean active) {
    }

    public record AllowedTypeCommand(
            @jakarta.validation.constraints.NotBlank
            @jakarta.validation.constraints.Pattern(regexp = "^[A-Za-z0-9.+-]+/[A-Za-z0-9.+*-]+$")
            @jakarta.validation.constraints.Size(max = 100) String mimeType,
            @jakarta.validation.constraints.Pattern(regexp = "^\\.?[A-Za-z0-9]{1,20}$")
            String extension) {
    }

    public record CategoryTranslationCommand(
            @jakarta.validation.constraints.NotBlank
            @jakarta.validation.constraints.Pattern(regexp = "^[a-z]{2}(-[A-Z]{2})?$")
            String locale,
            @jakarta.validation.constraints.NotBlank @jakarta.validation.constraints.Size(max = 120) String name,
            @jakarta.validation.constraints.Size(max = 4000) String description) {
    }

    public record SeverityRuleCommand(
            @jakarta.validation.constraints.Min(1) @jakarta.validation.constraints.Max(5) int impact,
            @jakarta.validation.constraints.Min(1) @jakarta.validation.constraints.Max(5) int likelihood,
            @jakarta.validation.constraints.NotNull IncidentSeverity severity,
            @jakarta.validation.constraints.Size(max = 1000) String justification,
            boolean active) {
    }

    public record SlaPolicyCommand(
            UUID categoryId,
            @jakarta.validation.constraints.NotNull IncidentSeverity severity,
            @jakarta.validation.constraints.Positive int responseSlaMinutes,
            @jakarta.validation.constraints.Positive Integer resolutionSlaMinutes,
            boolean businessHoursOnly) {
    }
}
