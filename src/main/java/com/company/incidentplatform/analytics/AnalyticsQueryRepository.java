package com.company.incidentplatform.analytics;

import com.company.incidentplatform.authorization.GroupVisibilityPolicy;
import com.company.incidentplatform.config.PlatformSecurityProperties;
import com.company.incidentplatform.incident.IncidentSeverity;
import com.company.incidentplatform.incident.IncidentStatus;
import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.security.VisibilityScope;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

/** Bounded, authorization-scoped incident projection for analytics and exports. */
@Repository
public class AnalyticsQueryRepository {

    private static final RowMapper<AnalyticsIncident> ROW_MAPPER = AnalyticsQueryRepository::mapRow;
    private static final int CSV_DESCRIPTION_LIMIT = 1_000;
    private static final int PDF_DESCRIPTION_LIMIT = 3_500;

    private final NamedParameterJdbcTemplate jdbc;
    private final GroupVisibilityPolicy groupVisibilityPolicy;

    public AnalyticsQueryRepository(
            NamedParameterJdbcTemplate jdbc, PlatformSecurityProperties securityProperties) {
        this.jdbc = jdbc;
        this.groupVisibilityPolicy = securityProperties.groupVisibilityPolicy();
    }

    public List<AnalyticsIncident> findVisibleCandidates(
            AnalyticsFilter filter, PlatformUser user, long offset, int limit, boolean includeDescription) {
        return query(filter, user, offset, limit, null, includeDescription ? CSV_DESCRIPTION_LIMIT : 0);
    }

    public List<AnalyticsIncident> findVisibleCandidate(
            UUID incidentId, PlatformUser user) {
        return query(
                new AnalyticsFilter(null, null, null, null, null, null),
                user,
                0,
                1,
                incidentId,
                PDF_DESCRIPTION_LIMIT);
    }

    private List<AnalyticsIncident> query(
            AnalyticsFilter filter,
            PlatformUser user,
            long offset,
            int limit,
            UUID incidentId,
            int descriptionLimit) {
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("userId", user.id())
                .addValue("offset", offset)
                .addValue("limit", limit)
                .addValue("descriptionLimit", descriptionLimit);
        List<String> predicates = new ArrayList<>();
        predicates.add("i.deleted_at IS NULL");

        String effectiveDepartment =
                "COALESCE(NULLIF(BTRIM(i.affected_department), ''), reporter.department)";
        String collaborator =
                "EXISTS (SELECT 1 FROM incident_collaborator c WHERE c.incident_id = i.id "
                        + "AND c.user_id = :userId AND c.removed_at IS NULL)";

        VisibilityScope scope = user.permissions().visibilityScope();
        switch (scope) {
            case OWN_INCIDENTS -> predicates.add("i.reporter_id = :userId");
            case ASSIGNED_AND_OWN_DEPARTMENT_UNASSIGNED -> {
                predicates.add("(i.assignee_id = :userId OR " + collaborator
                        + " OR (i.assignee_id IS NULL AND LOWER(" + effectiveDepartment + ") = :department))");
                params.addValue("department", user.department() == null ? "" : user.department().trim().toLowerCase());
                if (groupVisibilityPolicy == GroupVisibilityPolicy.GROUP_MEMBERSHIP) {
                    predicates.set(predicates.size() - 1, "(" + predicates.get(predicates.size() - 1)
                            + " OR (i.group_id IS NOT NULL AND EXISTS (SELECT 1 FROM incident grouped "
                            + "JOIN incident_collaborator gc ON gc.incident_id = grouped.id "
                            + "WHERE grouped.group_id = i.group_id AND gc.user_id = :userId "
                            + "AND gc.removed_at IS NULL)))");
                }
            }
            case LED_DEPARTMENTS -> {
                if (user.permissions().ledDepartments().isEmpty()) {
                    predicates.add(collaborator);
                } else {
                    predicates.add("(LOWER(" + effectiveDepartment + ") IN (:ledDepartments) OR " + collaborator + ")");
                    params.addValue(
                            "ledDepartments",
                            user.permissions().ledDepartments().stream()
                                    .map(value -> value.toLowerCase())
                                    .toList());
                }
            }
            case ORGANIZATION -> {
                // Admin and Auditor have organization-wide visibility.
            }
            case NONE -> predicates.add("1 = 0");
        }

        if (filter.status() != null) {
            predicates.add("i.status = :status");
            params.addValue("status", filter.status().name());
        }
        if (filter.severity() != null) {
            predicates.add("i.severity = :severity");
            params.addValue("severity", filter.severity().name());
        }
        if (filter.categoryId() != null) {
            predicates.add("i.category_id = :categoryId");
            params.addValue("categoryId", filter.categoryId());
        }
        if (filter.department() != null) {
            predicates.add("LOWER(" + effectiveDepartment + ") = :filterDepartment");
            params.addValue("filterDepartment", filter.department().toLowerCase());
        }
        if (filter.from() != null) {
            predicates.add("i.reported_at >= :from");
            params.addValue("from", Timestamp.from(filter.from()));
        }
        if (filter.to() != null) {
            predicates.add("i.reported_at <= :to");
            params.addValue("to", Timestamp.from(filter.to()));
        }
        if (incidentId != null) {
            predicates.add("i.id = :incidentId");
            params.addValue("incidentId", incidentId);
        }

        String sql = """
                SELECT i.id, i.title,
                       CASE WHEN :descriptionLimit = 0 THEN NULL
                            WHEN LENGTH(i.description) > :descriptionLimit
                                THEN LEFT(i.description, :descriptionLimit) || ' [truncated]'
                            ELSE i.description END AS description,
                       category.name AS category,
                       i.severity, i.status, i.reported_at, i.occurred_at, i.resolved_at,
                       i.affected_system, %s AS department, i.escalated, i.anonymous
                  FROM incident i
                  JOIN app_user reporter ON reporter.id = i.reporter_id
                  JOIN incident_category category ON category.id = i.category_id
                 WHERE %s
                 ORDER BY i.reported_at DESC, i.id
                 LIMIT :limit OFFSET :offset
                """.formatted(effectiveDepartment, String.join(" AND ", predicates));
        return jdbc.query(sql, params, ROW_MAPPER);
    }

    private static AnalyticsIncident mapRow(ResultSet rs, int rowNum) throws SQLException {
        return new AnalyticsIncident(
                rs.getObject("id", UUID.class),
                rs.getString("title"),
                rs.getString("description"),
                rs.getString("category"),
                enumValue(IncidentSeverity.class, rs.getString("severity")),
                enumValue(IncidentStatus.class, rs.getString("status")),
                dateTime(rs, "reported_at"),
                dateTime(rs, "occurred_at"),
                dateTime(rs, "resolved_at"),
                rs.getString("affected_system"),
                rs.getString("department"),
                rs.getBoolean("escalated"),
                rs.getBoolean("anonymous"));
    }

    private static OffsetDateTime dateTime(ResultSet rs, String column) throws SQLException {
        return rs.getObject(column, OffsetDateTime.class);
    }

    private static <E extends Enum<E>> E enumValue(Class<E> type, String value) {
        return value == null ? null : Enum.valueOf(type, value);
    }
}
