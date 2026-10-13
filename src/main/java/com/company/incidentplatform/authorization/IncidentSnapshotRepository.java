package com.company.incidentplatform.authorization;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/**
 * Loads {@link IncidentSnapshot}s for the object-level check.
 *
 * <p>Uses an explicit JDBC query rather than JPA here on purpose. This is the
 * hot authorization path -- it runs for every incident in every list response,
 * every page -- and what matters is that the query returns exactly the fields a
 * decision needs and nothing else. Loading whole entities would pull
 * descriptions, evidence-free aggregates, and audit-adjacent columns into memory
 * that the authorizer does not read, which is both slower and an invitation to
 * later serialise fields that should have been property-suppressed.
 *
 * <p>Collaborators arrive in the same round trip. Fetching them per incident
 * would be an N+1 query on a paged list; 7.2.1's cross-department rule has to
 * hold for every row in the page, so the decision needs them in bulk.
 */
@Repository
public class IncidentSnapshotRepository {

    private static final String SELECT_SNAPSHOT = """
            SELECT i.id                          AS id,
                   i.reporter_id                 AS reporter_id,
                   ru.department                 AS reporter_department,
                   i.affected_department         AS affected_department,
                   i.assignee_id                 AS assignee_id,
                   i.group_id                    AS group_id,
                   (i.deleted_at IS NOT NULL)    AS soft_deleted,
                   COALESCE(
                       (SELECT array_agg(c.user_id)
                          FROM incident_collaborator c
                         WHERE c.incident_id = i.id
                           AND c.removed_at IS NULL),
                       ARRAY[]::uuid[])           AS collaborator_ids
              FROM incident i
              JOIN app_user ru ON ru.id = i.reporter_id
            """;

    private static final RowMapper<IncidentSnapshot> SNAPSHOT_MAPPER = new SnapshotRowMapper();

    private final JdbcTemplate jdbc;

    public IncidentSnapshotRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<IncidentSnapshot> findById(UUID incidentId) {
        List<IncidentSnapshot> rows = jdbc.query(
                SELECT_SNAPSHOT + " WHERE i.id = ?", SNAPSHOT_MAPPER, incidentId);
        return rows.stream().findFirst();
    }

    /**
     * Batch form for list/search/export. Returns a map rather than a list
     * because the caller is filtering an already-paged result set and must not
     * be tempted to treat a missing id as "denied" when it actually means "not in
     * this page" -- the list query and this one must be given the same ids.
     */
    public Map<UUID, IncidentSnapshot> findAllByIds(Collection<UUID> incidentIds) {
        if (incidentIds == null || incidentIds.isEmpty()) {
            return Map.of();
        }
        // Typed as Object[] rather than UUID[] on purpose: JdbcTemplate's
        // queryForList/query(sql, RowMapper, Object... args) overload is varargs,
        // and passing a UUID[] silently binds it as a single sql.Array argument
        // instead of a parameter list -- which for `= ANY (?)` happens to work,
        // which is exactly why it is worth being explicit rather than lucky.
        List<IncidentSnapshot> rows = jdbc.query(
                SELECT_SNAPSHOT + " WHERE i.id = ANY (?)", SNAPSHOT_MAPPER, (Object[]) incidentIds.toArray(new UUID[0]));
        Map<UUID, IncidentSnapshot> byId = new HashMap<>(rows.size());
        for (IncidentSnapshot snapshot : rows) {
            byId.put(snapshot.id(), snapshot);
        }
        return byId;
    }

    /**
     * Whether a user participates in an Incident Group.
     *
     * <p>Only consulted when {@link GroupVisibilityPolicy#GROUP_MEMBERSHIP} is
     * selected. The default policy never calls it, so this is a guard against a
     * future configuration change silently turning campaign membership into a
     * visibility grant.
     *
     * <p>FLAGGED FOR REVIEW: "participates" is defined here as the user having
     * any visibility -- via assignment or collaboration -- of at least one other
     * incident in the group. There is no group_members table (see the Phase 1
     * decision on {@code incident_group}), so this is the only membership
     * signal the schema currently provides. If campaign membership is meant to
     * be a first-class concept, it needs its own table, which is a Phase 3
     * schema decision rather than something to infer here.
     */
    public boolean sharesGroupWith(UUID userId, UUID groupId) {
        Integer count = jdbc.queryForObject(
                """
                SELECT count(*)
                  FROM incident i
                  JOIN incident_collaborator c
                    ON c.incident_id = i.id AND c.removed_at IS NULL AND c.user_id = ?
                 WHERE i.group_id = ?
                """,
                Integer.class,
                userId,
                groupId);
        return count != null && count > 0;
    }

    private static final class SnapshotRowMapper implements RowMapper<IncidentSnapshot> {

        @Override
        public IncidentSnapshot mapRow(ResultSet rs, int rowNum) throws SQLException {
            Set<UUID> collaborators = readUuidArray(rs.getArray("collaborator_ids"));
            return new IncidentSnapshot(
                    (UUID) rs.getObject("id"),
                    (UUID) rs.getObject("reporter_id"),
                    rs.getString("reporter_department"),
                    rs.getString("affected_department"),
                    (UUID) rs.getObject("assignee_id"),
                    (UUID) rs.getObject("group_id"),
                    rs.getBoolean("soft_deleted"),
                    collaborators);
        }

        private static Set<UUID> readUuidArray(Array sqlArray) throws SQLException {
            if (sqlArray == null) {
                return Set.of();
            }
            Object raw = sqlArray.getArray();
            if (!(raw instanceof Object[] elements)) {
                return Set.of();
            }
            Set<UUID> ids = new LinkedHashSet<>(elements.length);
            List<UUID> ordered = new ArrayList<>(elements.length);
            for (Object element : elements) {
                if (element instanceof UUID uuid) {
                    ordered.add(uuid);
                }
            }
            ids.addAll(ordered);
            return ids;
        }
    }
}
