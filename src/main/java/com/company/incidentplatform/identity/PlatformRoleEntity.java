package com.company.incidentplatform.identity;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * ROLE -- the application-side projection of a Keycloak realm role (6.2.4).
 *
 * <p>Not a second source of truth for the coarse role. Keycloak decides who is
 * an ANALYST; this row carries only the fine-grained business detail Keycloak
 * does not model (6.2.3), which is why {@code permissions} is jsonb rather than
 * a fixed set of columns: FR-6.2 lets an Admin reconfigure capabilities
 * without a migration or redeploy.
 */
@Entity
@Table(name = "platform_role")
public class PlatformRoleEntity {

    @Id
    private UUID id;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.NAMED_ENUM)
    @Column(name = "name", nullable = false)
    private com.company.incidentplatform.security.PlatformRole name;

    @Column(name = "display_name", nullable = false)
    private String displayName;

    @Column(name = "permissions", nullable = false, columnDefinition = "jsonb")
    private String permissions;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    protected PlatformRoleEntity() {
        // for JPA
    }

    public UUID getId() {
        return id;
    }

    public com.company.incidentplatform.security.PlatformRole getName() {
        return name;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getPermissions() {
        return permissions;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public OffsetDateTime getUpdatedAt() {
        return updatedAt;
    }

    /** Exposed so the JSON can be parsed with the application's configured ObjectMapper. */
    public JsonNode permissionsJson(com.fasterxml.jackson.databind.ObjectMapper mapper) {
        if (permissions == null || permissions.isBlank()) {
            return mapper.createObjectNode();
        }
        try {
            return mapper.readTree(permissions);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            // A malformed permissions blob must not be treated as "no
            // permissions" silently -- it is a configuration defect, and
            // swallowing it would surface later as a puzzling authorization
            // failure far from its cause.
            throw new IllegalStateException(
                    "platform_role.permissions for role '" + name + "' is not valid JSON", e);
        }
    }
}
