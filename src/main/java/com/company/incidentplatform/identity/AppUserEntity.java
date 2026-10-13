package com.company.incidentplatform.identity;

import com.company.incidentplatform.security.PlatformRole;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * USER -- the synced identity projection (6.2.4, 7.1).
 *
 * <p>Holds the department, which Keycloak may know but which the authorization
 * rules consume directly, and the lifecycle state -- {@code active},
 * {@code disabled_at}, {@code disabled_reason} -- that 7.1 makes a
 * re-authorization trigger. Being deactivated is not a token problem; it is a
 * per-request authorization fact, and {@code CurrentUserStateService} consults
 * it on every request.
 *
 * <p>7.10 optimistic locking is on {@code version} so two Admins cannot silently
 * clobber a concurrent permission change -- relevant here because a permission
 * change is a security change.
 */
@Entity
@Table(name = "app_user")
public class AppUserEntity {

    @Id
    private UUID id;

    @Column(name = "keycloak_subject", nullable = false)
    private String keycloakSubject;

    @Column(name = "full_name", nullable = false)
    private String fullName;

    @Column(name = "email", nullable = false)
    private String email;

    /** 7.2.1: home department; scopes an Analyst's unassigned queue. */
    @Column(name = "department")
    private String department;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "role_id", nullable = false)
    private PlatformRoleEntity role;

    /** 7.1: deprovisioning / dormancy / manual disable all land here. */
    @Column(name = "active", nullable = false)
    private boolean active;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    /** Drives the 7.1 configurable inactivity check. */
    @Column(name = "last_login_at")
    private OffsetDateTime lastLoginAt;

    @Column(name = "disabled_at")
    private OffsetDateTime disabledAt;

    @Column(name = "disabled_reason")
    private String disabledReason;

    /**
     * 7.12: when this projection last matched the IdP claim. Drift between the
     * two systems is otherwise invisible until it becomes a support ticket.
     */
    @Column(name = "role_synced_at")
    private OffsetDateTime roleSyncedAt;

    @Version
    @Column(name = "version", nullable = false)
    private Integer version;

    protected AppUserEntity() {
        // for JPA
    }

    public UUID getId() {
        return id;
    }

    public String getKeycloakSubject() {
        return keycloakSubject;
    }

    public String getFullName() {
        return fullName;
    }

    public String getEmail() {
        return email;
    }

    public String getDepartment() {
        return department;
    }

    public PlatformRoleEntity getRole() {
        return role;
    }

    public PlatformRole coarseRole() {
        return role.getName();
    }

    public boolean isActive() {
        return active;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public OffsetDateTime getUpdatedAt() {
        return updatedAt;
    }

    public OffsetDateTime getLastLoginAt() {
        return lastLoginAt;
    }

    public OffsetDateTime getDisabledAt() {
        return disabledAt;
    }

    public String getDisabledReason() {
        return disabledReason;
    }

    public OffsetDateTime getRoleSyncedAt() {
        return roleSyncedAt;
    }
}
