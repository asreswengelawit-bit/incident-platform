package com.company.incidentplatform.identity;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AppUserRepository extends JpaRepository<AppUserEntity, UUID> {

    java.util.List<AppUserEntity> findByActiveTrueAndRole_Name(
            com.company.incidentplatform.security.PlatformRole role);

    Optional<AppUserEntity> findByKeycloakSubject(String keycloakSubject);

    Optional<AppUserEntity> findByEmail(String email);

    /**
     * 7.1 dormancy: accounts with no login inside the configured window.
     * Returned active-or-not, because the auto-disable job needs to be able to
     * report on, and skip, accounts it has already disabled.
     */
    @Query("""
            select u.id from AppUserEntity u
            where u.active = true
              and (u.lastLoginAt is null or u.lastLoginAt < :cutoff)
              and (u.createdAt < :cutoff)
            """)
    java.util.List<UUID> findDormantActiveUsers(
            @Param("cutoff") java.time.OffsetDateTime cutoff);
}
