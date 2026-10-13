package com.company.incidentplatform.identity;

import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PlatformRoleRepository extends JpaRepository<PlatformRoleEntity, UUID> {

    java.util.Optional<PlatformRoleEntity> findByName(
            com.company.incidentplatform.security.PlatformRole name);
}
