package com.company.incidentplatform.notification;

import java.util.List;
import java.util.UUID;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface NotificationRuleRepository extends JpaRepository<NotificationRuleEntity, UUID> {
    List<NotificationRuleEntity> findByEnabledTrueAndDeletedAtIsNull();

    Optional<NotificationRuleEntity> findByIdAndDeletedAtIsNull(UUID id);

    Page<NotificationRuleEntity> findByDeletedAtIsNull(Pageable pageable);
}
