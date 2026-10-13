package com.company.incidentplatform.notification;

import com.company.incidentplatform.error.ResourceNotFoundException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class NotificationInboxService {

    private final NotificationRepository repository;

    public NotificationInboxService(NotificationRepository repository) {
        this.repository = repository;
    }

    @Transactional(readOnly = true)
    public List<NotificationView> listFor(UUID recipientUserId, int page, int size) {
        int safePage = Math.max(page, 0);
        int safeSize = Math.max(1, Math.min(size, 100));
        return repository.findByRecipientUserIdAndChannelOrderByCreatedAtDesc(
                        recipientUserId, NotificationChannel.IN_APP, PageRequest.of(safePage, safeSize))
                .map(NotificationView::from)
                .getContent();
    }

    @Transactional
    public void markRead(UUID id, UUID recipientUserId) {
        NotificationEntity notification = repository.findByIdAndRecipientUserIdAndChannel(
                        id, recipientUserId, NotificationChannel.IN_APP)
                .orElseThrow(() -> new ResourceNotFoundException("notification", id));
        notification.markRead(OffsetDateTime.now(ZoneOffset.UTC));
    }
}
