package com.company.incidentplatform.notification;

import com.company.incidentplatform.identity.AppUserEntity;
import com.company.incidentplatform.identity.AppUserRepository;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class NotificationDeliveryService {

    private final NotificationRepository notifications;
    private final NotificationDeliveryDedupeRepository dedupe;
    private final AppUserRepository users;
    private final JavaMailSender mailSender;
    private final boolean emailEnabled;
    private final String fromAddress;
    private final String incidentBaseUrl;

    public NotificationDeliveryService(
            NotificationRepository notifications,
            NotificationDeliveryDedupeRepository dedupe,
            AppUserRepository users,
            JavaMailSender mailSender,
            @Value("${incident-platform.notifications.email.enabled:false}") boolean emailEnabled,
            @Value("${incident-platform.notifications.email.from:no-reply@incident-platform.local}")
                    String fromAddress,
            @Value("${incident-platform.notifications.email.incident-base-url:http://localhost:8080/api/v1/incidents}")
                    String incidentBaseUrl) {
        this.notifications = notifications;
        this.dedupe = dedupe;
        this.users = users;
        this.mailSender = mailSender;
        this.emailEnabled = emailEnabled;
        this.fromAddress = fromAddress;
        this.incidentBaseUrl = incidentBaseUrl.replaceAll("/+$", "");
    }

    @Transactional
    public void createInAppIfMissing(IncidentLifecycleEvent event, UUID recipientId) {
        String key = event.idempotencyKey();
        if (dedupe.findByIdempotencyKeyAndRecipientUserIdAndChannel(
                        key, recipientId, NotificationChannel.IN_APP).isPresent()) {
            return;
        }
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        dedupe.saveAndFlush(new NotificationDeliveryDedupeEntity(
                deliveryId(key, recipientId, NotificationChannel.IN_APP),
                key,
                recipientId,
                NotificationChannel.IN_APP,
                DeliveryDedupeStatus.SENT,
                messageId(key, recipientId),
                now));
        notifications.save(new NotificationEntity(
                deliveryId(key, recipientId, NotificationChannel.IN_APP),
                event.eventId(),
                event.incidentId(),
                recipientId,
                event.eventType(),
                NotificationChannel.IN_APP,
                NotificationDeliveryStatus.UNREAD,
                safeMessage(event),
                now));
    }

    @Transactional
    public boolean prepareEmailIfMissing(IncidentLifecycleEvent event, UUID recipientId) {
        var existing = dedupe.findByIdempotencyKeyAndRecipientUserIdAndChannel(
                event.idempotencyKey(), recipientId, NotificationChannel.EMAIL);
        if (existing.isPresent()) {
            return existing.get().getDeliveryStatus() == DeliveryDedupeStatus.PENDING;
        }

        AppUserEntity recipient = users.findById(recipientId)
                .orElseThrow(() -> new IllegalStateException("Notification recipient no longer exists: " + recipientId));
        if (!recipient.isActive()) {
            return false;
        }
        if (!emailEnabled) {
            if (!notifications.existsByEventIdAndRecipientUserIdAndChannel(
                    event.eventId(), recipientId, NotificationChannel.EMAIL)) {
                notifications.save(new NotificationEntity(
                        deliveryId(event.idempotencyKey(), recipientId, NotificationChannel.EMAIL),
                        event.eventId(),
                        event.incidentId(),
                        recipientId,
                        event.eventType(),
                        NotificationChannel.EMAIL,
                        NotificationDeliveryStatus.DISABLED,
                        safeMessage(event),
                        OffsetDateTime.now(ZoneOffset.UTC)));
            }
            return false;
        }
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        String stableMessageId = messageId(event.idempotencyKey(), recipientId);
        dedupe.saveAndFlush(new NotificationDeliveryDedupeEntity(
                deliveryId(event.idempotencyKey(), recipientId, NotificationChannel.EMAIL),
                event.idempotencyKey(),
                recipientId,
                NotificationChannel.EMAIL,
                DeliveryDedupeStatus.PENDING,
                stableMessageId,
                now));
        notifications.save(new NotificationEntity(
                deliveryId(event.idempotencyKey(), recipientId, NotificationChannel.EMAIL),
                event.eventId(),
                event.incidentId(),
                recipientId,
                event.eventType(),
                NotificationChannel.EMAIL,
                NotificationDeliveryStatus.QUEUED,
                safeMessage(event),
                now));
        return true;
    }

    @Transactional
    public void sendPendingEmail(IncidentLifecycleEvent event, UUID recipientId) {
        var locked = dedupe.lockDelivery(
                event.idempotencyKey(), recipientId, NotificationChannel.EMAIL);
        if (locked.isEmpty() || locked.get().getDeliveryStatus() == DeliveryDedupeStatus.SENT) {
            return;
        }

        AppUserEntity recipient = users.findById(recipientId)
                .orElseThrow(() -> new IllegalStateException("Notification recipient no longer exists: " + recipientId));
        if (!recipient.isActive() || recipient.getEmail() == null || recipient.getEmail().isBlank()) {
            throw new IllegalStateException("Notification recipient is inactive or has no email address: " + recipientId);
        }
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, StandardCharsets.UTF_8.name());
            helper.setFrom(fromAddress);
            helper.setTo(recipient.getEmail());
            helper.setSubject(emailSubject(event));
            helper.setText(safeMessage(event), false);
            message.setHeader("Message-ID", locked.get().getMessageId());
            mailSender.send(message);
        } catch (MessagingException e) {
            throw new IllegalStateException("Could not construct notification email", e);
        }

        locked.get().markSent(OffsetDateTime.now(ZoneOffset.UTC));
        NotificationEntity notification = notifications.findById(
                        deliveryId(event.idempotencyKey(), recipientId, NotificationChannel.EMAIL))
                .orElseThrow(() -> new IllegalStateException("Queued email notification record is missing"));
        notification.markSent();
    }

    private UUID deliveryId(String key, UUID recipient, NotificationChannel channel) {
        return UUID.nameUUIDFromBytes((key + ":" + recipient + ":" + channel).getBytes(StandardCharsets.UTF_8));
    }

    private String messageId(String key, UUID recipient) {
        UUID stable = UUID.nameUUIDFromBytes((key + ":" + recipient + ":EMAIL").getBytes(StandardCharsets.UTF_8));
        return "<" + stable + "@incident-platform.local>";
    }

    private String emailSubject(IncidentLifecycleEvent event) {
        return "[Incident Platform] " + event.eventType().name().replace('_', ' ').toLowerCase();
    }

    private String safeMessage(IncidentLifecycleEvent event) {
        return new NotificationRestrictedView(
                event.incidentId(),
                event.newSeverity() == null ? "UNCLASSIFIED" : event.newSeverity().name(),
                event.categoryId() == null ? "UNAVAILABLE" : event.categoryId().toString(),
                incidentBaseUrl + "/" + event.incidentId())
                .render();
    }

    private record NotificationRestrictedView(
            UUID incidentId, String severity, String category, String link) {

        private String render() {
            return "Incident ID: " + incidentId
                    + "\nSeverity: " + severity
                    + "\nCategory: " + category
                    + "\nLink: " + link;
        }
    }
}
