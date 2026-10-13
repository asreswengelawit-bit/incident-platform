ALTER TABLE incident_platform.notification
    DROP CONSTRAINT notification_delivery_status_check;

ALTER TABLE incident_platform.notification
    ADD CONSTRAINT notification_delivery_status_check
    CHECK (delivery_status IN ('UNREAD', 'READ', 'QUEUED', 'SENT', 'DISABLED'));
