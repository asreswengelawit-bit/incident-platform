ALTER TABLE incident_platform.notification_outbox
    ADD COLUMN idempotency_key VARCHAR(240);

UPDATE incident_platform.notification_outbox
SET idempotency_key = 'event:' || id::text;

ALTER TABLE incident_platform.notification_outbox
    ALTER COLUMN idempotency_key SET NOT NULL;

ALTER TABLE incident_platform.notification_outbox
    ADD CONSTRAINT notification_outbox_idempotency_unique UNIQUE (idempotency_key);

ALTER TABLE incident_platform.notification_outbox
    DROP CONSTRAINT notification_outbox_event_type_check;

ALTER TABLE incident_platform.notification_outbox
    ADD CONSTRAINT notification_outbox_event_type_check
    CHECK (event_type IN (
        'STATUS_CHANGED', 'ESCALATED', 'ASSIGNED', 'INCIDENT_CREATED',
        'SEVERITY_CHANGED', 'SLA_BREACHED', 'SLA_AT_RISK'
    ));

ALTER TABLE incident_platform.notification
    DROP CONSTRAINT notification_event_type_check;

ALTER TABLE incident_platform.notification
    ADD CONSTRAINT notification_event_type_check
    CHECK (event_type IN (
        'STATUS_CHANGED', 'ESCALATED', 'ASSIGNED', 'INCIDENT_CREATED',
        'SEVERITY_CHANGED', 'SLA_BREACHED', 'SLA_AT_RISK'
    ));

ALTER TABLE incident_platform.incident
    ADD COLUMN sla_cycle INTEGER NOT NULL DEFAULT 0 CHECK (sla_cycle >= 0);

CREATE TABLE incident_platform.notification_rule (
    id UUID PRIMARY KEY,
    event_type VARCHAR(40) NOT NULL CHECK (event_type IN (
        'INCIDENT_CREATED', 'SEVERITY_CHANGED', 'ESCALATED', 'SLA_BREACHED', 'SLA_AT_RISK'
    )),
    min_severity incident_platform.incident_severity,
    category_id UUID REFERENCES incident_platform.incident_category(id),
    channel VARCHAR(16) NOT NULL CHECK (channel IN ('EMAIL', 'IN_APP')),
    recipient_role VARCHAR(32) NOT NULL CHECK (recipient_role IN ('SECURITY_LEAD', 'SECURITY_ADMIN')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX notification_rule_enabled_idx
    ON incident_platform.notification_rule (event_type, channel)
    WHERE enabled = TRUE AND deleted_at IS NULL;

CREATE TABLE incident_platform.notification_delivery_dedupe (
    id UUID PRIMARY KEY,
    idempotency_key VARCHAR(240) NOT NULL,
    recipient_user_id UUID NOT NULL REFERENCES incident_platform.app_user(id),
    channel VARCHAR(16) NOT NULL CHECK (channel IN ('EMAIL', 'IN_APP')),
    delivery_status VARCHAR(16) NOT NULL CHECK (delivery_status IN ('PENDING', 'SENT')),
    message_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT notification_delivery_dedupe_unique
        UNIQUE (idempotency_key, recipient_user_id, channel)
);

INSERT INTO incident_platform.notification_delivery_dedupe
    (id, idempotency_key, recipient_user_id, channel, delivery_status, message_id, created_at, updated_at)
SELECT gen_random_uuid(),
       outbox.idempotency_key,
       notification.recipient_user_id,
       notification.channel,
       CASE
           WHEN notification.channel = 'EMAIL' AND notification.delivery_status = 'QUEUED'
               THEN 'PENDING'
           ELSE 'SENT'
       END,
       '<' || md5(outbox.idempotency_key || ':' || notification.recipient_user_id::text || ':EMAIL')
           || '@incident-platform.local>',
       notification.created_at,
       now()
FROM incident_platform.notification notification
JOIN incident_platform.notification_outbox outbox ON outbox.id = notification.event_id
WHERE (notification.channel = 'EMAIL' AND notification.delivery_status IN ('QUEUED', 'SENT'))
   OR notification.channel = 'IN_APP'
ON CONFLICT (idempotency_key, recipient_user_id, channel) DO NOTHING;

GRANT SELECT, INSERT, UPDATE ON
    incident_platform.notification_delivery_dedupe,
    incident_platform.notification_rule
TO incident_app;

INSERT INTO incident_platform.notification_rule
    (id, event_type, min_severity, channel, recipient_role)
SELECT gen_random_uuid(), event_type, min_severity::incident_platform.incident_severity,
       channel, recipient_role
FROM (VALUES
    ('INCIDENT_CREATED', 'CRITICAL'),
    ('SEVERITY_CHANGED', 'CRITICAL'),
    ('ESCALATED', NULL),
    ('SLA_BREACHED', NULL)
) AS events(event_type, min_severity)
CROSS JOIN (VALUES ('EMAIL'), ('IN_APP')) AS channels(channel)
CROSS JOIN (VALUES ('SECURITY_LEAD'), ('SECURITY_ADMIN')) AS roles(recipient_role);
