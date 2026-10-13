CREATE TABLE incident_platform.notification_outbox (
    id UUID PRIMARY KEY,
    event_type VARCHAR(40) NOT NULL
        CHECK (event_type IN ('STATUS_CHANGED', 'ESCALATED', 'ASSIGNED')),
    incident_id UUID NOT NULL REFERENCES incident_platform.incident(id),
    payload TEXT NOT NULL,
    status VARCHAR(24) NOT NULL
        CHECK (status IN ('PENDING', 'PUBLISHED', 'DEAD_LETTERED')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at TIMESTAMPTZ NOT NULL,
    available_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ,
    dead_lettered_at TIMESTAMPTZ,
    last_error VARCHAR(1000)
);

CREATE INDEX notification_outbox_ready_idx
    ON incident_platform.notification_outbox (available_at, created_at)
    WHERE status = 'PENDING';

CREATE TABLE incident_platform.notification (
    id UUID PRIMARY KEY,
    event_id UUID NOT NULL REFERENCES incident_platform.notification_outbox(id),
    incident_id UUID NOT NULL REFERENCES incident_platform.incident(id),
    recipient_user_id UUID NOT NULL REFERENCES incident_platform.app_user(id),
    event_type VARCHAR(40) NOT NULL
        CHECK (event_type IN ('STATUS_CHANGED', 'ESCALATED', 'ASSIGNED')),
    channel VARCHAR(16) NOT NULL CHECK (channel IN ('IN_APP', 'EMAIL')),
    delivery_status VARCHAR(16) NOT NULL CHECK (delivery_status IN ('UNREAD', 'READ', 'QUEUED', 'DISABLED')),
    message VARCHAR(500) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    read_at TIMESTAMPTZ,
    CONSTRAINT notification_delivery_unique UNIQUE (event_id, recipient_user_id, channel)
);

CREATE INDEX notification_recipient_recent_idx
    ON incident_platform.notification (recipient_user_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE ON
    incident_platform.notification_outbox,
    incident_platform.notification
TO incident_app;
