ALTER TABLE incident_platform.notification_rule
    ADD COLUMN created_by UUID REFERENCES incident_platform.app_user(id),
    ADD COLUMN updated_by UUID REFERENCES incident_platform.app_user(id),
    ADD COLUMN deleted_by UUID REFERENCES incident_platform.app_user(id);

ALTER TABLE incident_platform.notification_rule
    ADD CONSTRAINT notification_rule_severity_threshold_check
    CHECK (event_type <> 'SEVERITY_CHANGED' OR min_severity IS NOT NULL);

UPDATE incident_platform.platform_role
SET permissions = jsonb_set(
        coalesce(permissions, '{}'::jsonb),
        '{can_manage_notification_rules}',
        CASE WHEN name = 'SECURITY_ADMIN' THEN 'true'::jsonb ELSE 'false'::jsonb END,
        true);
