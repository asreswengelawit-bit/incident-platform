SET search_path TO incident_platform, public;

CREATE OR REPLACE FUNCTION incident_platform.audit_log_append(
    p_action                 text,
    p_entity_type            text,
    p_entity_id              uuid                     DEFAULT NULL,
    p_actor_id               uuid                     DEFAULT NULL,
    p_actor_role             incident_platform.platform_coarse_role DEFAULT NULL,
    p_actor_keycloak_subject text                     DEFAULT NULL,
    p_result                 incident_platform.audit_result DEFAULT 'ALLOWED',
    p_reason_code            text                     DEFAULT NULL,
    p_reason_detail          text                     DEFAULT NULL,
    p_endpoint               text                     DEFAULT NULL,
    p_method                 text                     DEFAULT NULL,
    p_request_id             uuid                     DEFAULT NULL,
    p_authorization_check    incident_platform.authorization_check_type DEFAULT 'NONE',
    p_authorization_rule     text                     DEFAULT NULL,
    p_ip_address             inet                     DEFAULT NULL,
    p_before_value           jsonb                    DEFAULT NULL,
    p_after_value            jsonb                    DEFAULT NULL,
    p_pii_redacted           boolean                  DEFAULT false,
    p_timestamp              timestamptz              DEFAULT NULL
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, incident_platform
AS $$
DECLARE
    v_id           uuid := gen_random_uuid();
    v_ts           timestamptz := coalesce(p_timestamp, now());
    v_prev_hash    bytea;
    v_prev_ts      timestamptz;
    v_entry_hash   bytea;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('incident_platform.audit_log_chain')::bigint);

    SELECT a.entry_hash, a.timestamp
      INTO v_prev_hash, v_prev_ts
      FROM incident_platform.audit_log a
     ORDER BY a.timestamp DESC, a.id DESC
     LIMIT 1;

    IF v_prev_ts IS NOT NULL AND v_ts <= v_prev_ts THEN
        v_ts := v_prev_ts + interval '1 microsecond';
    END IF;

    v_entry_hash := incident_platform.audit_log_entry_hash(
        v_id, v_ts, p_actor_id, p_actor_role, p_action, p_entity_type, p_entity_id,
        p_result, p_reason_code, p_endpoint, p_method, p_request_id,
        p_authorization_check, p_ip_address, p_before_value, p_after_value, v_prev_hash);

    INSERT INTO incident_platform.audit_log (
        id, timestamp, actor_id, actor_role, actor_keycloak_subject,
        entity_type, entity_id, action, before_value, after_value, ip_address,
        result, reason_code, reason_detail, endpoint, method, request_id,
        authorization_check, authorization_rule, pii_redacted,
        previous_hash, entry_hash
    ) VALUES (
        v_id, v_ts, p_actor_id, p_actor_role, p_actor_keycloak_subject,
        p_entity_type, p_entity_id, p_action, p_before_value, p_after_value, p_ip_address,
        p_result, p_reason_code, p_reason_detail, p_endpoint, p_method, p_request_id,
        p_authorization_check, p_authorization_rule, p_pii_redacted,
        v_prev_hash, v_entry_hash
    );

    RETURN v_id;
END;
$$;

COMMENT ON FUNCTION incident_platform.audit_log_append IS
    '7.11: the only sanctioned audit writer. Serializes on an advisory lock and advances timestamps by one microsecond when concurrent or backdated writes would otherwise violate hash-chain ordering.';
