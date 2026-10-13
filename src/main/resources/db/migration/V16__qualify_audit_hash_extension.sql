SET search_path TO incident_platform, public;

CREATE OR REPLACE FUNCTION incident_platform.audit_log_entry_hash(
    p_id                  uuid,
    p_timestamp           timestamptz,
    p_actor_id            uuid,
    p_actor_role          incident_platform.platform_coarse_role,
    p_action              text,
    p_entity_type         text,
    p_entity_id           uuid,
    p_result              incident_platform.audit_result,
    p_reason_code         text,
    p_endpoint            text,
    p_method              text,
    p_request_id          uuid,
    p_authorization_check incident_platform.authorization_check_type,
    p_ip_address          inet,
    p_before_value        jsonb,
    p_after_value         jsonb,
    p_previous_hash       bytea
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT incident_platform.digest(
        coalesce(p_id::text, '') || '|'
        || coalesce(to_char(p_timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '') || '|'
        || coalesce(p_actor_id::text, '') || '|'
        || coalesce(p_actor_role::text, '') || '|'
        || coalesce(p_action, '') || '|'
        || coalesce(p_entity_type, '') || '|'
        || coalesce(p_entity_id::text, '') || '|'
        || coalesce(p_result::text, '') || '|'
        || coalesce(p_reason_code, '') || '|'
        || coalesce(p_endpoint, '') || '|'
        || coalesce(p_method, '') || '|'
        || coalesce(p_request_id::text, '') || '|'
        || coalesce(p_authorization_check::text, '') || '|'
        || coalesce(host(p_ip_address), '') || '|'
        || coalesce(p_before_value::text, '') || '|'
        || coalesce(p_after_value::text, '') || '|'
        || coalesce(encode(p_previous_hash, 'hex'), ''),
        'sha256'
    );
$$;
