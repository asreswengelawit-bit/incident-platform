package com.company.incidentplatform.incident;

import java.util.UUID;

/**
 * What {@code POST /api/v1/incidents} returns.
 *
 * <p>A wrapper rather than the bare view for two reasons. The {@code id} is
 * needed to build a {@code Location} header and is otherwise buried in whichever
 * view type property-level authorization selected, so the controller would have
 * to know about the view hierarchy. And {@code replayed} carries 5.4's
 * at-most-once result to the caller: a retrying SIEM can tell "created" from
 * "already existed" without comparing ids against a previous attempt it may
 * never have seen the response to.
 *
 * @param view the role-scoped view; already property-filtered, never the entity
 */
public record CreateIncidentResult(
        UUID id,
        boolean replayed,
        IncidentSource source,
        Object view) {
}
