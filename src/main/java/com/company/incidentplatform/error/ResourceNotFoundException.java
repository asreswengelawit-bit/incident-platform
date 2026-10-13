package com.company.incidentplatform.error;

/**
 * A named resource does not exist, or the caller's authorization has already
 * been checked and the lookup found nothing.
 *
 * <p>Exists so a 404 is a decision rather than an accident of which exception a
 * repository lookup happened to throw. The services previously threw bare
 * {@link IllegalArgumentException} for "not found", which mapped to a 400 and
 * drew a false distinction from the 403 that 7.2's BOLA check produces.
 *
 * <p>The distinction this type must <em>not</em> blur: a caller who failed an
 * object-level check gets a 403 and no lookup is performed at all, so no code
 * path can reveal existence to a caller who is not entitled to know it. A 404
 * from this class therefore only ever reaches a caller who could already see
 * the record.
 */
public class ResourceNotFoundException extends RuntimeException {

    private final String resourceType;
    private final String resourceId;

    public ResourceNotFoundException(String resourceType, Object resourceId) {
        super(resourceType + " not found: " + resourceId);
        this.resourceType = resourceType;
        this.resourceId = String.valueOf(resourceId);
    }

    public String resourceType() {
        return resourceType;
    }

    public String resourceId() {
        return resourceId;
    }
}
