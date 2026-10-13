package com.company.incidentplatform.config;

import com.company.incidentplatform.audit.RequestContext;
import org.springframework.stereotype.Component;

/**
 * Publishes the deployment's trusted-proxy decision to {@link RequestContext}.
 *
 * <p>Exists because the decision is made once, in configuration, while the audit
 * paths that depend on it are static utility calls made from services that have
 * no business holding the security properties. Without it the value was repeated
 * as a literal {@code false} at each of those call sites, which is correct for
 * direct-to-internet deployments and silently wrong behind a proxy -- see
 * {@link RequestContext#trustForwardedFor(boolean)}.
 */
@Component
public class RequestContextConfiguration {

    public RequestContextConfiguration(PlatformSecurityProperties properties) {
        RequestContext.trustForwardedFor(properties.trustForwardedFor());
    }
}
