package com.company.incidentplatform.config;

import com.company.incidentplatform.authorization.GroupVisibilityPolicy;
import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Section 7 configuration. Defaults are the document's own stated values where
 * 7 gives one, and fail-closed where it does not.
 */
@ConfigurationProperties(prefix = "incident-platform")
public record PlatformSecurityProperties(
        /**
         * Full OIDC issuer URI ({@code https://host/realms/<realm>}), used for
         * both signature/issuer validation and JWKS discovery. Configurable as a
         * whole URL rather than assembled from a host and a realm name, so that
         * no environment can be served with a {@code localhost} issuer by
         * omission -- a hard-coded default here would validate tokens for a
         * developer realm and fail open to "no tokens validate at all" only by
         * accident of network topology.
         */
        @DefaultValue("http://localhost:8081/realms/incident-platform") String keycloakIssuer,
        @DefaultValue("incident-platform-api") String apiClientId,
        @DefaultValue("incident-platform-spa") String spaClientId,
        @DefaultValue List<String> allowedOrigins,
        @DefaultValue("PT30S") Duration userStateCacheTtl,
        @DefaultValue GroupVisibilityPolicy groupVisibilityPolicy,
        @DefaultValue("false") boolean trustForwardedFor,
        @DefaultValue("PT15M") Duration accessTokenExpectedLifetime,
        @DefaultValue("PT8H") Duration absoluteSessionTimeout,
        @DefaultValue("PT30M") Duration idleSessionTimeout,
        @DefaultValue("false") boolean reporterMfaRequired,
        @DefaultValue("mfa") String requiredAcr,
        @DefaultValue("PT30M") Duration auditPartitionLookahead,
        @DefaultValue List<String> actuatorUnauthenticatedPaths) {
}
