package com.company.incidentplatform.security.lockout;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.client.RestClient;

/**
 * Section 7.1 -- wiring for brute-force lockout monitoring.
 *
 * <p>Scheduling is enabled here rather than on the application class so that unit
 * tests, which construct components directly, never start a poller. The poller
 * talks to Keycloak's Admin API on a timer; a test run that silently began polling
 * would be slow and non-deterministic, and would make a failure ambiguous between
 * "the control is broken" and "the control ran against a real realm".
 *
 * <p>Every value is an environment variable with no credential default. 7.8: a
 * missing secret must fail loudly at the point of use, never fall back to a
 * committed constant.
 */
@Configuration
@EnableScheduling
public class AccountLockoutMonitorConfig {

    @Bean
    public RestClient keycloakAdminRestClient(
            RestClient.Builder builder,
            @Value("${incident-platform.keycloak-admin.base-url:http://localhost:8081}") String baseUrl) {
        return builder.baseUrl(baseUrl).build();
    }

    /**
     * 7.7: a dedicated, read-only realm-management credential -- never the
     * application's own client secret and never an admin token, which are both
     * over-privileged for "read the brute-force settings and the login feed".
     * An empty token makes every call refuse and log rather than authenticate
     * with something hard-coded.
     */
    @Bean
    public KeycloakEventFeedClient keycloakEventFeedClient(
            RestClient keycloakAdminRestClient,
            @Value("${incident-platform.keycloak-admin.realm:incident-platform}") String realm,
            @Value("${incident-platform.keycloak-admin.token:}") String token) {
        return new KeycloakEventFeedClient(keycloakAdminRestClient, realm, () -> token.isBlank() ? null : token);
    }

    @Bean
    public BruteForceLockoutDetector bruteForceLockoutDetector() {
        return new BruteForceLockoutDetector();
    }
}
