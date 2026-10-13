package com.company.incidentplatform.security.lockout;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Section 7.1 -- reads the realm's brute-force parameters and the login event feed
 * from Keycloak's Admin REST API.
 *
 * <p>Reads parameters from the live realm rather than trusting a local copy; see
 * {@link BruteForcePolicy} for why a drifting local copy is the failure mode
 * worth designing against.
 *
 * <p>The client credential is a dedicated, read-only realm-management account, not
 * the application's own client secret and not an admin token (7.7/7.8: third-party
 * and integration access gets its own scoped credential). It arrives from the vault
 * at runtime and is never logged -- a value that can read every user in the realm
 * should not appear in a log line, an exception message, or a heap dump.
 */
public class KeycloakEventFeedClient {

    private static final Logger log = LoggerFactory.getLogger(KeycloakEventFeedClient.class);

    private final RestClient restClient;
    private final String realm;
    private final TokenSupplier bearerTokenSupplier;

    public KeycloakEventFeedClient(RestClient restClient, String realm, TokenSupplier bearerTokenSupplier) {
        this.restClient = restClient;
        this.realm = realm;
        this.bearerTokenSupplier = bearerTokenSupplier;
    }

    /** The realm's current brute-force configuration, or null if protection is off/absent. */
    public BruteForcePolicy fetchBruteForcePolicy() {
        JsonNode realmRepresentation = getJson("/admin/realms/" + realm);
        if (realmRepresentation == null) {
            return null;
        }
        return new BruteForcePolicy(
                realmRepresentation.path("failureFactor").asInt(0),
                realmRepresentation.path("waitIncrementSeconds").asLong(0L),
                realmRepresentation.path("maxFailureWaitSeconds").asLong(0L),
                realmRepresentation.path("maxDeltaTimeSeconds").asLong(0L),
                realmRepresentation.path("bruteForceProtected").asBoolean(false));
    }

    /**
     * The most recent login and login-error events, oldest first.
     *
     * <p>Bounded by {@code max} because this is an unauthenticated-toward-the-app
     * poll on a schedule: an unbounded read against a feed that retains events for
     * {@code eventsExpiration} seconds would be a memory-growth path in a
     * long-running pod.
     */
    public List<LoginEvent> fetchRecentLoginEvents(int max) {
        JsonNode events = getJson(
                "/admin/realms/" + realm + "/events?type=" + "LOGIN+LOGIN_ERROR&max=" + Math.max(1, max));
        List<LoginEvent> parsed = new ArrayList<>();
        if (events == null || !events.isArray()) {
            return parsed;
        }
        for (JsonNode event : events) {
            String type = event.path("type").asText("");
            boolean success = "LOGIN".equals(type);
            if (!success && !"LOGIN_ERROR".equals(type)) {
                continue;
            }
            String userId = event.path("userId").asText(null);
            if (userId == null || userId.isBlank()) {
                // A login error with no resolved user is not attributable to an
                // account, so it cannot be reconstructed into a per-user lockout.
                // 7.12 still wants anomalous failed logins surfaced, and the
                // unstructured feed remains available to the SIEM for that.
                continue;
            }
            parsed.add(new LoginEvent(
                    java.util.UUID.fromString(userId),
                    event.path("username").asText("unknown"),
                    success,
                    parseTimestamp(event)));
        }
        parsed.sort(java.util.Comparator.comparing(LoginEvent::occurredAt));
        return parsed;
    }

    /** A user's realm roles, for the 7.1 privileged-account paging decision. */
    public Set<String> fetchRealmRoles(java.util.UUID userId) {
        JsonNode user = getJson("/admin/realms/" + realm + "/users/" + userId);
        if (user == null) {
            return Set.of();
        }
        Set<String> roles = new java.util.LinkedHashSet<>();
        JsonNode realmRoles = user.path("realmRoles");
        if (realmRoles.isArray()) {
            for (JsonNode role : realmRoles) {
                roles.add(role.asText());
            }
        }
        return roles;
    }

    private Instant parseTimestamp(JsonNode event) {
        long epochMillis = event.path("time").asLong(0L);
        return epochMillis > 0 ? Instant.ofEpochMilli(epochMillis) : Instant.now();
    }

    private JsonNode getJson(String path) {
        try {
            String token = bearerTokenSupplier == null ? null : bearerTokenSupplier.call();
            if (token == null || token.isBlank()) {
                log.warn("Keycloak admin token unavailable; skipping {}", path);
                return null;
            }
            return restClient.get()
                    .uri(path)
                    .accept(MediaType.APPLICATION_JSON)
                    .headers(headers -> headers.setBearerAuth(token))
                    .retrieve()
                    .body(JsonNode.class);
        } catch (RestClientException e) {
            // Monitoring must never take the API down with it, and must never
            // throw into the scheduler and cancel all future runs.
            log.warn("Keycloak admin call to {} failed: {}", path, e.getMessage());
            return null;
        }
    }

    /**
     * @param occurredAt event time from the feed
     * @param success    true for LOGIN, false for LOGIN_ERROR
     */
    public record LoginEvent(java.util.UUID userId, String username, boolean success, Instant occurredAt) {
    }

    /** Supplies an access token for the management client, without this class knowing how it is obtained. */
    @FunctionalInterface
    public interface TokenSupplier {
        String call();
    }
}
