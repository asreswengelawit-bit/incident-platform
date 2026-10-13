package com.company.incidentplatform.identity;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

/** Obtains and briefly caches a dedicated service-account token for identity sync. */
@Component
public class KeycloakAdminTokenProvider {

    private final RestClient client;
    private final String realm;
    private final String clientId;
    private final String clientSecret;
    private final Clock clock;
    private final AtomicReference<CachedToken> cached = new AtomicReference<>();

    public KeycloakAdminTokenProvider(
            RestClient.Builder builder,
            @Value("${incident-platform.keycloak-admin.base-url:http://localhost:8081}") String baseUrl,
            @Value("${incident-platform.keycloak-admin.realm:incident-platform}") String realm,
            @Value("${incident-platform.identity.reconciliation.client-id:}") String clientId,
            @Value("${incident-platform.identity.reconciliation.client-secret:}") String clientSecret,
            Clock clock) {
        this.client = builder.baseUrl(baseUrl).build();
        this.realm = realm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.clock = clock;
    }

    public synchronized String getToken() {
        CachedToken current = cached.get();
        if (current != null && current.expiresAt().isAfter(clock.instant().plusSeconds(30))) {
            return current.value();
        }
        if (clientId.isBlank() || clientSecret.isBlank()) {
            throw new IllegalStateException(
                    "Identity reconciliation requires a dedicated Keycloak client id and secret");
        }

        LinkedMultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        JsonNode response = client.post()
                .uri("/realms/{realm}/protocol/openid-connect/token", realm)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(JsonNode.class);
        if (response == null
                || response.path("access_token").asText("").isBlank()
                || response.path("expires_in").asInt(0) <= 0) {
            throw new IllegalStateException("Keycloak did not return a valid identity-sync service token");
        }

        String token = response.path("access_token").asText();
        Instant expiresAt = clock.instant().plusSeconds(response.path("expires_in").asLong());
        cached.set(new CachedToken(token, expiresAt));
        return token;
    }

    private record CachedToken(String value, Instant expiresAt) {
    }
}
