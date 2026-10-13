package com.company.incidentplatform.identity;

import com.company.incidentplatform.security.PlatformRole;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Reconciles active status, coarse roles, and departments from the authoritative
 * Keycloak directory. Requires a least-privilege client-credentials account.
 */
@Component
@ConditionalOnProperty(
        prefix = "incident-platform.identity.reconciliation",
        name = "enabled",
        havingValue = "true")
public class KeycloakIdentityReconciliationMonitor {

    private static final Logger log = LoggerFactory.getLogger(KeycloakIdentityReconciliationMonitor.class);

    private final RestClient client;
    private final KeycloakAdminTokenProvider tokenProvider;
    private final IdentityProjectionSyncService projections;
    private final String realm;
    private final int pageSize;
    private final int maxUsers;

    public KeycloakIdentityReconciliationMonitor(
            RestClient.Builder builder,
            KeycloakAdminTokenProvider tokenProvider,
            IdentityProjectionSyncService projections,
            @Value("${incident-platform.keycloak-admin.base-url:http://localhost:8081}") String baseUrl,
            @Value("${incident-platform.keycloak-admin.realm:incident-platform}") String realm,
            @Value("${incident-platform.identity.reconciliation.page-size:100}") int pageSize,
            @Value("${incident-platform.identity.reconciliation.max-users:20000}") int maxUsers) {
        if (pageSize < 1 || pageSize > 500 || maxUsers < pageSize) {
            throw new IllegalArgumentException("Identity sync requires page-size 1..500 and max-users >= page-size");
        }
        this.client = builder.baseUrl(baseUrl).build();
        this.tokenProvider = tokenProvider;
        this.projections = projections;
        this.realm = realm;
        this.pageSize = pageSize;
        this.maxUsers = maxUsers;
    }

    @Scheduled(
            fixedDelayString = "${incident-platform.identity.reconciliation.poll-interval-ms:300000}",
            initialDelayString = "${incident-platform.identity.reconciliation.initial-delay-ms:120000}")
    public void reconcile() {
        try {
            List<IdentityProjectionSyncService.ProviderIdentity> snapshot = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            int offset = 0;
            while (true) {
                List<JsonNode> page = fetchUsers(offset);
                for (JsonNode user : page) {
                    snapshot.add(mapUser(user, seen));
                }
                offset += page.size();
                if (page.size() < pageSize) {
                    break;
                }
                if (offset >= maxUsers) {
                    if (!fetchUsers(offset).isEmpty()) {
                        throw new IllegalStateException(
                                "Keycloak user snapshot exceeded the configured max-users limit; "
                                        + "refusing to run incomplete deprovisioning");
                    }
                    break;
                }
            }
            projections.reconcileSnapshot(snapshot);
            log.info("Reconciled {} Keycloak identity projections", snapshot.size());
        } catch (RuntimeException e) {
            // Build the complete snapshot before applying it, so a Keycloak or
            // database failure cannot trigger absence-based mass deprovisioning.
            log.error("Keycloak identity reconciliation failed; no incomplete snapshot was applied", e);
        }
    }

    private List<JsonNode> fetchUsers(int offset) {
        JsonNode response = client.get()
                .uri(uri -> uri.path("/admin/realms/{realm}/users")
                        .queryParam("first", offset)
                        .queryParam("max", pageSize)
                        .queryParam("briefRepresentation", false)
                        .build(realm))
                .accept(MediaType.APPLICATION_JSON)
                .headers(headers -> headers.setBearerAuth(tokenProvider.getToken()))
                .retrieve()
                .body(JsonNode.class);
        if (response == null || !response.isArray()) {
            throw new IllegalStateException("Keycloak returned an invalid user page");
        }
        List<JsonNode> users = new ArrayList<>();
        response.forEach(users::add);
        return users;
    }

    private IdentityProjectionSyncService.ProviderIdentity mapUser(JsonNode user, Set<String> seen) {
        String subject = user.path("id").asText("");
        if (subject.isBlank()) {
            throw new IllegalStateException("Keycloak user response omitted its subject");
        }
        seen.add(subject);
        boolean enabled = user.path("enabled").asBoolean(false);
        List<String> roles = fetchRealmRoles(subject).stream()
                .filter(role -> {
                    try {
                        PlatformRole.fromKeycloakRole(role);
                        return true;
                    } catch (IllegalArgumentException ignored) {
                        return false;
                    }
                })
                .distinct()
                .toList();

        String role = roles.size() == 1 ? roles.get(0) : null;
        if (roles.size() > 1) {
            log.error("Keycloak subject {} has multiple platform roles {}; deprovisioning its projection",
                    subject, roles);
        } else if (roles.isEmpty() && enabled) {
            log.error("Keycloak subject {} has no recognized platform role; access will be disabled", subject);
        }
        String department = user.path("attributes").path("department").isArray()
                ? user.path("attributes").path("department").path(0).asText(null)
                : null;
        String fullName = joinName(user.path("firstName").asText(null), user.path("lastName").asText(null));
        return new IdentityProjectionSyncService.ProviderIdentity(
                subject, role, user.path("email").asText(null), fullName, department, enabled);
    }

    private Set<String> fetchRealmRoles(String subject) {
        JsonNode response = client.get()
                .uri("/admin/realms/{realm}/users/{id}/role-mappings/realm", realm, subject)
                .accept(MediaType.APPLICATION_JSON)
                .headers(headers -> headers.setBearerAuth(tokenProvider.getToken()))
                .retrieve()
                .body(JsonNode.class);
        if (response == null || !response.isArray()) {
            throw new IllegalStateException("Keycloak returned an invalid realm-role mapping response");
        }
        Set<String> names = new LinkedHashSet<>();
        response.forEach(role -> names.add(role.path("name").asText("")));
        return names;
    }

    private static String joinName(String first, String last) {
        String full = ((first == null ? "" : first) + " " + (last == null ? "" : last)).trim();
        return full.isBlank() ? null : full;
    }
}
