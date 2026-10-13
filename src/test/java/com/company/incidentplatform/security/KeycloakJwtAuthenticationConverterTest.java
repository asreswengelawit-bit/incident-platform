package com.company.incidentplatform.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;

class KeycloakJwtAuthenticationConverterTest {

    @Test
    void authenticationPrincipalIsTheResolvedPlatformUser() throws Exception {
        CurrentUserStateService userState = mock(CurrentUserStateService.class);
        ObjectMapper mapper = new ObjectMapper();
        PlatformUser user = new PlatformUser(
                UUID.randomUUID(),
                "subject",
                "admin@example.test",
                "Admin",
                null,
                PlatformRole.SECURITY_ADMIN,
                RolePermissions.fromJson(mapper.readTree("{\"can_manage_notification_rules\":true}")),
                true,
                false);
        when(userState.resolve(
                        eq("subject"),
                        eq("SECURITY_ADMIN"),
                        anyList(),
                        isNull(),
                        eq("admin@example.test"),
                        eq("Admin"),
                        isNull(),
                        any(Instant.class)))
                .thenReturn(new CurrentUserStateService.Resolution(user, null, "resolved"));
        Instant now = Instant.now();
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .subject("subject")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(60))
                .claim("realm_access", Map.of("roles", List.of("SECURITY_ADMIN")))
                .claim("email", "admin@example.test")
                .claim("name", "Admin")
                .build();

        Authentication authentication = new KeycloakJwtAuthenticationConverter(userState).convert(jwt);

        assertThat(authentication).isInstanceOf(PlatformJwtAuthenticationToken.class);
        assertThat(authentication.getPrincipal()).isSameAs(user);
    }
}
