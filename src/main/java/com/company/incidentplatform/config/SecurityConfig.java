package com.company.incidentplatform.config;

import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.audit.RequestContext;
import com.company.incidentplatform.authorization.AuthorizationDeniedException;
import com.company.incidentplatform.authorization.GroupVisibilityPolicy;
import com.company.incidentplatform.authorization.IncidentObjectAuthorizer;
import com.company.incidentplatform.authorization.IncidentSnapshotRepository;
import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.DeniedReason;
import com.company.incidentplatform.security.MfaVerifier;
import com.company.incidentplatform.security.PlatformUser;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Section 7.5 -- HTTP security configuration.
 *
 * <p>The decisions that matter, and why:
 *
 * <ul>
 *   <li><b>Stateless, no sessions</b> (Section 4). Authorization is re-evaluated
 *       per request from current state, so a server-side session would add state
 *       to invalidate without adding any security, and would make horizontal
 *       scaling of the API pod sticky.</li>
 *   <li><b>CSRF disabled</b>, deliberately and explicitly. 7.5 requires that
 *       cross-site request forgery protection be configured and <em>verified</em>
 *       for a browser session, and that disabling it be justified. The
 *       justification: the API is a pure OAuth2 bearer-token resource server that
 *       never authenticates a request from a cookie or ambient credential, so
 *       there is no ambient authority for a cross-site page to ride on. The token
 *       is sent in an {@code Authorization} header, which a cross-origin
 *       <em>form</em> post cannot set. This is a consequence of choosing
 *       bearer tokens, not a blanket relaxation -- and it is asserted in the
 *       integration tests so a future change to cookie authentication fails
 *       loudly rather than silently reintroducing CSRF exposure.</li>
 *   <li><b>Security headers</b> per 7.5. Same-origin policy is the primary
 *       defence here: CSP is set to deny framing, and the API is not intended to
 *       serve the SPA's HTML at all.</li>
 * </ul>
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final PlatformSecurityProperties props;

    /**
     * Only the properties are constructor-injected. {@code AuditService} and
     * {@code KeycloakJwtAuthenticationConverter} are taken as parameters of
     * {@link #filterChain} instead, and that is load-bearing rather than stylistic.
     *
     * <p>A {@code @Configuration} class is needed to build the beans everything else
     * depends on, so constructor-injecting a collaborator into it can close a cycle
     * that Spring cannot break. These two did: {@code filterChain} needs the JWT
     * converter, the converter needs {@code CurrentUserStateService}, and
     * {@code CurrentUserStateService} needs {@code SecurityConfig} itself. Being
     * constructor arguments, that cycle was unresolvable and startup failed with
     * "Requested bean is currently in creation".
     *
     * <p>{@code @Bean} method parameters are resolved when the bean is created, after
     * every definition is registered, so the same dependencies no longer participate in
     * the construction cycle.
     */
    public SecurityConfig(PlatformSecurityProperties props) {
        this.props = props;
    }

    @Bean
    MfaVerifier mfaVerifier() {
        return new MfaVerifier(props.requiredAcr());
    }

    @Bean
    IncidentObjectAuthorizer incidentObjectAuthorizer() {
        IncidentObjectAuthorizer authorizer = new IncidentObjectAuthorizer(props.groupVisibilityPolicy());
        if (props.groupVisibilityPolicy() == GroupVisibilityPolicy.GROUP_MEMBERSHIP) {
            IncidentSnapshotRepository repository = snapshotRepositoryRef.get();
            if (repository != null) {
                authorizer = authorizer.withGroupMembershipChecker(repository::sharesGroupWith);
            }
        }
        return authorizer;
    }

    /**
     * Set by the {@code IncidentSnapshotRepository} bean definition via the
     * static holder below. Kept out of constructor injection to avoid a
     * circular dependency: the authorizer is needed by the guard, and the
     * repository is needed by the authorizer only under the optional policy.
     */
    private final java.util.concurrent.atomic.AtomicReference<IncidentSnapshotRepository>
            snapshotRepositoryRef = new java.util.concurrent.atomic.AtomicReference<>();

    @org.springframework.beans.factory.annotation.Autowired
    void setSnapshotRepository(IncidentSnapshotRepository repository) {
        this.snapshotRepositoryRef.set(repository);
    }

    @Bean
    SecurityFilterChain filterChain(
            HttpSecurity http,
            AuditService audit,
            com.company.incidentplatform.security.KeycloakJwtAuthenticationConverter jwtConverter)
            throws Exception {
        http
                // 7.5: see the javadoc above -- bearer-token resource server, no
                // ambient authority, therefore no CSRF vector.
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(headers -> headers
                        .contentTypeOptions(Customizer.withDefaults())
                        .frameOptions(frame -> frame.deny())
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31536000))
                        .referrerPolicy(referrer -> referrer.policy(
                                org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter
                                        .ReferrerPolicy.NO_REFERRER))
                        .permissionsPolicyHeader(policy -> policy.policy(
                                "geolocation=(), microphone=(), camera=(), payment=()"))
                        .cacheControl(Customizer.withDefaults()))
                .authorizeHttpRequests(auth -> auth
                        // Unauthenticated liveness only. 7.11 restricts the audit
                        // log to Admin/Auditor, and the Actuator surface is
                        // deliberately limited to liveness so it cannot become a
                        // way to read environment or configuration values.
                        .requestMatchers(props.actuatorUnauthenticatedPaths().toArray(String[]::new))
                        .permitAll()
                        .requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**")
                        .permitAll()
                        // Everything else requires a valid token. Note this is only
                        // the FIRST gate: authentication having succeeded says
                        // nothing about authorization, which is 7.2's job.
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtConverter))
                        // Lambdas rather than method references, so the resolved
                        // AuditService is captured from the bean-method parameter.
                        .authenticationEntryPoint(
                                (entryRequest, entryResponse, entryException) ->
                                        writeAuthenticationFailure(audit, entryRequest, entryResponse, entryException)))
                // Spring Security's own AccessDeniedHandler is replaced so that a
                // denial always produces a 7.11 audit entry rather than only a 403.
                .exceptionHandling(handling -> handling
                        .accessDeniedHandler((deniedRequest, deniedResponse, deniedException) ->
                                writeAccessDenied(audit, deniedRequest, deniedResponse, deniedException)))
                .securityContext(context -> context
                        .requireExplicitSave(false)
                        .securityContextRepository(
                                new org.springframework.security.web.context.NullSecurityContextRepository()));

        return http.build();
    }

    /**
     * 7.9 -- access tokens are short-lived and validated for issuer, audience,
     * signature, and expiry.
     *
     * <p>The audience validator is the important one. Without it, any token
     * minted by the same Keycloak realm for any other client -- including the
     * SPA's own client, and including a client an attacker has registered -- would
     * be accepted by this API. Same-realm is not same-audience.
     */
    @Bean
    JwtDecoder jwtDecoder(
            @org.springframework.beans.factory.annotation.Value("${KEYCLOAK_JWK_SET_URI:}") String jwkSetUri) {

        String issuer = props.keycloakIssuer();
        NimbusJwtDecoder decoder = jwkSetUri.isBlank()
                ? (NimbusJwtDecoder) org.springframework.security.oauth2.jwt.JwtDecoders.fromIssuerLocation(issuer)
                : NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();

        OAuth2TokenValidator<Jwt> issuerValidator = new JwtIssuerValidator(issuer);
        OAuth2TokenValidator<Jwt> audienceValidator = jwt -> {
            List<String> audience = jwt.getAudience();
            if (audience != null && audience.contains(props.apiClientId())) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token", "Token audience does not include " + props.apiClientId(), null));
        };
        // JwtTimestampValidator enforces exp/nbf, giving 7.9 token expiry.
        decoder.setJwtValidator(new org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator<>(
                issuerValidator, audienceValidator, new JwtTimestampValidator()));
        return decoder;
    }

    /**
     * 7.5 -- CORS restricted to the configured origins. The SPA is served
     * separately, so this is a real cross-origin call and wildcard-plus-credentials
     * would be both useless and dangerous.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(props.allowedOrigins());
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Request-Id", "Idempotency-Key"));
        configuration.setExposedHeaders(List.of("X-Request-Id"));
        configuration.setAllowCredentials(false);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        return source;
    }

    /**
     * A request that failed authentication.
     *
     * <p>7.11 requires these to be audited too -- an unauthenticated caller is
     * exactly the traffic 7.12 anomaly detection should see. The response body is
     * generic, per 7.5: it must not reveal whether a token was absent, expired,
     * or signed by the wrong key.
     */
    private void writeAuthenticationFailure(
            AuditService audit,
            jakarta.servlet.http.HttpServletRequest request,
            jakarta.servlet.http.HttpServletResponse response,
            AuthenticationException exception) throws java.io.IOException {

        // A validated token whose authorization context could not be established
        // arrives here as BadCredentialsException carrying an
        // AuthorizationContextRefused cause. Classifying it properly is the whole
        // point of 7.11: "MFA_REQUIRED" and "ACCOUNT_DISABLED" demand different
        // responses, and collapsing both into a flat token error would hide a
        // dormant-account or MFA-policy problem behind an apparent auth outage.
        DeniedReason reason = DeniedReason.TOKEN_INVALID;
        String rule = "authentication.token_rejected";

        Throwable cause = exception.getCause();
        if (cause instanceof com.company.incidentplatform.security.AuthorizationContextRefused refused) {
            reason = refused.reason();
            rule = "authentication." + refused.rule();
        } else if (cause instanceof org.springframework.security.oauth2.jwt.JwtValidationException) {
            rule = "authentication.token_invalid";
        }

        audit.recordDenied(
                null,
                reason,
                "session",
                null,
                "authenticate",
                RequestContext.endpoint(),
                RequestContext.method(),
                RequestContext.requestId().orElse(null),
                RequestContext.remoteAddress(props.trustForwardedFor()),
                AuthorizationCheckType.FUNCTION_LEVEL,
                rule);
        writeGenericFailure(response);
    }

    /**
     * A request that authenticated but failed an authorization check, including
     * every {@link AuthorizationDeniedException} from the 7.2 chain.
     */
    private void writeAccessDenied(
            AuditService audit,
            jakarta.servlet.http.HttpServletRequest request,
            jakarta.servlet.http.HttpServletResponse response,
            org.springframework.security.access.AccessDeniedException exception)
            throws java.io.IOException {

        AuthorizationCheckType checkType = AuthorizationCheckType.OBJECT_LEVEL;
        DeniedReason reason = DeniedReason.INSUFFICIENT_ROLE;
        String rule = "security.access_denied";
        String resourceType = "endpoint";
        java.util.UUID resourceId = null;

        if (exception instanceof AuthorizationDeniedException denied) {
            checkType = denied.decision().checkType();
            reason = denied.decision().deniedReason() == null
                    ? DeniedReason.INSUFFICIENT_ROLE
                    : denied.decision().deniedReason();
            rule = denied.decision().rule();
            resourceType = denied.resourceType();
            resourceId = denied.resourceId();
        } else if (!props.trustForwardedFor() && request.getUserPrincipal() == null) {
            reason = DeniedReason.TOKEN_INVALID;
            rule = "authentication.required";
        }

        audit.recordDenied(
                currentUserOrNull(),
                reason,
                resourceType,
                resourceId,
                "access",
                RequestContext.endpoint(),
                RequestContext.method(),
                RequestContext.requestId().orElse(null),
                RequestContext.remoteAddress(props.trustForwardedFor()),
                checkType,
                rule);

        writeGenericFailure(response);
    }

    private PlatformUser currentUserOrNull() {
        var authentication =
                org.springframework.security.core.context.SecurityContextHolder.getContext()
                        .getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof PlatformUser user)) {
            return null;
        }
        return user;
    }

    /**
     * 7.5 -- a rejection must be uniform. Distinguishing "no such incident" from
     * "not your incident" hands an attacker the enumeration oracle that 7.2
     * exists to remove, so every denial gets the same 403 and the same body. The
     * detail lives in the audit log.
     */
    private static void writeGenericFailure(jakarta.servlet.http.HttpServletResponse response)
            throws java.io.IOException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"error\":\"forbidden\"}");
    }
}
