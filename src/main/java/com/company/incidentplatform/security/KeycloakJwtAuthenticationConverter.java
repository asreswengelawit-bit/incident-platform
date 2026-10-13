package com.company.incidentplatform.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/**
 * Section 6.2.2 -- the bridge from a validated Keycloak token to the
 * {@link PlatformUser} the rest of the authorization chain consumes.
 *
 * <p>Three things happen here, in this order, and the order is the design:
 *
 * <ol>
 *   <li><b>Extract the coarse role</b> from the token's realm role claim. The
 *       token is the authority for <em>who the user is</em> and
 *       <em>which coarse role they hold</em> -- this class never invents a role,
 *       which is what 6.2.2 requires.</li>
 *   <li><b>Re-validate against current state</b> via
 *       {@link CurrentUserStateService}, which is where 7.1/7.9 revocation is
 *       enforced. See that class for how this is reconciled with 6.2.2.</li>
 *   <li><b>Emit the principal</b>, so that every downstream check operates on
 *       {@link PlatformUser} and never on raw claims.</li>
 * </ol>
 *
 * <h2>Failing closed</h2>
 *
 * <p>Every failure path raises a {@link org.springframework.security.authentication.BadCredentialsException}
 * rather than returning a principal with reduced privileges. A converter that
 * "helpfully" downgraded an unrecognised role to Reporter would turn an IdP
 * misconfiguration into an authorization defect that is invisible until someone
 * notices a user with the wrong access.
 */
@Component
public class KeycloakJwtAuthenticationConverter
        implements org.springframework.core.convert.converter.Converter<Jwt, AbstractAuthenticationToken> {

    private static final Logger log = LoggerFactory.getLogger(KeycloakJwtAuthenticationConverter.class);

    private static final String REALM_ACCESS = "realm_access";
    private static final String ROLES = "roles";
    private static final String AMR = "amr";
    private static final String ACR = "acr";
    private static final String PREFERRED_USERNAME = "preferred_username";

    private final CurrentUserStateService userState;
    private final Set<String> knownRoleNames;

    public KeycloakJwtAuthenticationConverter(CurrentUserStateService userState) {
        this.userState = userState;
        this.knownRoleNames = java.util.Arrays.stream(PlatformRole.values())
                .map(Enum::name)
                .collect(Collectors.toUnmodifiableSet());
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        String subject = jwt.getSubject();
        String tokenRole = extractCoarseRole(jwt);
        List<String> amr = readClaimAsStringList(jwt, AMR);
        String acr = jwt.getClaimAsString(ACR);
        String fullName = jwt.getClaimAsString("name");
        if (fullName == null || fullName.isBlank()) {
            fullName = jwt.getClaimAsString(PREFERRED_USERNAME);
        }
        String department = jwt.getClaimAsString("department");

        CurrentUserStateService.Resolution resolution = userState.resolve(
                subject,
                tokenRole,
                amr,
                acr,
                jwt.getClaimAsString("email"),
                fullName,
                department,
                jwt.getIssuedAt());

        if (!resolution.isAllowed()) {
            // Raised during authentication, so Spring Security routes it to the
            // authentication entry point, which writes the 7.11 DENIED entry.
            // The DeniedReason travels as the exception cause so the entry point
            // can classify the audit row rather than logging a flat "unauthorized".
            throw new org.springframework.security.authentication.BadCredentialsException(
                    "Authorization context could not be established: " + resolution.rule(),
                    new AuthorizationContextRefused(resolution.reason(), resolution.rule()));
        }

        PlatformUser user = resolution.user();
        return new PlatformJwtAuthenticationToken(jwt, authoritiesFor(user), user);
    }

    /**
     * Reads the single coarse role from the token.
     *
     * <p>Keycloak composite roles can put several role names into
     * {@code realm_access.roles}. The document's model (6.1 USER has one role;
     * 6.2.1 defines one coarse role per user) does not have a defined meaning
     * for "holds two coarse roles at once", and silently picking the
     * highest-privilege one would be a privilege-escalation bug in the
     * authorization layer. So this is refused and logged, and it surfaces as an
     * authentication failure the operator can see.
     */
    private String extractCoarseRole(Jwt jwt) {
        Object realmAccess = jwt.getClaims().get(REALM_ACCESS);
        if (!(realmAccess instanceof Map<?, ?> realmMap)) {
            throw new org.springframework.security.authentication.BadCredentialsException(
                    "Token carries no realm_access claim; it was not issued by the platform realm", null);
        }
        Object rolesClaim = realmMap.get(ROLES);
        if (!(rolesClaim instanceof Collection<?> roles) || roles.isEmpty()) {
            throw new org.springframework.security.authentication.BadCredentialsException(
                    "Token carries no realm roles", null);
        }

        List<String> coarseRoles = roles.stream()
                .map(String::valueOf)
                .filter(knownRoleNames::contains)
                .distinct()
                .toList();

        if (coarseRoles.isEmpty()) {
            throw new org.springframework.security.authentication.BadCredentialsException(
                    "Token holds no recognised platform role; present: " + roles, null);
        }
        if (coarseRoles.size() > 1) {
            log.error("Subject {} holds multiple coarse roles {}; the model defines exactly one",
                    jwt.getSubject(), coarseRoles);
            throw new org.springframework.security.authentication.BadCredentialsException(
                    "Token asserts more than one coarse role: " + coarseRoles, null);
        }
        return coarseRoles.get(0);
    }

    /**
     * Spring Security authorities. These are coarse and derived from the resolved
     * user, not from the raw claim, so {@code @PreAuthorize("hasRole('ANALYST')")}
     * reflects current state rather than a stale token.
     */
    private Collection<GrantedAuthority> authoritiesFor(PlatformUser user) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + user.role().name()));
        if (user.permissions().isReadOnly()) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_read_only"));
        }
        return authorities;
    }

    private static List<String> readClaimAsStringList(Jwt jwt, String claim) {
        Object value = jwt.getClaims().get(claim);
        if (value instanceof Collection<?> collection) {
            return collection.stream().map(String::valueOf).toList();
        }
        if (value instanceof String single) {
            return List.of(single);
        }
        return List.of();
    }
}
