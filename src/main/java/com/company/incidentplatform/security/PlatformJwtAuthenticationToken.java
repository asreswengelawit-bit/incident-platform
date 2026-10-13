package com.company.incidentplatform.security;

import java.util.Collection;
import java.util.Objects;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public final class PlatformJwtAuthenticationToken extends JwtAuthenticationToken {

    private final PlatformUser user;

    public PlatformJwtAuthenticationToken(
            Jwt token, Collection<? extends GrantedAuthority> authorities, PlatformUser user) {
        super(token, authorities, Objects.requireNonNull(user).email() == null
                ? token.getClaimAsString("preferred_username")
                : user.email());
        this.user = user;
    }

    @Override
    public PlatformUser getPrincipal() {
        return user;
    }
}
