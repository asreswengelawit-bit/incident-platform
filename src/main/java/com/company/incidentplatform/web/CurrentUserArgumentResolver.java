package com.company.incidentplatform.web;

import com.company.incidentplatform.security.PlatformUser;
import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * Resolves {@link CurrentUser} to the authenticated {@link PlatformUser}.
 *
 * <p>Fails closed. If the principal is absent, is the anonymous token Spring
 * issues for unauthenticated requests, or is not a {@code PlatformUser}, this
 * throws rather than returning null -- and the exception is an
 * {@code AuthenticationCredentialsNotFoundException}, which the filter chain's
 * entry point already turns into a 401 with a 7.11 audit entry. A null user
 * reaching a service would instead be a NullPointerException deep in a
 * repository call, or worse, a service that treats "no user" as "no
 * restrictions".
 */
@Component
public class CurrentUserArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(CurrentUser.class)
                && PlatformUser.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(
            MethodParameter parameter,
            ModelAndViewContainer mavContainer,
            NativeWebRequest webRequest,
            WebDataBinderFactory binderFactory) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            throw new org.springframework.security.authentication.AuthenticationCredentialsNotFoundException(
                    "No authenticated principal for @CurrentUser; the request reached a controller "
                            + "without passing authentication");
        }

        Object principal = authentication.getPrincipal();
        if (!(principal instanceof PlatformUser user)) {
            throw new org.springframework.security.authentication.AuthenticationCredentialsNotFoundException(
                    "Authenticated principal is not a PlatformUser; the JWT authentication converter did "
                            + "not run for this request");
        }
        return user;
    }
}
