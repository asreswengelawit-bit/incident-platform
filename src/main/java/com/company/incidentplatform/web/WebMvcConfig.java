package com.company.incidentplatform.web;

import java.util.List;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * MVC wiring that is not security policy.
 *
 * <p>Only the {@link CurrentUser} resolver is registered here. CORS, headers and
 * CSRF decisions live in {@code SecurityConfig}, because they are enforced by
 * the filter chain rather than by the dispatcher -- splitting them across two
 * classes is how a CORS allow-list ends up in the wrong one and appears not to
 * apply.
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    private final CurrentUserArgumentResolver currentUserArgumentResolver;

    public WebMvcConfig(CurrentUserArgumentResolver currentUserArgumentResolver) {
        this.currentUserArgumentResolver = currentUserArgumentResolver;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        // Custom resolvers run before the built-in ones, which is what lets
        // @CurrentUser bind to a type Spring does not otherwise know how to
        // resolve.
        resolvers.add(currentUserArgumentResolver);
    }
}
