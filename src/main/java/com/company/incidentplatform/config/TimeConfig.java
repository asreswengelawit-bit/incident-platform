package com.company.incidentplatform.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The application {@link Clock}.
 *
 * <p>Injected rather than calling {@code Instant.now()} inline, so that session
 * timeouts, dormancy checks, and audit timestamps are all testable against a fixed
 * clock.
 *
 * <p>This lives outside {@link SecurityConfig} because it has to. {@code AuditService}
 * takes a {@code Clock}, and {@code SecurityConfig} takes an {@code AuditService}, so
 * a {@code Clock} declared as a {@code @Bean} method on {@code SecurityConfig} closes
 * a constructor-injection cycle: creating the {@code Clock} requires the
 * {@code SecurityConfig} instance, and creating that requires the {@code AuditService}
 * that requires the {@code Clock}. Spring cannot resolve constructor cycles, so this
 * failed at startup with "Requested bean is currently in creation" and took down every
 * application context that boots the entity manager and the filter chain -- which is
 * why no full-context test had ever run.
 *
 * <p>A bean with no dependencies of its own belongs in a configuration class that
 * depends on nothing, so it can be created first.
 */
@Configuration
public class TimeConfig {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
