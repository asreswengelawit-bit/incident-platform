package com.company.incidentplatform;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * Section 5.4: modular monolith. Bounded modules ({@code incident},
 * {@code evidence}, {@code notification}, {@code audit}, {@code admin}) each own
 * their package, their persistence boundary, and their test suite. Cross-module
 * access goes through a module's public service interface only -- no direct
 * entity access -- which is what keeps Section 7.2's object-level authorization
 * a single enforced choke point rather than a scattering of ad-hoc queries.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
@EnableJpaAuditing
public class IncidentPlatformApplication {

    public static void main(String[] args) {
        SpringApplication.run(IncidentPlatformApplication.class, args);
    }
}
