package io.axiam.sdk.spring;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Coverage for {@link AxiamAutoConfiguration}'s bean factory methods without
 * bootstrapping a full Spring {@code ApplicationContext}: the no-arg
 * constructor (invoked by Spring Boot) and the default
 * {@link AxiamAuthenticationFilter} bean built from the {@code axiam.base-url}
 * / {@code axiam.tenant-id} properties. The {@code JwksVerifier} it constructs
 * does no network I/O at construction time, so this is fully offline.
 */
class AxiamAutoConfigurationTest {

    @Test
    void buildsDefaultAuthenticationFilterFromProperties() {
        AxiamAutoConfiguration config = new AxiamAutoConfiguration();

        AxiamAuthenticationFilter filter =
                config.axiamAuthenticationFilter("http://localhost:8080", "tenant-a");

        assertNotNull(filter, "the auto-configuration must produce a default authentication filter bean");
    }
}
