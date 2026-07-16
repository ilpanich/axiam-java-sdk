package io.axiam.sdk.spring;

import io.axiam.sdk.AxiamClient;

import org.junit.jupiter.api.Test;

import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Coverage for {@link AxiamAutoConfiguration}'s bean factory methods without
 * bootstrapping a full Spring {@code ApplicationContext}: the no-arg
 * constructor (invoked by Spring Boot), the default
 * {@link AxiamAuthenticationFilter} bean built from the {@code axiam.base-url}
 * / {@code axiam.tenant-id} properties, and the nested
 * {@link AxiamAutoConfiguration.AxiamAuthorizationMvcConfiguration} that wires
 * the &sect;11 {@link AxiamAuthorizationInterceptor} through a
 * {@link WebMvcConfigurer}. The {@code JwksVerifier}/{@code AxiamClient} these
 * construct do no network I/O at construction time, so this is fully offline.
 */
class AxiamAutoConfigurationTest {

    @Test
    void buildsDefaultAuthenticationFilterFromProperties() {
        AxiamAutoConfiguration config = new AxiamAutoConfiguration();

        AxiamAuthenticationFilter filter =
                config.axiamAuthenticationFilter("http://localhost:8080", "tenant-a");

        assertNotNull(filter, "the auto-configuration must produce a default authentication filter bean");
    }

    @Test
    void buildsDefaultAxiamClientForTheInterceptor() {
        AxiamAutoConfiguration.AxiamAuthorizationMvcConfiguration mvcConfig =
                new AxiamAutoConfiguration.AxiamAuthorizationMvcConfiguration();

        try (AxiamClient client = mvcConfig.axiamClient("http://localhost:8080", "tenant-a")) {
            assertNotNull(client, "the auto-configuration must produce a default AxiamClient bean");
        }
    }

    @Test
    void registersTheAuthorizationInterceptorViaWebMvcConfigurer() {
        AxiamAutoConfiguration.AxiamAuthorizationMvcConfiguration mvcConfig =
                new AxiamAutoConfiguration.AxiamAuthorizationMvcConfiguration();

        try (AxiamClient client = mvcConfig.axiamClient("http://localhost:8080", "tenant-a")) {
            WebMvcConfigurer configurer = mvcConfig.axiamAuthorizationWebMvcConfigurer(client);
            assertNotNull(configurer, "the auto-configuration must produce a WebMvcConfigurer bean");
            // Exercise the registration callback — must not throw.
            configurer.addInterceptors(new InterceptorRegistry());
        }
    }
}
