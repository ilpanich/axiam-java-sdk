package io.axiam.sdk.spring;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.oidc.MemoryOidcStateStore;
import io.axiam.sdk.oidc.OidcStateStore;

import org.junit.jupiter.api.Test;

import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
                config.axiamAuthenticationFilter("http://localhost:8080", "tenant-a", "", "", 60L);

        assertNotNull(filter, "the auto-configuration must produce a default authentication filter bean");
    }

    @Test
    void buildsAuthenticationFilterWithConfiguredIssuerAudienceAndSkew() {
        AxiamAutoConfiguration config = new AxiamAutoConfiguration();

        AxiamAuthenticationFilter filter = config.axiamAuthenticationFilter(
                "http://localhost:8080", "tenant-a", "https://axiam.example", "axiam:user", 30L);

        assertNotNull(filter, "the §10.1 rule 5-7 properties must be accepted by the auto-configuration");
    }

    @Test
    void rejectsAnUnboundedConfiguredClockSkew() {
        AxiamAutoConfiguration config = new AxiamAutoConfiguration();

        // CONTRACT.md §10.1 rule 7: the leeway MUST NOT be operator-settable
        // to an unbounded value — an out-of-range property fails context
        // startup rather than silently widening acceptance.
        assertThrows(
                IllegalArgumentException.class,
                () -> config.axiamAuthenticationFilter("http://localhost:8080", "tenant-a", "", "", 86_400L));
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

    @Test
    void buildsDefaultOidcClientFromProperties() {
        AxiamAutoConfiguration.AxiamOidcMvcConfiguration oidcConfig =
                new AxiamAutoConfiguration.AxiamOidcMvcConfiguration();

        try (AxiamClient client = oidcConfig.axiamOidcClient("http://localhost:8080", "tenant-a", "my-app", "")) {
            assertNotNull(client, "the auto-configuration must produce a default OIDC-configured AxiamClient bean");
        }
    }

    @Test
    void buildsOidcClientWithAConfidentialClientSecret() {
        AxiamAutoConfiguration.AxiamOidcMvcConfiguration oidcConfig =
                new AxiamAutoConfiguration.AxiamOidcMvcConfiguration();

        try (AxiamClient client = oidcConfig.axiamOidcClient("http://localhost:8080", "tenant-a", "my-app", "shh")) {
            assertNotNull(client);
        }
    }

    @Test
    void buildsDefaultInMemoryOidcStateStore() {
        AxiamAutoConfiguration.AxiamOidcMvcConfiguration oidcConfig =
                new AxiamAutoConfiguration.AxiamOidcMvcConfiguration();

        OidcStateStore store = oidcConfig.axiamOidcStateStore();

        assertNotNull(store);
        assertTrue(store instanceof MemoryOidcStateStore);
    }

    @Test
    void registersTheOidcLoginRoutes() {
        AxiamAutoConfiguration.AxiamOidcMvcConfiguration oidcConfig =
                new AxiamAutoConfiguration.AxiamOidcMvcConfiguration();

        try (AxiamClient client = oidcConfig.axiamOidcClient("http://localhost:8080", "tenant-a", "my-app", "")) {
            RouterFunction<ServerResponse> routes = oidcConfig.axiamOidcLoginRoutes(
                    client, oidcConfig.axiamOidcStateStore(), "/oidc/login", "/oidc/callback",
                    "http://localhost:8080/oidc/callback", "", "");

            assertNotNull(routes, "the auto-configuration must produce the login-redirect + callback RouterFunction");
        }
    }
}
