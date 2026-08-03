package io.axiam.sdk.spring;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.internal.JwksVerifier;
import io.axiam.sdk.oidc.MemoryOidcStateStore;
import io.axiam.sdk.oidc.OidcStateStore;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

/**
 * Zero-config Spring Boot auto-registration for {@link AxiamAuthenticationFilter}
 * (D-15, RESEARCH.md Pattern 9). Registered via {@code
 * META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}
 * (the Spring Boot 3.x mechanism; NOT the legacy {@code spring.factories}
 * path).
 *
 * <p>{@code @ConditionalOnClass(SecurityFilterChain.class)} keeps this
 * configuration inert unless Spring Security is actually on the classpath —
 * combined with the {@code provided}/{@code optional} Spring dependencies in
 * {@code pom.xml}, a non-Spring consumer's classpath is never affected.
 *
 * <p>Reads {@code axiam.base-url} and {@code axiam.tenant-id} from the
 * Spring {@code Environment} to build a default {@link AxiamAuthenticationFilter}
 * and, if the consuming application has not defined its OWN
 * {@link SecurityFilterChain} bean, a default one that requires
 * authentication for every request via that filter. Both beans are
 * {@code @ConditionalOnMissingBean} — a consumer who wires the filter
 * explicitly in their own {@code SecurityFilterChain} (the example app's
 * pattern, 20-09) takes precedence and this auto-configuration yields
 * entirely (D-15's "explicit example + zero-config convenience").
 */
@AutoConfiguration
@ConditionalOnClass(SecurityFilterChain.class)
public class AxiamAutoConfiguration {

    /** Creates a new auto-configuration instance (instantiated by Spring Boot, not user code). */
    public AxiamAutoConfiguration() {
    }

    /**
     * Builds the default {@link AxiamAuthenticationFilter} bean from {@code axiam.base-url}/
     * {@code axiam.tenant-id}, unless the consuming application already defines its own.
     *
     * <p>The CONTRACT.md &sect;10.1 rule 5&ndash;7 settings are read from three
     * <strong>optional</strong> properties. Rules 5 and 6 are conditional
     * ("checked when the SDK is configured with an expected value; absent
     * configuration means no check"), so {@code axiam.expected-issuer} and
     * {@code axiam.expected-audience} default to blank &rarr; unset, and no
     * issuer or audience is ever assumed. {@code axiam.clock-skew-seconds}
     * defaults to the RECOMMENDED
     * {@link JwksVerifier#DEFAULT_CLOCK_SKEW_SECONDS} and is bounded by
     * {@link JwksVerifier#MAX_CLOCK_SKEW_SECONDS} (rule 7 forbids an
     * operator-settable unbounded leeway), so an out-of-range value fails
     * context startup rather than silently widening acceptance.
     *
     * @param baseUrl          the AXIAM server base URL ({@code axiam.base-url} property)
     * @param tenantId         the configured tenant identifier ({@code axiam.tenant-id} property)
     * @param expectedIssuer   the expected {@code iss} ({@code axiam.expected-issuer} property);
     *                         blank means the {@code iss} claim is not checked
     * @param expectedAudience the expected {@code aud} ({@code axiam.expected-audience} property);
     *                         blank means the {@code aud} claim is not checked
     * @param clockSkewSeconds the &sect;10.1 rule 7 leeway in seconds
     *                         ({@code axiam.clock-skew-seconds} property)
     * @return the default {@link AxiamAuthenticationFilter} bean
     */
    @Bean
    @ConditionalOnMissingBean(AxiamAuthenticationFilter.class)
    public AxiamAuthenticationFilter axiamAuthenticationFilter(
            @Value("${axiam.base-url}") String baseUrl,
            @Value("${axiam.tenant-id}") String tenantId,
            @Value("${axiam.expected-issuer:}") String expectedIssuer,
            @Value("${axiam.expected-audience:}") String expectedAudience,
            @Value("${axiam.clock-skew-seconds:60}") long clockSkewSeconds) {
        JwksVerifier.LocalVerificationPolicy policy = new JwksVerifier.LocalVerificationPolicy(
                expectedIssuer.isBlank() ? null : expectedIssuer,
                expectedAudience.isBlank() ? null : expectedAudience,
                clockSkewSeconds);
        return new AxiamAuthenticationFilter(new JwksVerifier(baseUrl, policy), tenantId);
    }

    /**
     * Builds a default {@link SecurityFilterChain} requiring authentication for every
     * request via {@code filter}, unless the consuming application already defines its own.
     *
     * @param http   the {@code HttpSecurity} builder to configure
     * @param filter the {@link AxiamAuthenticationFilter} bean to register
     * @return the default {@link SecurityFilterChain}
     * @throws Exception if {@code http.build()} fails
     */
    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain axiamSecurityFilterChain(HttpSecurity http, AxiamAuthenticationFilter filter)
            throws Exception {
        http
                // Spring's own CSRF token protects Spring's session-cookie auth,
                // which this app does not use. AxiamAuthenticationFilter enforces
                // its OWN cookie double-submit check (X-CSRF-Token vs axiam_csrf,
                // CONTRACT.md §3) for any request authenticated via the
                // axiam_access cookie — see the filter's class Javadoc. Enabling
                // Spring's CSRF filter here would 403 legitimate Bearer-token
                // requests (which never carry a Spring CSRF token) without adding
                // any protection the filter doesn't already provide.
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    /**
     * Declarative-authorization (&sect;11) enforcement wiring, active only when
     * Spring MVC is on the classpath ({@code @ConditionalOnClass(HandlerInterceptor.class)}),
     * kept in a nested configuration so a non-MVC consumer never loads the
     * {@code spring-webmvc} types this section references.
     *
     * <p>Registers {@link AxiamAuthorizationInterceptor} through a
     * {@link WebMvcConfigurer}, backed by an {@link AxiamClient} built from the
     * same {@code axiam.base-url}/{@code axiam.tenant-id} properties as the
     * authentication filter. Both beans are {@code @ConditionalOnMissingBean},
     * so a consumer who defines their own {@link AxiamClient} or their own
     * {@code axiamAuthorizationWebMvcConfigurer} takes precedence.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(HandlerInterceptor.class)
    public static class AxiamAuthorizationMvcConfiguration {

        /** Creates the nested MVC configuration (instantiated by Spring, not user code). */
        public AxiamAuthorizationMvcConfiguration() {
        }

        /**
         * Builds a default {@link AxiamClient} for the &sect;11 interceptor from
         * {@code axiam.base-url}/{@code axiam.tenant-id}, unless the consuming
         * application already defines its own {@link AxiamClient} bean.
         *
         * @param baseUrl  the AXIAM server base URL ({@code axiam.base-url} property)
         * @param tenantId the configured tenant identifier ({@code axiam.tenant-id} property)
         * @return the default {@link AxiamClient} bean
         */
        @Bean
        @ConditionalOnMissingBean(AxiamClient.class)
        public AxiamClient axiamClient(
                @Value("${axiam.base-url}") String baseUrl, @Value("${axiam.tenant-id}") String tenantId) {
            return AxiamClient.builder(baseUrl, tenantId).build();
        }

        /**
         * Registers {@link AxiamAuthorizationInterceptor} via a
         * {@link WebMvcConfigurer}, unless the consuming application already
         * defines a bean named {@code axiamAuthorizationWebMvcConfigurer}.
         *
         * @param client the {@link AxiamClient} the interceptor uses to evaluate
         *               {@code @AxiamRequireAccess} checks
         * @return a {@link WebMvcConfigurer} that adds the &sect;11 interceptor
         */
        @Bean
        @ConditionalOnMissingBean(name = "axiamAuthorizationWebMvcConfigurer")
        public WebMvcConfigurer axiamAuthorizationWebMvcConfigurer(AxiamClient client) {
            AxiamAuthorizationInterceptor interceptor = new AxiamAuthorizationInterceptor(client);
            return new WebMvcConfigurer() {
                @Override
                public void addInterceptors(InterceptorRegistry registry) {
                    registry.addInterceptor(interceptor);
                }
            };
        }
    }

    /**
     * CONTRACT.md &sect;12 "Login with AXIAM" wiring — active only when
     * {@code spring-webmvc}'s {@link RouterFunction} is on the classpath
     * <strong>and</strong> the consuming application opts in via
     * {@code axiam.oidc.enabled=true} (plan T5 item 2: "auto-configured only
     * when the consumer opts in via properties" — unlike
     * {@link AxiamAuthorizationMvcConfiguration}, this section is never
     * active by the mere presence of a dependency, since an OIDC login route
     * is a much larger behavioral surface to add silently).
     *
     * <p>Reads {@code axiam.oidc.client-id} (required), {@code axiam.oidc.client-secret}
     * (optional — confidential clients only), {@code axiam.oidc.redirect-uri}
     * (required), {@code axiam.oidc.login-path}/{@code axiam.oidc.callback-path}
     * (default {@code /oidc/login}/{@code /oidc/callback}), {@code axiam.oidc.scope},
     * and {@code axiam.oidc.success-redirect}. Builds its own {@link AxiamClient}
     * bean (named {@code axiamOidcClient}, distinct from
     * {@link AxiamAuthorizationMvcConfiguration}'s {@code axiamClient} — the
     * two auto-configurations are independent and, if both are enabled without
     * an application-supplied shared bean, construct separate client
     * instances) unless the application already supplies one under that name.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(RouterFunction.class)
    @ConditionalOnProperty(prefix = "axiam.oidc", name = "enabled", havingValue = "true")
    public static class AxiamOidcMvcConfiguration {

        /** Creates the nested OIDC configuration (instantiated by Spring, not user code). */
        public AxiamOidcMvcConfiguration() {
        }

        /**
         * Builds the OIDC-configured {@link AxiamClient} bean, unless the
         * consuming application already defines one named {@code axiamOidcClient}.
         *
         * @param baseUrl      the AXIAM server base URL ({@code axiam.base-url} property)
         * @param tenantId     the configured tenant identifier ({@code axiam.tenant-id} property)
         * @param clientId     the relying party's OAuth2 {@code client_id} ({@code axiam.oidc.client-id} property)
         * @param clientSecret the confidential client's {@code client_secret} ({@code axiam.oidc.client-secret} property), or blank for a public client
         * @return the OIDC-configured {@link AxiamClient} bean
         */
        @Bean
        @ConditionalOnMissingBean(name = "axiamOidcClient")
        public AxiamClient axiamOidcClient(
                @Value("${axiam.base-url}") String baseUrl,
                @Value("${axiam.tenant-id}") String tenantId,
                @Value("${axiam.oidc.client-id}") String clientId,
                @Value("${axiam.oidc.client-secret:}") String clientSecret) {
            AxiamClient.Builder builder = AxiamClient.builder(baseUrl, tenantId).oidcClientId(clientId);
            if (!clientSecret.isBlank()) {
                builder.oidcClientSecret(clientSecret);
            }
            return builder.build();
        }

        /**
         * Builds the default in-memory {@link OidcStateStore} bean, unless the
         * consuming application already defines its own (e.g. a Redis-backed
         * implementation for a multi-instance deployment).
         *
         * @return the default {@link MemoryOidcStateStore} bean
         */
        @Bean
        @ConditionalOnMissingBean(OidcStateStore.class)
        public OidcStateStore axiamOidcStateStore() {
            return new MemoryOidcStateStore();
        }

        /**
         * Registers the {@link AxiamOidcLoginRoutes#routes} login-redirect +
         * callback pair, unless the consuming application already defines a
         * bean named {@code axiamOidcLoginRoutes}.
         *
         * @param client          the {@code axiamOidcClient} bean
         * @param store           the configured {@link OidcStateStore} bean
         * @param loginPath       the login route path ({@code axiam.oidc.login-path} property, default {@code /oidc/login})
         * @param callbackPath    the callback route path ({@code axiam.oidc.callback-path} property, default {@code /oidc/callback})
         * @param redirectUri     the relying party's registered redirect URI ({@code axiam.oidc.redirect-uri} property)
         * @param scope           requested scope, space-separated ({@code axiam.oidc.scope} property), or blank for the default
         * @param successRedirect where to send the browser after a successful login ({@code axiam.oidc.success-redirect} property), or blank to fall back to the captured {@code returnTo}/a JSON summary
         * @return the login-redirect + callback {@link RouterFunction}
         */
        @Bean
        @ConditionalOnMissingBean(name = "axiamOidcLoginRoutes")
        public RouterFunction<ServerResponse> axiamOidcLoginRoutes(
                @Qualifier("axiamOidcClient") AxiamClient client,
                OidcStateStore store,
                @Value("${axiam.oidc.login-path:/oidc/login}") String loginPath,
                @Value("${axiam.oidc.callback-path:/oidc/callback}") String callbackPath,
                @Value("${axiam.oidc.redirect-uri}") String redirectUri,
                @Value("${axiam.oidc.scope:}") String scope,
                @Value("${axiam.oidc.success-redirect:}") String successRedirect) {
            AxiamOidcLoginRoutes.Options options = new AxiamOidcLoginRoutes.Options(
                    loginPath, callbackPath, redirectUri,
                    scope.isBlank() ? null : scope,
                    successRedirect.isBlank() ? null : successRedirect,
                    null);
            return AxiamOidcLoginRoutes.routes(client, store, options);
        }
    }
}
