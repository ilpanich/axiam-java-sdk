package io.axiam.sdk.spring;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.internal.JwksVerifier;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

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
     * @param baseUrl  the AXIAM server base URL ({@code axiam.base-url} property)
     * @param tenantId the configured tenant identifier ({@code axiam.tenant-id} property)
     * @return the default {@link AxiamAuthenticationFilter} bean
     */
    @Bean
    @ConditionalOnMissingBean(AxiamAuthenticationFilter.class)
    public AxiamAuthenticationFilter axiamAuthenticationFilter(
            @Value("${axiam.base-url}") String baseUrl, @Value("${axiam.tenant-id}") String tenantId) {
        return new AxiamAuthenticationFilter(new JwksVerifier(baseUrl), tenantId);
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
}
