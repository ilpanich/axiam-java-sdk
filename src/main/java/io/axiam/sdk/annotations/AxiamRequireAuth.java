package io.axiam.sdk.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares that an endpoint requires an authenticated AXIAM identity
 * (CONTRACT.md &sect;11 {@code require_auth}). Pure sugar over the &sect;10
 * guard for frameworks where the guard is opt-in per route rather than global;
 * a request that reaches the annotated handler without a verified identity in
 * the request context is rejected with HTTP 401
 * ({@code authentication_failed}).
 *
 * <p>Applied at the method level it guards a single handler; applied at the
 * type level it guards every handler on the controller. A method-level
 * annotation overrides a type-level one of the same kind.
 *
 * <p>Enforced by {@link io.axiam.sdk.spring.AxiamAuthorizationInterceptor} in
 * the Spring integration.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface AxiamRequireAuth {
}
