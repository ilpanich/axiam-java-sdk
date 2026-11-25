package io.axiam.sdk.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares that an endpoint requires the caller's verified token to carry at least one of the
 * named OAuth2 <em>scopes</em> (CONTRACT.md &sect;11 {@code require_scope}, contract 1.68).
 *
 * <p>This is a <em>local</em> check of the token's {@code scope} claim &mdash; the
 * space-separated list of RFC 6749 &sect;3.3, each entry compared by exact, case-sensitive
 * equality &mdash; and it never calls the AXIAM server. It reads only {@code scope}: a token's
 * {@code roles} claim never stands in for a scope, and a scope never stands in for a role (see
 * {@link AxiamRequireRole}). A scope is chosen by the <em>client</em> and bounded only by its
 * registration, so it says what the client may do, not what the user holds; it is coarser than
 * {@link AxiamRequireAccess}, which is the authoritative check.
 *
 * <p>A request with no verified identity &rarr; HTTP 401 ({@code authentication_failed}); an
 * authenticated caller whose token carries none of the listed scopes (or no {@code scope} claim)
 * &rarr; HTTP 403 ({@code authorization_denied}). Stack the annotation's values only as
 * alternatives; a route that needs several scopes uses several guards.
 *
 * <p>Enforced by {@link io.axiam.sdk.spring.AxiamAuthorizationInterceptor}, which matches the
 * {@code SCOPE_}-prefixed authorities {@link io.axiam.sdk.spring.AxiamAuthenticationFilter} builds.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface AxiamRequireScope {

    /**
     * The scopes to check for; the token must carry at least one of them.
     *
     * @return the accepted scope names (at least one must be present in the token's {@code scope})
     */
    String[] value();
}
