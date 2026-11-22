package io.axiam.sdk.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares that the authenticated caller must hold at least one of the named
 * roles (CONTRACT.md &sect;11 {@code require_role}). This is a <em>local</em>
 * check of the verified token's {@code roles} claim, which the &sect;10 guard
 * injects as {@code ROLE_<name>} authorities &mdash; it never calls the AXIAM server.
 *
 * <p><strong>Roles come from the {@code roles} claim and from nothing else
 * (contract 1.68; N15).</strong> A token with no {@code roles} claim fails every
 * {@code @AxiamRequireRole} with HTTP 403, and so does one whose {@code roles}
 * is not an array of strings; the OAuth2 {@code scope} claim is never read,
 * split or prefixed into a role (use {@link AxiamRequireScope} for scopes).
 * <strong>The application must request the {@code roles} scope</strong> (add it
 * to the scope passed to {@code oidcBegin}, device, CIBA or client-credentials
 * requests, and have an administrator add {@code roles} to the client's
 * registered scopes), or every role guard answers 403. The claim lists the
 * subject's <em>global</em> role names in the token's tenant as of the moment
 * the token was minted, so it can be stale for up to one access-token lifetime.
 *
 * <p>A request with no verified identity &rarr; HTTP 401
 * ({@code authentication_failed}); an authenticated caller holding none of the
 * listed roles &rarr; HTTP 403 ({@code authorization_denied}).
 *
 * <p><strong>Role names are tenant-defined.</strong> This check is cheaper but
 * coarser than {@link AxiamRequireAccess}; it is NOT a substitute for a
 * resource-level check. {@link AxiamRequireAccess} is the authoritative
 * authorization mechanism.
 *
 * <p>Applied at the method level it guards a single handler; applied at the
 * type level it guards every handler on the controller. A method-level
 * annotation overrides a type-level one of the same kind. Enforced by
 * {@link io.axiam.sdk.spring.AxiamAuthorizationInterceptor}.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface AxiamRequireRole {

    /**
     * The roles to check for; the caller must hold at least one of them.
     * Matched, by exact case-sensitive equality, against the names in the verified token's
     * {@code roles} claim (the {@code ROLE_}-prefixed Spring authorities); never against scopes.
     *
     * @return the accepted role names (at least one must be held)
     */
    String[] value();
}
