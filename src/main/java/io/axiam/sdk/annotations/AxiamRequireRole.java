package io.axiam.sdk.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares that the authenticated caller must hold at least one of the named
 * roles (CONTRACT.md &sect;11 {@code require_role}). This is a <em>local</em>
 * check against the authorities already present in the request context (the
 * verified token's roles/authorities injected by the &sect;10 guard) &mdash; it
 * never calls the AXIAM server.
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
     * Matched against the caller's Spring {@code GrantedAuthority} names, both
     * verbatim and with the conventional {@code ROLE_} prefix.
     *
     * @return the accepted role names (at least one must be held)
     */
    String[] value();
}
