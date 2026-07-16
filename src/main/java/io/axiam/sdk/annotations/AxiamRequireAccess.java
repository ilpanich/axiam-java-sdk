package io.axiam.sdk.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares that an endpoint requires the <strong>authenticated caller</strong>
 * to pass an AXIAM authorization check for {@link #action()} on a resource
 * resolved from the request (CONTRACT.md &sect;11 {@code require_access}).
 *
 * <p>Semantics (CONTRACT.md &sect;11.2), enforced by
 * {@link io.axiam.sdk.spring.AxiamAuthorizationInterceptor}:
 * <ul>
 *   <li>Runs strictly <em>after</em> authentication. No verified identity in
 *       the request context &rarr; HTTP 401 ({@code authentication_failed}); it
 *       never performs its own token extraction.</li>
 *   <li>The check is made for the request's authenticated user &mdash; the
 *       helper passes {@code subject_id = <authenticated user id>} to
 *       {@code checkAccess}, not the application's own service-account
 *       session.</li>
 *   <li>The resource id is a UUID resolved in order of precedence:
 *       {@link #resourceId()} (a static UUID literal, for singleton resources),
 *       else the path variable named by {@link #resourceParam()}. A missing or
 *       non-UUID value is a programming error surfaced as HTTP 400
 *       ({@code invalid_request}), never a silent allow.</li>
 *   <li>{@link #scope()}, when non-empty, is passed through to
 *       {@code checkAccess} verbatim.</li>
 *   <li>A denied check (or server 403) &rarr; HTTP 403
 *       ({@code authorization_denied}); a transport failure while calling the
 *       authz endpoint fails closed with HTTP 503
 *       ({@code authz_unavailable}).</li>
 * </ul>
 *
 * <p>Applied at the method level it guards a single handler; applied at the
 * type level it guards every handler on the controller. A method-level
 * annotation overrides a type-level one of the same kind.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface AxiamRequireAccess {

    /**
     * The action to authorize (e.g. {@code "read"}, {@code "documents:delete"}).
     *
     * @return the action checked against the resolved resource
     */
    String action();

    /**
     * The name of the path/route variable whose value is the resource UUID.
     * Used only when {@link #resourceId()} is empty. Defaults to {@code "id"}.
     *
     * @return the path-variable name to resolve the resource UUID from
     */
    String resourceParam() default "id";

    /**
     * A static resource UUID literal, for singleton resources. When non-empty
     * it takes precedence over {@link #resourceParam()}. Defaults to the empty
     * string (resolve from the path variable instead).
     *
     * @return a static resource UUID, or the empty string to resolve from the
     *         path variable
     */
    String resourceId() default "";

    /**
     * An optional sub-resource scope qualifier passed through to
     * {@code checkAccess} verbatim. Defaults to the empty string (no scope).
     *
     * @return the scope qualifier, or the empty string for none
     */
    String scope() default "";
}
