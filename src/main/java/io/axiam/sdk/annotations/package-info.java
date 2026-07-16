/**
 * Framework-free declarative authorization annotations (CONTRACT.md &sect;11).
 *
 * <p>These three annotations &mdash;
 * {@link io.axiam.sdk.annotations.AxiamRequireAuth},
 * {@link io.axiam.sdk.annotations.AxiamRequireAccess}, and
 * {@link io.axiam.sdk.annotations.AxiamRequireRole} &mdash; declare a
 * per-endpoint authorization requirement directly on a controller method or
 * type. They carry no framework dependency and live in the core jar so any
 * integration (Spring today, others in future) can enforce them; the Spring
 * enforcement point is
 * {@link io.axiam.sdk.spring.AxiamAuthorizationInterceptor}.
 *
 * <p>The helpers are an <em>additive</em> layer on top of the &sect;10
 * middleware/route-guard: they run strictly <em>after</em> authentication and
 * consume the identity it injected. They never duplicate, bypass, or
 * re-implement any part of the &sect;10 verification path (JWKS, tenant check,
 * &sect;3a CSRF).
 */
@NullMarked
package io.axiam.sdk.annotations;

import org.jspecify.annotations.NullMarked;
