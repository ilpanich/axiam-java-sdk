/**
 * OIDC / SSO relying-party helpers (CONTRACT.md &sect;12): authorization-code
 * + PKCE login against AXIAM's own OIDC provider, service-account
 * {@code client_credentials} login, token introspection/revocation, and the
 * server's upstream-IdP federation endpoints.
 *
 * <p>The nine canonical operations ({@code oidcDiscover}, {@code oidcBegin},
 * {@code oidcExchange}, {@code oidcRefresh}, {@code loginClientCredentials},
 * {@code introspect}, {@code revoke}, {@code ssoStart}, {@code ssoComplete})
 * are exposed directly on {@link io.axiam.sdk.AxiamClient}, per CONTRACT.md
 * &sect;12.2's Java naming map — this package holds the supporting value
 * types ({@link io.axiam.sdk.oidc.OidcConfiguration},
 * {@link io.axiam.sdk.oidc.OidcTokenSet}, …), PKCE/ID-token validation logic,
 * and the optional {@link io.axiam.sdk.oidc.OidcStateStore}.
 *
 * <p>Everything here is built on the SDK's existing machinery — the &sect;4
 * cookie jar, &sect;6/&sect;6.1 TLS configuration, &sect;7 {@code Sensitive}
 * wrapper, &sect;9 single-flight refresh guard, and the &sect;10 JWKS
 * verifier — extended, never forked.
 */
@NullMarked
package io.axiam.sdk.oidc;

import org.jspecify.annotations.NullMarked;
