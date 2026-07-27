package io.axiam.sdk.oidc;

/**
 * The result of {@code ssoStart} (wire schema {@code OidcStartResponse},
 * CONTRACT.md &sect;12.1) — step 1 of first-time SSO against an upstream IdP.
 *
 * <p>There is deliberately <strong>no nonce</strong>: on the federation path
 * the nonce never leaves the server (CONTRACT.md &sect;12.1 note 7).
 * Round-trip {@link #state()} into {@code ssoComplete} unmodified — the
 * server stores it single-use with a 10-minute TTL and recovers the whole
 * login context from it.
 *
 * @param authorizeUrl  the upstream IdP authorization URL to redirect the browser to
 * @param state         single-use CSRF state to round-trip back into {@code ssoComplete} unmodified
 * @param expiresInSecs remaining TTL of the server-side state row, in seconds (600 = 10 min)
 */
public record SsoStartResult(String authorizeUrl, String state, long expiresInSecs) {
}
