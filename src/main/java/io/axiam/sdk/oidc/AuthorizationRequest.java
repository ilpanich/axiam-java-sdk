package io.axiam.sdk.oidc;

import io.axiam.sdk.Sensitive;

/**
 * The result of {@code oidcBegin} (CONTRACT.md &sect;12.1) — everything the
 * caller needs to start an authorization-code + PKCE login.
 *
 * <p><strong>The caller owns this state</strong> (CONTRACT.md &sect;12.3
 * rule 1). The SDK stores nothing: it keeps no copy of {@code state},
 * {@code nonce}, or {@code codeVerifier} in process-global state or any
 * implicit cache. Persist all three in your own HTTP session (or an
 * {@link OidcStateStore}), redirect the browser to {@link #url()}, and pass
 * {@code nonce} + {@code codeVerifier} back into {@code oidcExchange} when
 * the authorization code arrives.
 *
 * @param url          the fully-built authorization URL to redirect the browser to
 * @param state        CSPRNG CSRF value (&ge;128 bits, base64url unpadded) to compare against the {@code state} the IdP returns; not a secret (CONTRACT.md &sect;12.3 rule 2)
 * @param nonce        CSPRNG replay-protection value (&ge;128 bits) that must equal the ID token's {@code nonce} claim; not a secret (&sect;12.3 rule 2)
 * @param codeVerifier the PKCE verifier, secret for its whole lifetime (&sect;12.5); pass it back into {@code oidcExchange}
 */
public record AuthorizationRequest(String url, String state, String nonce, Sensitive codeVerifier) {
}
