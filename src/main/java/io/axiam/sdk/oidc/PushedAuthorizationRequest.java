package io.axiam.sdk.oidc;

import io.axiam.sdk.Sensitive;

/**
 * The result of {@code oidcPar} (CONTRACT.md &sect;26.1).
 *
 * <p>The server answered <strong>201</strong> — RFC 9126 &sect;2.2 specifies
 * Created, and a success predicate written {@code == 200} would treat every
 * successful push as a failure.
 *
 * <p>{@code state}, {@code nonce} and {@code codeVerifier} are carried straight
 * through from the {@link AuthorizationRequest} that was pushed: &sect;26.2
 * rule 1 forbids a second generator, and rule 6 wants exactly one
 * {@code codeVerifier} so there is no second place for the two to disagree.
 *
 * @param url          where to redirect the user agent. Carries
 *                     <strong>exactly</strong> {@code client_id} and
 *                     {@code request_uri} — the server refuses a request that
 *                     mixes a {@code request_uri} with inline authorization
 *                     parameters rather than merging them, because merging is
 *                     where parameter confusion lives (&sect;26.2 rule 2).
 * @param requestUri   the opaque, single-use handle. {@link Sensitive} per
 *                     &sect;26.5: between the push and the redirect it is a
 *                     bearer handle to a fully-formed authorization request,
 *                     and a log line is the wrong place for it to sit for the
 *                     length of that window.
 * @param expiresIn    the handle's lifetime in seconds; not advisory (&sect;26.2 rule 3)
 * @param state        the value to compare against the {@code state} the IdP returns
 * @param nonce        the value that must equal the ID token's {@code nonce} claim
 * @param codeVerifier the PKCE verifier to pass into {@code oidcExchange} — the
 *                     same one {@code oidcBegin} produced
 */
public record PushedAuthorizationRequest(
        String url,
        Sensitive requestUri,
        long expiresIn,
        String state,
        String nonce,
        Sensitive codeVerifier) {
}
