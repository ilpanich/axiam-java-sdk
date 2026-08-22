package io.axiam.sdk.examples.parlogin;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.OAuthProtocolError;
import io.axiam.sdk.oidc.AuthorizationRequest;
import io.axiam.sdk.oidc.OidcConfiguration;
import io.axiam.sdk.oidc.OidcTokenSet;
import io.axiam.sdk.oidc.PushedAuthorizationRequest;

/**
 * CONTRACT.md &sect;26 — Pushed Authorization Requests (RFC 9126).
 *
 * <p>PAR moves the authorization request off the browser. Instead of putting
 * {@code scope}, {@code redirect_uri}, {@code state} and the PKCE challenge
 * into a URL the user agent carries, the client POSTs them straight to AXIAM
 * over an authenticated back channel and puts an opaque {@code request_uri} in
 * the redirect. What travels through the browser is then a random string that
 * cannot be edited into meaning something else.
 *
 * <p><strong>A FAPI 2.0 client has no choice</strong>: {@code profile: "fapi2"}
 * refuses a registration that does not set {@code require_par}, so such a
 * client cannot authorize any other way (&sect;21.1).
 *
 * <p>Run: {@code AXIAM_BASE_URL=... AXIAM_TENANT_ID=... AXIAM_CLIENT_ID=...
 * AXIAM_CLIENT_SECRET=... java ParLoginExample.java}
 */
public final class ParLoginExample {

    private static final String REDIRECT_URI = "https://app.example.com/callback";

    public static void main(String[] args) {
        String baseUrl = env("AXIAM_BASE_URL", "https://axiam.example.com");
        String tenantId = env("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000");

        try (AxiamClient client = AxiamClient.builder(baseUrl, tenantId)
                .oidcClientId(env("AXIAM_CLIENT_ID", "app"))
                .oidcClientSecret(env("AXIAM_CLIENT_SECRET", "s3cret"))
                .build()) {

            OidcConfiguration config = client.oidcDiscover();

            // §26 is optional, so a server may advertise no endpoint at all.
            // The SDK refuses client-side rather than concatenating a URL onto
            // the issuer and POSTing a fully-formed authorization request at a
            // 404 (§12.7.2 rule 1).
            if (config.pushed_authorization_request_endpoint() == null) {
                System.out.println("this server does not support RFC 9126 — "
                        + "fall back to the plain oidcBegin redirect");
                return;
            }

            pushAndRedirect(client, config);
        }
    }

    private static void pushAndRedirect(AxiamClient client, OidcConfiguration config) {
        // oidcBegin still runs first, and still owns state/nonce/PKCE. §26.2
        // rule 1 forbids a second generator: two sources for any of those are
        // two things that can disagree.
        AuthorizationRequest begun = client.oidcBegin(config, REDIRECT_URI, "openid profile", null);

        PushedAuthorizationRequest pushed;
        try {
            pushed = client.oidcPar(config, begun, REDIRECT_URI, "openid profile", null);
        } catch (OAuthProtocolError e) {
            System.out.println("the server rejected the push: " + e.error());
            return;
        } catch (AuthError e) {
            System.out.println("no PAR endpoint: " + e.getMessage());
            return;
        }
        // Note there is no retry here, and there must not be. This is a POST
        // that creates server state, so it falls outside §16.2's read-only
        // eligibility. The safe recovery is a fresh push, which costs one
        // round trip and cannot double-consume anything (§26.2 rule 4).

        // The URL carries EXACTLY client_id and request_uri. The server
        // refuses a request that mixes a request_uri with inline authorization
        // parameters rather than merging them — an attacker supplies the
        // inline value they want and lets the pushed copy satisfy whichever
        // check reads the other one. Re-adding scope "for compatibility"
        // restores the attack (§26.2 rule 2).
        System.out.println("redirect the browser to: " + pushed.url());
        System.out.println("the handle expires in " + pushed.expiresIn() + "s");

        // Persist these three exactly as a non-PAR login would — the redirect
        // being opaque changes nothing about the callback's obligations.
        rememberForTheCallback(pushed.state(), pushed.nonce(), pushed.codeVerifier());

        completeTheCallback(client, config, pushed);
    }

    private static void completeTheCallback(AxiamClient client, OidcConfiguration config,
            PushedAuthorizationRequest pushed) {
        String code = codeFromTheCallbackQuery();
        String returnedState = stateFromTheCallbackQuery();

        if (!pushed.state().equals(returnedState)) {
            // Constant-time comparison is the better habit here; state is not
            // a secret (§12.3 rule 2), but the check itself is the CSRF guard.
            System.out.println("state mismatch — drop this callback on the floor");
            return;
        }

        // The exchange is the ordinary §12 one. The request_uri is spent by
        // now: it is single-use, and a second redirect through it fails.
        OidcTokenSet tokens = client.oidcExchange(
                config, code, pushed.codeVerifier(), REDIRECT_URI, pushed.nonce(), null);
        System.out.println("signed in, id token subject: "
                + (tokens.idClaims() == null ? "(none)" : tokens.idClaims().sub()));
    }

    // ------------------------------------------------------------------

    private static void rememberForTheCallback(String state, String nonce, Sensitive codeVerifier) {
        // A real application puts these in its own HTTP session, or in an
        // io.axiam.sdk.oidc.OidcStateStore. The SDK stores nothing itself
        // (§12.3 rule 1).
        System.out.println("  stashed state/nonce/verifier for the callback");
    }

    private static String codeFromTheCallbackQuery() {
        return env("AXIAM_AUTH_CODE", "the-code-from-the-redirect");
    }

    private static String stateFromTheCallbackQuery() {
        return env("AXIAM_STATE", "the-state-from-the-redirect");
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? fallback : value;
    }

    private ParLoginExample() {
    }
}
