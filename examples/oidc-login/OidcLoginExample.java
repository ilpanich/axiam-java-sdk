package io.axiam.sdk.examples.oidclogin;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.OAuthProtocolError;
import io.axiam.sdk.oidc.AuthorizationRequest;
import io.axiam.sdk.oidc.IntrospectionResult;
import io.axiam.sdk.oidc.OidcConfiguration;
import io.axiam.sdk.oidc.OidcTokenSet;

/**
 * Demonstrates the CONTRACT.md &sect;12 OIDC/SSO relying-party helpers,
 * importing ONLY public SDK entry points ({@code io.axiam.sdk.AxiamClient},
 * {@code io.axiam.sdk.oidc.*} — never {@code io.axiam.sdk.internal.*}).
 *
 * <p>Three independent demonstrations, each illustrative/compilable against
 * the SDK's public API:
 *
 * <ol>
 *   <li>{@code oidcDiscover}/{@code oidcBegin} — builds a "Login with AXIAM"
 *       redirect URL. A real web application would send the browser to this
 *       URL and persist {@code state}/{@code nonce}/{@code codeVerifier} in
 *       its own HTTP session (or an {@link io.axiam.sdk.oidc.OidcStateStore})
 *       for the callback — see {@code io.axiam.sdk.spring.AxiamOidcLoginRoutes}
 *       for a ready-made Spring MVC pair that does exactly this.</li>
 *   <li>{@code loginClientCredentials}/{@code introspect}/{@code revoke} —
 *       the full machine-to-machine flow, runnable end-to-end from a CLI
 *       against a reachable AXIAM server.</li>
 *   <li>{@code oidcExchange} — shown as a documented snippet (not run) since
 *       completing it requires a real authorization code from a browser
 *       redirect, which this CLI example cannot obtain.</li>
 * </ol>
 *
 * <p>Run: {@code AXIAM_BASE_URL=... AXIAM_TENANT_ID=... AXIAM_CLIENT_ID=...
 * AXIAM_CLIENT_SECRET=... java OidcLoginExample.java}
 */
public final class OidcLoginExample {

    public static void main(String[] args) {
        String baseUrl = getenv("AXIAM_BASE_URL", "https://localhost:8443");
        String tenantId = getenv("AXIAM_TENANT_ID", "33333333-3333-3333-3333-333333333333");
        String clientId = getenv("AXIAM_CLIENT_ID", "my-app");
        String clientSecret = getenv("AXIAM_CLIENT_SECRET", "");
        String redirectUri = getenv("AXIAM_REDIRECT_URI", "https://app.example.com/oidc/callback");

        // §6: TLS is always strict — the only escape hatch is
        // Builder.customCa(pem), never a boolean bypass. §12: oidcClientId is
        // configured once at construction time (never a per-call argument) —
        // it is also what §12.4 rule 4 matches an ID token's aud/azp against.
        AxiamClient.Builder builder = AxiamClient.builder(baseUrl, tenantId).oidcClientId(clientId);
        if (!clientSecret.isBlank()) {
            // A confidential client secret is required for introspect/revoke/
            // loginClientCredentials (§12.1 note 4) — omit it for a public
            // client that only performs the authorization-code flow.
            builder.oidcClientSecret(clientSecret);
        }

        try (AxiamClient client = builder.build()) {
            demonstrateAuthorizationCodeRedirect(client, redirectUri);

            if (!clientSecret.isBlank()) {
                demonstrateClientCredentials(client);
            } else {
                System.out.println("\nAXIAM_CLIENT_SECRET not set — skipping the client_credentials/introspect/revoke demo.");
            }
        }
    }

    /**
     * Step 1 of "Login with AXIAM": fetch the discovery document (cached,
     * &ge;5-minute TTL) and build the authorization URL. Nothing is stored by
     * the SDK — persist {@code state}/{@code nonce}/{@code codeVerifier}
     * yourself (CONTRACT.md &sect;12.3 rule 1).
     */
    private static void demonstrateAuthorizationCodeRedirect(AxiamClient client, String redirectUri) {
        OidcConfiguration configuration = client.oidcDiscover();
        AuthorizationRequest request = client.oidcBegin(configuration, redirectUri, "openid profile", null);

        System.out.println("Redirect the browser to:");
        System.out.println("  " + request.url());
        System.out.println("Persist these before redirecting (your own HTTP session, or an OidcStateStore):");
        System.out.println("  state=" + request.state());
        System.out.println("  nonce=" + request.nonce());
        System.out.println("  codeVerifier=" + request.codeVerifier()); // [SENSITIVE] — never logged in real code

        // On the callback (GET redirectUri?code=...&state=...), after
        // confirming the returned state matches what you persisted:
        //
        //   OidcTokenSet tokens = client.oidcExchange(
        //       configuration, code, request.codeVerifier(), redirectUri, request.nonce());
        //   System.out.println("Authenticated subject: " + tokens.idClaims().sub());
        //
        // Any CONTRACT.md §12.4 ID-token failure (invalid_alg, unknown_kid,
        // invalid_signature, invalid_issuer, invalid_audience, token_expired,
        // nonce_mismatch) raises AuthError with that reason code and discards
        // the whole token set — the access/refresh token is never returned.
    }

    /** Service-account login, introspection, and revocation — requires a confidential client (&sect;12.1 note 4). */
    private static void demonstrateClientCredentials(AxiamClient client) {
        OidcTokenSet tokens;
        try {
            tokens = client.loginClientCredentials();
        } catch (AuthError e) {
            System.err.println("loginClientCredentials failed: " + e.getMessage());
            return;
        }

        // tokens.accessToken() is Sensitive<String> — toString()/logging never
        // exposes the raw value (CONTRACT.md §12.5); expose() is intentionally
        // not part of the public API.
        System.out.println("\nService-account access token acquired (expires in " + tokens.expiresIn() + "s).");

        Sensitive accessToken = tokens.accessToken();
        try {
            IntrospectionResult introspection = client.introspect(accessToken);
            System.out.println("introspect: active=" + introspection.active() + ", clientId=" + introspection.clientId());
        } catch (OAuthProtocolError e) {
            System.err.println("introspect failed: " + e.error() + ": " + e.errorDescription());
            return;
        }

        // revoke is idempotent — any 200 (including for a token the server
        // has never seen) is success (CONTRACT.md §12.1 note 5).
        client.revoke(accessToken);
        System.out.println("revoke: done");
    }

    private static String getenv(String key, String fallback) {
        String v = System.getenv(key);
        return (v == null || v.isBlank()) ? fallback : v;
    }

    private OidcLoginExample() {
    }
}
