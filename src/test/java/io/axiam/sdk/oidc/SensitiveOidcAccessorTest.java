package io.axiam.sdk.oidc;

import com.nimbusds.jose.jwk.OctetKeyPair;

import io.axiam.sdk.AxiamClient;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Follow-up F-02 (cross-SDK CONTRACT.md &sect;12 conformance review, T9):
 * {@link Sensitive#expose()} was package-private to {@code io.axiam.sdk},
 * so a caller holding an {@link OidcTokenSet} — returned from
 * <em>this</em> package, {@code io.axiam.sdk.oidc} — could not read
 * {@code accessToken()}/{@code refreshToken()}/{@code idToken()} at all.
 * This class lives in that other package deliberately: before the fix these
 * tests would not have compiled, since {@code expose()} was not visible
 * here. Now that CONTRACT.md &sect;7 rule 3 recommends widening the
 * accessor for &sect;12, these tests prove (a) the accessor is genuinely
 * reachable from outside {@code io.axiam.sdk}, (b) redaction still holds
 * everywhere it always did, and (c) a caller can rehydrate a bare
 * {@code code_verifier} it persisted itself and hand it back into
 * {@code oidcExchange}.
 */
class SensitiveOidcAccessorTest {

    private static final String TENANT_ID = "44444444-4444-4444-4444-444444444444";

    @Test
    void callerOutsideTheSdkPackageCanReadTheAccessTokenFromAnExchangedTokenSet() throws Exception {
        OctetKeyPair keyPair = OidcTestSupport.generateEd25519KeyPair("key-1");
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            String idToken = OidcTestSupport.signEdDsa(keyPair,
                    OidcTestSupport.validIdTokenClaims(stripSlash(base), "my-app", "the-nonce"));
            server.enqueue(OidcTestSupport.tokenResponse("caller-visible-access-tok", "caller-visible-refresh-tok", idToken));
            server.enqueue(OidcTestSupport.jwksResponse(keyPair.toPublicJWK()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("my-app")
                    .build()) {
                OidcConfiguration config = client.oidcDiscover();

                OidcTokenSet tokenSet = client.oidcExchange(
                        config, "auth-code-1", "the-verifier", "https://app.example.com/cb", "the-nonce");

                // The round trip a real §12 caller performs: read the raw
                // token back out of the SDK type to persist/forward it.
                // Sensitive.expose() must be public for this to compile.
                String accessToken = tokenSet.accessToken().expose();
                String refreshToken = tokenSet.refreshToken().expose();

                assertEquals("caller-visible-access-tok", accessToken);
                assertEquals("caller-visible-refresh-tok", refreshToken);
            }
        }
    }

    @Test
    void redactionStillHoldsOnTheWrapperAndOnAContainingTokenSetAfterWidening() {
        Sensitive accessToken = Sensitive.of("must-never-appear-in-output");

        assertEquals("[SENSITIVE]", accessToken.toString());
        assertFalse(accessToken.toString().contains("must-never-appear-in-output"));

        OidcTokenSet tokenSet = new OidcTokenSet(accessToken, "Bearer", 900, null,
                Sensitive.of("refresh-must-never-appear"), null, null);

        String tokenSetToString = tokenSet.toString();
        assertTrue(tokenSetToString.contains("[SENSITIVE]"),
                "OidcTokenSet.toString() must redact its Sensitive components: " + tokenSetToString);
        assertFalse(tokenSetToString.contains("must-never-appear-in-output"));
        assertFalse(tokenSetToString.contains("refresh-must-never-appear"));
    }

    @Test
    void aCallerCanRehydrateABareCodeVerifierWithTheFactoryAndExchangeIt() throws Exception {
        OctetKeyPair keyPair = OidcTestSupport.generateEd25519KeyPair("key-2");
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            String idToken = OidcTestSupport.signEdDsa(keyPair,
                    OidcTestSupport.validIdTokenClaims(stripSlash(base), "my-app", "the-nonce"));
            server.enqueue(OidcTestSupport.tokenResponse("rehydrated-flow-access-tok", null, idToken));
            server.enqueue(OidcTestSupport.jwksResponse(keyPair.toPublicJWK()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("my-app")
                    .build()) {
                OidcConfiguration config = client.oidcDiscover();

                // Simulates a caller that persisted the bare code_verifier
                // string in its own session store and must wrap it again
                // before passing it back into oidcExchange — Sensitive.of()
                // is the public factory for exactly this purpose.
                String bareVerifierFromCallersOwnStore = "rehydrated-verifier-value";
                Sensitive rehydrated = Sensitive.of(bareVerifierFromCallersOwnStore);

                OidcTokenSet tokenSet = client.oidcExchange(
                        config, "auth-code-2", rehydrated, "https://app.example.com/cb", "the-nonce", null);

                assertNotNull(tokenSet);
                assertEquals("rehydrated-flow-access-tok", tokenSet.accessToken().expose());
            }
        }
    }

    private static String stripSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
