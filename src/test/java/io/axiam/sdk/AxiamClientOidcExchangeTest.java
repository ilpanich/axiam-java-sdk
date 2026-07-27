package io.axiam.sdk;

import com.nimbusds.jose.jwk.OctetKeyPair;

import io.axiam.sdk.errors.OAuthProtocolError;
import io.axiam.sdk.oidc.AuthorizationRequest;
import io.axiam.sdk.oidc.OidcConfiguration;
import io.axiam.sdk.oidc.OidcTokenSet;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12.1 {@code oidcBegin}/{@code oidcExchange}: local
 * authorization-request construction (S256-only, RFC 3986 percent-encoding,
 * reserved-parameter protection) and the full authorization-code exchange
 * (form-encoded body, {@code ?tenant_id=} query parameter, ID-token
 * validation, and {@code OAuth2ErrorResponse} &rarr; {@code OAuthProtocolError}).
 */
class AxiamClientOidcExchangeTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";

    @Test
    void oidcBeginBuildsTheEightMandatedParametersWithS256() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .oidcClientId("my-app")
                    .build()) {
                OidcConfiguration config = client.oidcDiscover();
                AuthorizationRequest request = client.oidcBegin(config, "https://app.example.com/callback");

                HttpUrl url = HttpUrl.parse(request.url());
                assertNotNull(url);
                assertEquals("code", url.queryParameter("response_type"));
                assertEquals("my-app", url.queryParameter("client_id"));
                assertEquals("https://app.example.com/callback", url.queryParameter("redirect_uri"));
                assertEquals("openid", url.queryParameter("scope"));
                assertEquals(request.state(), url.queryParameter("state"));
                assertEquals(request.nonce(), url.queryParameter("nonce"));
                assertEquals("S256", url.queryParameter("code_challenge_method"));
                assertNotNull(url.queryParameter("code_challenge"));

                // §12.1 rule 3: verifier <-> challenge relationship holds.
                String verifier = request.codeVerifier().expose();
                assertEquals(io.axiam.sdk.oidc.OidcPkce.computeCodeChallenge(verifier), url.queryParameter("code_challenge"));
            }
        }
    }

    @Test
    void oidcBeginAddsOpenidWhenScopeOmitsIt() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .oidcClientId("my-app")
                    .build()) {
                OidcConfiguration config = client.oidcDiscover();
                AuthorizationRequest request = client.oidcBegin(config, "https://app.example.com/cb", "profile email", null);

                HttpUrl url = HttpUrl.parse(request.url());
                assertEquals("openid profile email", url.queryParameter("scope"));
            }
        }
    }

    @Test
    void oidcBeginEncodesSpacesAsPercent20NotPlus() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .oidcClientId("my-app")
                    .build()) {
                OidcConfiguration config = client.oidcDiscover();
                AuthorizationRequest request = client.oidcBegin(config, "https://app.example.com/cb", "profile email", null);

                assertTrue(request.url().contains("scope=openid%20profile%20email"),
                        "spaces in query values must be %20-encoded, not '+' (port-brief-addendum item 10): " + request.url());
            }
        }
    }

    @Test
    void oidcBeginRejectsExtraParamsOverridingAnSdkOwnedParameter() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .oidcClientId("my-app")
                    .build()) {
                OidcConfiguration config = client.oidcDiscover();

                assertThrows(IllegalArgumentException.class, () -> client.oidcBegin(
                        config, "https://app.example.com/cb", null, Map.of("client_id", "attacker-app")));
            }
        }
    }

    @Test
    void oidcBeginPermitsNonReservedExtraParams() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .oidcClientId("my-app")
                    .build()) {
                OidcConfiguration config = client.oidcDiscover();
                AuthorizationRequest request = client.oidcBegin(
                        config, "https://app.example.com/cb", null, Map.of("prompt", "login"));

                assertEquals("login", HttpUrl.parse(request.url()).queryParameter("prompt"));
            }
        }
    }

    @Test
    void oidcBeginRequiresClientIdConfiguredAtConstruction() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                OidcConfiguration config = client.oidcDiscover();
                assertThrows(io.axiam.sdk.errors.AuthError.class,
                        () -> client.oidcBegin(config, "https://app.example.com/cb"));
            }
        }
    }

    @Test
    void oidcExchangeSendsFormEncodedBodyWithTenantIdQueryParam() throws Exception {
        OctetKeyPair keyPair = OidcTestSupport.generateEd25519KeyPair("key-1");
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            String idToken = OidcTestSupport.signEdDsa(keyPair,
                    OidcTestSupport.validIdTokenClaims(stripSlash(base), "my-app", "the-nonce"));
            server.enqueue(OidcTestSupport.tokenResponse("access-tok-1", "refresh-tok-1", idToken));
            server.enqueue(OidcTestSupport.jwksResponse(keyPair.toPublicJWK()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("my-app")
                    .oidcClientSecret("shh-secret")
                    .build()) {
                OidcConfiguration config = client.oidcDiscover();

                OidcTokenSet tokenSet = client.oidcExchange(
                        config, "auth-code-1", "the-verifier", "https://app.example.com/cb", "the-nonce");

                assertEquals("access-tok-1", tokenSet.accessToken().expose());
                assertEquals("refresh-tok-1", tokenSet.refreshToken().expose());
                assertEquals("Bearer", tokenSet.tokenType());
                assertNotNull(tokenSet.idClaims());
                assertEquals("user-1", tokenSet.idClaims().sub());
            }

            server.takeRequest(); // discovery
            RecordedRequest tokenRequest = server.takeRequest();
            assertEquals("/oauth2/token", tokenRequest.getPath().split("\\?")[0]);
            assertTrue(tokenRequest.getPath().contains("tenant_id=" + TENANT_ID));
            assertEquals("application/x-www-form-urlencoded", tokenRequest.getHeader("Content-Type"));
            String body = tokenRequest.getBody().readUtf8();
            assertTrue(body.contains("grant_type=authorization_code"));
            assertTrue(body.contains("code=auth-code-1"));
            assertTrue(body.contains("code_verifier=the-verifier"));
            assertTrue(body.contains("client_id=my-app"));
            assertTrue(body.contains("client_secret=shh-secret"));
        }
    }

    @Test
    void loginClientCredentialsRequestsNoOpenidAndCarriesNoIdToken() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.tokenResponse("service-access-tok", null, null));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("service-app")
                    .oidcClientSecret("service-secret")
                    .build()) {
                OidcTokenSet tokenSet = client.loginClientCredentials();

                assertEquals("service-access-tok", tokenSet.accessToken().expose());
                assertNull(tokenSet.idToken());
                assertNull(tokenSet.idClaims());
            }

            server.takeRequest(); // discovery
            RecordedRequest tokenRequest = server.takeRequest();
            String body = tokenRequest.getBody().readUtf8();
            assertTrue(body.contains("grant_type=client_credentials"));
        }
    }

    @Test
    void oAuth2ErrorResponseOn400BecomesOAuthProtocolError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(new MockResponse()
                    .setResponseCode(400)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"error\":\"invalid_grant\",\"error_description\":\"the authorization code has expired\"}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("my-app")
                    .build()) {
                OidcConfiguration config = client.oidcDiscover();

                OAuthProtocolError error = assertThrows(OAuthProtocolError.class, () -> client.oidcExchange(
                        config, "bad-code", "verifier", "https://app.example.com/cb", "nonce-1"));

                assertEquals("invalid_grant: the authorization code has expired", error.getMessage());
                assertEquals("invalid_grant", error.error());
            }
        }
    }

    private static String stripSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
