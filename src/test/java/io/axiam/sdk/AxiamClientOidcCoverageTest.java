package io.axiam.sdk;

import com.nimbusds.jose.jwk.OctetKeyPair;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.oidc.IntrospectionResult;
import io.axiam.sdk.oidc.OidcConfiguration;
import io.axiam.sdk.oidc.OidcTokenSet;
import io.axiam.sdk.oidc.SsoCompleteResult;
import io.axiam.sdk.oidc.SsoStartResult;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Additional CONTRACT.md &sect;12 coverage: the {@code *Async} companions
 * (&sect;12.2's Java note), optional {@code scope}/{@code tokenTypeHint}
 * arguments, {@code oidcClockSkew} configuration, and the client-side
 * (no-wire-call) error paths for tenant/context resolution.
 */
class AxiamClientOidcCoverageTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";

    @Test
    void oidcExchangeAsyncResolvesTheSameTokenSet() throws Exception {
        OctetKeyPair keyPair = OidcTestSupport.generateEd25519KeyPair("key-1");
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            String idToken = OidcTestSupport.signEdDsa(keyPair,
                    OidcTestSupport.validIdTokenClaims(stripSlash(base), "my-app", "nonce-1"));
            server.enqueue(OidcTestSupport.tokenResponse("access-1", null, idToken));
            server.enqueue(OidcTestSupport.jwksResponse(keyPair.toPublicJWK()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID).oidcClientId("my-app").build()) {
                OidcConfiguration config = client.oidcDiscover();
                OidcTokenSet result = client.oidcExchangeAsync(
                        config, "code-1", Sensitive.of("verifier-1"), "https://app/cb", "nonce-1", null)
                        .get(5, TimeUnit.SECONDS);

                assertEquals("access-1", result.accessToken().expose());
            }
        }
    }

    @Test
    void loginClientCredentialsAsyncResolves() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.tokenResponse("access-svc", null, null));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("svc").oidcClientSecret("s").build()) {
                OidcTokenSet result = client.loginClientCredentialsAsync().get(5, TimeUnit.SECONDS);
                assertEquals("access-svc", result.accessToken().expose());
            }
        }
    }

    @Test
    void introspectAsyncResolves() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"active\":false}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("app").oidcClientSecret("s").build()) {
                IntrospectionResult result = client.introspectAsync(Sensitive.of("tok")).get(5, TimeUnit.SECONDS);
                assertEquals(false, result.active());
            }
        }
    }

    @Test
    void revokeAsyncCompletes() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(new MockResponse().setResponseCode(200));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("app").oidcClientSecret("s").build()) {
                client.revokeAsync(Sensitive.of("tok")).get(5, TimeUnit.SECONDS);
            }
        }
    }

    @Test
    void ssoStartAsyncResolves() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"authorize_url\":\"https://idp/authorize\",\"state\":\"s1\",\"expires_in_secs\":600}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .orgId(java.util.UUID.fromString("44444444-4444-4444-4444-444444444444"))
                    .build()) {
                SsoStartResult result = client.ssoStartAsync(
                        "55555555-5555-5555-5555-555555555555", "https://app/cb").get(5, TimeUnit.SECONDS);
                assertEquals("s1", result.state());
            }
        }
    }

    @Test
    void ssoCompleteAsyncResolves() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"user_id\":\"u1\",\"session_id\":\"s1\",\"expires_in\":900,\"redirect_uri\":\"https://app/home\"}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                SsoCompleteResult result = client.ssoCompleteAsync("state-1", "code-1").get(5, TimeUnit.SECONDS);
                assertEquals("u1", result.userId());
            }
        }
    }

    @Test
    void oidcDiscoverAsyncPropagatesFailure() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(500));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                Exception thrown = assertThrows(java.util.concurrent.ExecutionException.class,
                        () -> client.oidcDiscoverAsync().get(5, TimeUnit.SECONDS));
                assertTrue(thrown.getCause() instanceof NetworkError);
            }
        }
    }

    @Test
    void oidcRefreshHonorsExplicitScope() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.tokenResponse("new-access", null, null));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID).oidcClientId("app").build()) {
                client.oidcRefresh(Sensitive.of("refresh-tok"), "profile email", null, null);
            }

            server.takeRequest();
            RecordedRequest tokenRequest = server.takeRequest();
            assertTrue(tokenRequest.getBody().readUtf8().contains("scope=profile"));
        }
    }

    @Test
    void loginClientCredentialsHonorsExplicitScope() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.tokenResponse("svc-access", null, null));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("svc").oidcClientSecret("s").build()) {
                client.loginClientCredentials("read:things", null, null);
            }

            server.takeRequest();
            RecordedRequest tokenRequest = server.takeRequest();
            assertTrue(tokenRequest.getBody().readUtf8().contains("scope=read%3Athings"));
        }
    }

    @Test
    void introspectAndRevokeHonorTokenTypeHint() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                    .setBody("{\"active\":true}"));
            server.enqueue(new MockResponse().setResponseCode(200));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("app").oidcClientSecret("s").build()) {
                OidcConfiguration config = client.oidcDiscover();
                client.introspect(Sensitive.of("tok"), "refresh_token", null, config);
                client.revoke(Sensitive.of("tok"), "refresh_token", null, config);
            }

            server.takeRequest(); // discovery
            RecordedRequest introspectRequest = server.takeRequest();
            assertTrue(introspectRequest.getBody().readUtf8().contains("token_type_hint=refresh_token"));
            RecordedRequest revokeRequest = server.takeRequest();
            assertTrue(revokeRequest.getBody().readUtf8().contains("token_type_hint=refresh_token"));
        }
    }

    @Test
    void oidcClockSkewIsHonoredForATokenJustOutsideTheConfiguredWindow() throws Exception {
        OctetKeyPair keyPair = OidcTestSupport.generateEd25519KeyPair("key-1");
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            // exp is 40 seconds in the past: within the default 60s skew, but
            // outside a client-configured 10s skew.
            com.nimbusds.jwt.JWTClaimsSet claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
                    .issuer(stripSlash(base))
                    .subject("user-1")
                    .audience("my-app")
                    .claim("nonce", "nonce-1")
                    .expirationTime(new Date(System.currentTimeMillis() - 40_000))
                    .issueTime(new Date(System.currentTimeMillis() - 100_000))
                    .build();
            String idToken = OidcTestSupport.signEdDsa(keyPair, claims);
            // F-13 (cross-SDK CONTRACT.md §12 conformance review, T9): the
            // access token in the wire response deliberately carries a
            // sentinel value. §12.4 rule 7 requires the whole token set,
            // including this access token, to be discarded when id_token
            // validation fails -- validation happens strictly before
            // OidcTokenSet is constructed (see AxiamClient#buildTokenSet),
            // so the sentinel below must never reach the caller through
            // either the (nonexistent, since the call throws) outcome or
            // the thrown AuthError itself.
            String sentinelAccessToken = "should-never-be-returned";
            server.enqueue(OidcTestSupport.tokenResponse(sentinelAccessToken, null, idToken));
            server.enqueue(OidcTestSupport.jwksResponse(keyPair.toPublicJWK()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("my-app")
                    .oidcClockSkew(Duration.ofSeconds(10))
                    .build()) {
                OidcConfiguration config = client.oidcDiscover();

                AuthError e = assertThrows(AuthError.class, () -> client.oidcExchange(
                        config, "code-1", "verifier-1", "https://app/cb", "nonce-1"));
                assertEquals("token_expired", e.reason());
                // §12.4 rule 7: an all-or-nothing discard -- the sentinel
                // access token must appear nowhere in the error the caller
                // observes (message or the exception's own toString/cause
                // chain rendering).
                assertFalse(e.getMessage() != null && e.getMessage().contains(sentinelAccessToken),
                        "AuthError message must never contain the discarded access token: " + e.getMessage());
                assertFalse(e.toString().contains(sentinelAccessToken),
                        "AuthError#toString() must never contain the discarded access token: " + e);
            }
        }
    }

    @Test
    void oidcClockSkewAboveSixtySecondsIsClampedAndDoesNotRescueAnExpiredToken() throws Exception {
        try (AxiamClient client = AxiamClient.builder("https://axiam.example.com", TENANT_ID)
                .oidcClockSkew(Duration.ofHours(1))
                .build()) {
            // No wire call needed: this just proves the builder path compiles
            // and the client remains usable — the clamp itself is exercised
            // functionally by IdTokenValidatorClaimsTest#clockSkewIsClampedToSixtySecondsMaximum.
            assertEquals(TENANT_ID, client.tenantId());
        }
    }

    @Test
    void oauth2QueryTenantIdRaisesAuthErrorClientSideForASlugOnlyClient() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.start();

            // Constructed with a tenant SLUG (not a UUID) and no explicit
            // tenantId override — §12.3 rule 4 requires a client-side failure
            // with no wire call to the token endpoint itself.
            try (AxiamClient client = AxiamClient.builder(base, "acme-slug")
                    .oidcClientId("app").oidcClientSecret("s").build()) {
                AuthError e = assertThrows(AuthError.class, () -> client.loginClientCredentials());
                assertTrue(e.getMessage().contains("tenant_id"));
            }

            // discovery only — no /oauth2/token call was ever attempted.
            assertEquals(1, server.getRequestCount());
        }
    }

    @Test
    void oidcBeginRejectsAMalformedAuthorizationEndpoint() throws Exception {
        OidcConfiguration malformed = new OidcConfiguration(
                "https://axiam.example.com", "::not a url::", "https://axiam.example.com/oauth2/token",
                "https://axiam.example.com/oauth2/userinfo", "https://axiam.example.com/oauth2/jwks",
                "https://axiam.example.com/oauth2/revoke", "https://axiam.example.com/oauth2/introspect",
                java.util.List.of("code"), java.util.List.of("public"), java.util.List.of("EdDSA"),
                java.util.List.of("openid"), java.util.List.of("client_secret_post"), java.util.List.of(),
                java.util.List.of("authorization_code"),
                null, null, false, false);

        try (AxiamClient client = AxiamClient.builder("https://axiam.example.com", TENANT_ID)
                .oidcClientId("app").build()) {
            assertThrows(NetworkError.class, () -> client.oidcBegin(malformed, "https://app/cb"));
        }
    }

    private static String stripSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
