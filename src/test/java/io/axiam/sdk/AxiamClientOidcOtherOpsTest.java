package io.axiam.sdk;

import io.axiam.sdk.errors.OAuthProtocolError;
import io.axiam.sdk.oidc.IntrospectionResult;
import io.axiam.sdk.oidc.OidcTokenSet;
import io.axiam.sdk.testutil.OidcTestSupport;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12.1 {@code introspect}/{@code revoke}/{@code oidcRefresh}:
 * confidential-client-only, idempotent revoke, the &sect;9 single-flight
 * guard, the &sect;12.3 rule 3 "401 from /oauth2/* must not enter the refresh
 * guard" requirement, and &sect;12.5 {@code Sensitive} redaction.
 */
class AxiamClientOidcOtherOpsTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";

    @Test
    void introspectReturnsActiveTokenMetadata() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"active\":true,\"sub\":\"user-1\",\"client_id\":\"my-app\",\"scope\":\"openid\","
                            + "\"token_type\":\"Bearer\",\"exp\":1999999999,\"iat\":1999999000}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("my-app")
                    .oidcClientSecret("shh")
                    .build()) {
                IntrospectionResult result = client.introspect("some-token");

                assertTrue(result.active());
                assertEquals("user-1", result.sub());
                assertEquals("my-app", result.clientId());
                assertEquals(1999999999L, result.exp());
            }

            server.takeRequest(); // discovery
            RecordedRequest introspectRequest = server.takeRequest();
            assertTrue(introspectRequest.getPath().startsWith("/oauth2/introspect"));
            assertTrue(introspectRequest.getPath().contains("tenant_id=" + TENANT_ID));
            String body = introspectRequest.getBody().readUtf8();
            assertTrue(body.contains("token=some-token"));
            assertTrue(body.contains("client_secret=shh"));
        }
    }

    @Test
    void introspectRequiresConfidentialClientCredentials() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .oidcClientId("public-app")
                    .build()) {
                assertThrows(io.axiam.sdk.errors.AuthError.class, () -> client.introspect("some-token"));
            }
        }
    }

    @Test
    void revokeTreatsAny200AsSuccessEvenForAnUnknownToken() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(new MockResponse().setResponseCode(200));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("my-app")
                    .oidcClientSecret("shh")
                    .build()) {
                assertDoesNotThrow(() -> client.revoke("never-issued-token"));
            }
        }
    }

    @Test
    void revoke401IsClientAuthenticationFailureNotSuccess() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"error\":\"invalid_client\",\"error_description\":\"bad client_secret\"}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("my-app")
                    .oidcClientSecret("wrong-secret")
                    .build()) {
                assertThrows(OAuthProtocolError.class, () -> client.revoke("some-token"));
            }
        }
    }

    @Test
    void revoke5xxStaysANetworkErrorNotSuccess() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(new MockResponse().setResponseCode(500));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("my-app")
                    .oidcClientSecret("shh")
                    .build()) {
                assertThrows(io.axiam.sdk.errors.NetworkError.class, () -> client.revoke("some-token"));
            }
        }
    }

    /**
     * CONTRACT.md &sect;12.3 rule 3: a 401 from {@code /oauth2/introspect}/
     * {@code /oauth2/revoke} must never trigger the &sect;9 single-flight
     * refresh guard — proven here by asserting NO
     * {@code /api/v1/auth/refresh} request is ever recorded, even though the
     * client holds an established (cookie) session when the 401 arrives.
     */
    @Test
    void a401FromIntrospectDoesNotEnterTheRefreshGuard() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(loginSuccessResponse());
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"error\":\"invalid_client\",\"error_description\":\"bad client_secret\"}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .orgId(java.util.UUID.fromString("44444444-4444-4444-4444-444444444444"))
                    .oidcClientId("my-app")
                    .oidcClientSecret("wrong-secret")
                    .build()) {
                client.login("alice@example.com", "correct horse battery staple");

                assertThrows(OAuthProtocolError.class, () -> client.introspect("some-token"));
            }

            // login, discovery, introspect — and NOTHING else (no refresh call).
            assertEquals(3, server.getRequestCount());
            for (int i = 0; i < 3; i++) {
                RecordedRequest recorded = server.takeRequest();
                assertFalse("/api/v1/auth/refresh".equals(recorded.getPath()),
                        "a 401 from /oauth2/introspect must never trigger /api/v1/auth/refresh (§12.3 rule 3)");
            }
        }
    }

    @Test
    void oidcRefreshHappyPathAndConcurrentCallersShareOneWireCall() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.tokenResponse("refreshed-access", "refreshed-refresh", null));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("my-app")
                    .build()) {
                int threadCount = 5;
                ExecutorService pool = Executors.newFixedThreadPool(threadCount);
                CountDownLatch startBarrier = new CountDownLatch(1);
                try {
                    java.util.List<Callable<OidcTokenSet>> tasks = new java.util.ArrayList<>();
                    for (int i = 0; i < threadCount; i++) {
                        tasks.add(() -> {
                            startBarrier.await();
                            return client.oidcRefresh("some-refresh-token");
                        });
                    }
                    java.util.List<Future<OidcTokenSet>> futures = new java.util.ArrayList<>();
                    for (Callable<OidcTokenSet> task : tasks) {
                        futures.add(pool.submit(task));
                    }
                    startBarrier.countDown();
                    for (Future<OidcTokenSet> future : futures) {
                        OidcTokenSet result = future.get(5, TimeUnit.SECONDS);
                        assertEquals("refreshed-access", result.accessToken().expose());
                    }
                } finally {
                    pool.shutdown();
                    assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
                }
            }

            // discovery (cached across all callers) + exactly one token request.
            assertEquals(2, server.getRequestCount(),
                    "N concurrent oidcRefresh callers must collapse to exactly one token-endpoint call");
        }
    }

    @Test
    void oidcRefreshIsDistinctFromCookieSessionRefresh() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.tokenResponse("oidc-access", null, null));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("my-app")
                    .build()) {
                OidcTokenSet tokenSet = client.oidcRefresh("some-refresh-token");
                assertEquals("oidc-access", tokenSet.accessToken().expose());
            }

            server.takeRequest(); // discovery
            RecordedRequest tokenRequest = server.takeRequest();
            assertTrue(tokenRequest.getPath().startsWith("/oauth2/token"),
                    "oidcRefresh must hit /oauth2/token, never /api/v1/auth/refresh");
        }
    }

    @Test
    void oidcTokenSetToStringRedactsEverySensitiveField() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            String base = server.url("/").toString();
            server.enqueue(OidcTestSupport.discoveryResponse(base));
            server.enqueue(OidcTestSupport.tokenResponse("super-secret-access", "super-secret-refresh", null));
            server.start();

            try (AxiamClient client = AxiamClient.builder(base, TENANT_ID)
                    .oidcClientId("my-app")
                    .oidcClientSecret("shh")
                    .build()) {
                OidcTokenSet tokenSet = client.loginClientCredentials();
                String repr = tokenSet.toString();

                assertFalse(repr.contains("super-secret-access"), "toString() must not leak the access token");
                assertFalse(repr.contains("super-secret-refresh"), "toString() must not leak the refresh token");
                assertTrue(repr.contains("[SENSITIVE]"));
            }
        }
    }

    @Test
    void authorizationRequestToStringRedactsTheCodeVerifier() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(OidcTestSupport.discoveryResponse(server.url("/").toString()));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .oidcClientId("my-app")
                    .build()) {
                var config = client.oidcDiscover();
                var request = client.oidcBegin(config, "https://app.example.com/cb");
                String verifier = request.codeVerifier().expose();

                assertFalse(request.toString().contains(verifier), "AuthorizationRequest.toString() must not leak code_verifier");
            }
        }
    }

    private static MockResponse loginSuccessResponse() {
        return new MockResponse()
                .setResponseCode(200)
                .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken() + "; Path=/; HttpOnly")
                .addHeader("Set-Cookie", "axiam_refresh=fake-refresh-token; Path=/; HttpOnly")
                .setHeader("Content-Type", "application/json")
                .setBody("{\"user\":{\"id\":\"11111111-1111-1111-1111-111111111111\",\"username\":\"alice\",\"email\":\"alice@example.com\"},"
                        + "\"session_id\":\"22222222-2222-2222-2222-222222222222\",\"expires_in\":900}");
    }

    private static String fakeAccessToken() {
        String header = base64Url("{\"alg\":\"EdDSA\"}");
        String payload = base64Url("{\"sub\":\"11111111-1111-1111-1111-111111111111\","
                + "\"tenant_id\":\"" + TENANT_ID + "\","
                + "\"org_id\":\"44444444-4444-4444-4444-444444444444\","
                + "\"jti\":\"22222222-2222-2222-2222-222222222222\","
                + "\"exp\":" + (System.currentTimeMillis() / 1000 + 900) + "}");
        return header + "." + payload + ".fake-signature";
    }

    private static String base64Url(String json) {
        return java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
