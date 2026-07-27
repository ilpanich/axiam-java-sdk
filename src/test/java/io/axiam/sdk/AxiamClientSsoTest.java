package io.axiam.sdk;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.oidc.SsoCompleteResult;
import io.axiam.sdk.oidc.SsoStartResult;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12.1 {@code ssoStart}/{@code ssoComplete}: the upstream-IdP
 * federation pair — JSON request bodies, &sect;5.1 tenant/org context
 * resolution, and the &sect;4 cookie-jar session handoff on completion.
 */
class AxiamClientSsoTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String ORG_ID = "44444444-4444-4444-4444-444444444444";

    @Test
    void ssoStartSendsJsonBodyAndDefaultsTenantOrgFromClientConfiguration() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"authorize_url\":\"https://idp.example.com/authorize?x=1\",\"state\":\"state-abc\",\"expires_in_secs\":600}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .orgId(UUID.fromString(ORG_ID))
                    .build()) {
                SsoStartResult result = client.ssoStart("55555555-5555-5555-5555-555555555555", "https://app.example.com/sso-cb");

                assertEquals("https://idp.example.com/authorize?x=1", result.authorizeUrl());
                assertEquals("state-abc", result.state());
                assertEquals(600, result.expiresInSecs());
            }

            RecordedRequest request = server.takeRequest();
            assertEquals("/api/v1/auth/federation/oidc/start", request.getPath());
            assertEquals("application/json; charset=utf-8", request.getHeader("Content-Type"));
            String body = request.getBody().readUtf8();
            assertTrue(body.contains("\"federation_config_id\":\"55555555-5555-5555-5555-555555555555\""));
            assertTrue(body.contains("\"redirect_uri\":\"https://app.example.com/sso-cb\""));
            assertTrue(body.contains("\"tenant_id\":\"" + TENANT_ID + "\""));
            assertTrue(body.contains("\"org_id\":\"" + ORG_ID + "\""));
        }
    }

    @Test
    void ssoStartRequiresOrgContext() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();

            // A client built with a tenant SLUG (not UUID) and no org context
            // configured has neither a resolvable tenant UUID default relevant
            // here nor an org default at all — org context is required
            // regardless, and must fail client-side with no wire call.
            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), "acme-slug").build()) {
                assertThrows(AuthError.class,
                        () -> client.ssoStart("55555555-5555-5555-5555-555555555555", "https://app.example.com/cb"));
            }

            assertEquals(0, server.getRequestCount(), "a missing org context must fail with no wire call");
        }
    }

    @Test
    void ssoStartAcceptsExplicitTenantSlugAndOrgSlugOverrides() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"authorize_url\":\"https://idp.example.com/authorize\",\"state\":\"s\",\"expires_in_secs\":600}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                client.ssoStart("55555555-5555-5555-5555-555555555555", "https://app.example.com/cb",
                        null, "acme-tenant-slug", null, "acme-org-slug");
            }

            RecordedRequest request = server.takeRequest();
            String body = request.getBody().readUtf8();
            assertTrue(body.contains("\"tenant_slug\":\"acme-tenant-slug\""));
            assertTrue(body.contains("\"org_slug\":\"acme-org-slug\""));
        }
    }

    @Test
    void ssoStartErrorFallsThroughToGenericMappingNeverOAuthProtocolError() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            // port-brief-addendum item 12: the federation start error body
            // shape is undocumented — even an OAuth2-shaped body must NOT
            // become OAuthProtocolError here (that mapping is reserved for
            // /oauth2/* endpoints).
            server.enqueue(new MockResponse()
                    .setResponseCode(401)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"error\":\"invalid_grant\",\"error_description\":\"whatever\"}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID)
                    .orgId(UUID.fromString(ORG_ID))
                    .build()) {
                AuthError error = assertThrows(AuthError.class,
                        () -> client.ssoStart("55555555-5555-5555-5555-555555555555", "https://app.example.com/cb"));
                assertTrue(!(error instanceof io.axiam.sdk.errors.OAuthProtocolError));
            }
        }
    }

    @Test
    void ssoCompleteEstablishesSessionViaCookieJar() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken() + "; Path=/; HttpOnly")
                    .addHeader("Set-Cookie", "axiam_refresh=fake-refresh; Path=/; HttpOnly")
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"user_id\":\"11111111-1111-1111-1111-111111111111\","
                            + "\"session_id\":\"22222222-2222-2222-2222-222222222222\","
                            + "\"expires_in\":900,\"redirect_uri\":\"https://app.example.com/dashboard\"}"));
            server.start();

            try (AxiamClient client = AxiamClient.builder(server.url("/").toString(), TENANT_ID).build()) {
                SsoCompleteResult result = client.ssoComplete("state-abc", "code-abc");

                assertEquals("11111111-1111-1111-1111-111111111111", result.userId());
                assertEquals("22222222-2222-2222-2222-222222222222", result.sessionId());
                assertEquals("https://app.example.com/dashboard", result.redirectUri());
                // §4: the session must actually be captured (not just returned in
                // the body) — a subsequent authenticated call must carry the
                // axiam_access cookie's bearer token automatically.
                assertEquals("11111111-1111-1111-1111-111111111111", client.session().cachedAccessToken() != null
                        ? io.axiam.sdk.internal.SessionState.decodeUnverifiedClaims(client.session().cachedAccessToken()).sub()
                        : null);
            }

            RecordedRequest request = server.takeRequest();
            assertEquals("/api/v1/auth/federation/oidc/callback", request.getPath());
            String body = request.getBody().readUtf8();
            assertTrue(body.contains("\"state\":\"state-abc\""));
            assertTrue(body.contains("\"code\":\"code-abc\""));
        }
    }

    private static String fakeAccessToken() {
        String header = base64Url("{\"alg\":\"EdDSA\"}");
        String payload = base64Url("{\"sub\":\"11111111-1111-1111-1111-111111111111\","
                + "\"tenant_id\":\"" + TENANT_ID + "\","
                + "\"exp\":" + (System.currentTimeMillis() / 1000 + 900) + "}");
        return header + "." + payload + ".fake-signature";
    }

    private static String base64Url(String json) {
        return java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
