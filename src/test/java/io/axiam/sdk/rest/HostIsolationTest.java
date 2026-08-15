package io.axiam.sdk.rest;

import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.SessionState;

import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.Test;

import java.net.CookieManager;
import java.net.CookiePolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Host-isolation guard (3A): {@link SessionState#isBaseHost} recognises only
 * the session's own origin host, so {@link AuthInterceptor} attaches the
 * bearer token and CSRF token exclusively to same-origin requests — never to
 * an absolute third-party URL or a followed cross-host redirect.
 *
 * <p>Follow-up F-15 (cross-SDK CONTRACT.md &sect;12 conformance review, T9):
 * {@code X-Tenant-Id} is the one exception to strict same-host gating — a
 * discovery-document-derived {@code /oauth2/*} endpoint can legitimately be
 * hosted off {@code base_url} (e.g. a proxy-fronted deployment), and
 * CONTRACT.md &sect;12.1 note 2 calls the header unconditional there. The
 * live round trips below exercise the real {@link AuthInterceptor} against a
 * foreign host to prove that widening: {@code X-Tenant-Id} still arrives on
 * a foreign-host {@code /oauth2/token} request, but the bearer token does
 * not, and neither header arrives on a foreign-host non-{@code /oauth2/*}
 * request. No sibling SDK carried this test before this follow-up.
 */
class HostIsolationTest {

    private static SessionState session() {
        CookieManager cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        return new SessionState(cookieManager, "https://api.axiam.test", "acme-tenant", null, null);
    }

    @Test
    void recognisesOwnOriginHostCaseInsensitively() {
        SessionState session = session();
        assertTrue(session.isBaseHost("api.axiam.test"));
        assertTrue(session.isBaseHost("API.AXIAM.TEST"));
    }

    @Test
    void rejectsForeignAndNullHosts() {
        SessionState session = session();
        assertFalse(session.isBaseHost("evil.example"));
        assertFalse(session.isBaseHost("api.axiam.test.evil.example"));
        assertFalse(session.isBaseHost(null));
    }

    @Test
    void xTenantIdIsEmittedOnAForeignHostOauth2TokenRequestButTheBearerTokenIsNot() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200));
            server.start();

            // The session's configured base_url is a different host than the
            // server this test actually dials -- simulating a discovery
            // document whose token_endpoint lives on a different origin than
            // base_url (F-15's exact scenario).
            SessionState session = session();
            HttpUrl foreignTokenEndpoint = server.url("/oauth2/token");
            assertFalse(session.isBaseHost(foreignTokenEndpoint.host()),
                    "test setup sanity: the dialed host must differ from the session's configured base host");

            OkHttpClient client = new OkHttpClient.Builder()
                    .addInterceptor(new AuthInterceptor(new RefreshGuard(), session))
                    .build();

            Request request = new Request.Builder()
                    .url(foreignTokenEndpoint)
                    .post(RequestBody.create(
                            "grant_type=client_credentials",
                            MediaType.get("application/x-www-form-urlencoded")))
                    .build();

            try (Response response = client.newCall(request).execute()) {
                assertTrue(response.isSuccessful());
            }

            RecordedRequest recorded = server.takeRequest();
            assertEquals("acme-tenant", recorded.getHeader("X-Tenant-Id"),
                    "CONTRACT.md §12.1 note 2: X-Tenant-Id must be unconditional on a discovery-derived "
                            + "/oauth2/* request, even off base_url");
            assertNull(recorded.getHeader("Authorization"),
                    "the bearer token must stay strictly same-host-gated (§3A) even though X-Tenant-Id "
                            + "is now unconditional on /oauth2/*");
        }
    }

    @Test
    void neitherHeaderIsEmittedOnAForeignHostNonOauth2Request() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(200));
            server.start();

            SessionState session = session();
            HttpUrl foreignUrl = server.url("/api/v1/something");
            assertFalse(session.isBaseHost(foreignUrl.host()));

            OkHttpClient client = new OkHttpClient.Builder()
                    .addInterceptor(new AuthInterceptor(new RefreshGuard(), session))
                    .build();

            try (Response response = client.newCall(new Request.Builder().url(foreignUrl).build()).execute()) {
                assertTrue(response.isSuccessful());
            }

            RecordedRequest recorded = server.takeRequest();
            assertNull(recorded.getHeader("X-Tenant-Id"),
                    "a foreign-host request outside /oauth2/* must not receive the tenant header");
            assertNull(recorded.getHeader("Authorization"));
        }
    }
}
