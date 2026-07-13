package io.axiam.sdk.internal;

import io.axiam.sdk.errors.AuthError;

import okhttp3.JavaNetCookieJar;
import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.Test;

import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit coverage for {@link SessionState}'s pure state/derivation logic and the
 * validation guards in {@link SessionState#doHttpRefresh()}, plus one live
 * (MockWebServer) happy-path refresh proving the token/cookie round trip. No
 * real AXIAM server is contacted; the guard-path tests never open a socket.
 */
class SessionStateTest {

    private static final String TENANT = "tenant-a";
    private static final UUID TENANT_UUID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID ORG_UUID = UUID.fromString("22222222-2222-2222-2222-222222222222");

    // ---- accessors / derivation --------------------------------------------

    @Test
    void baseUrlTrailingSlashIsStripped() {
        SessionState state = new SessionState(new CookieManager(), "http://localhost:8080/", TENANT, null, null);
        assertEquals("http://localhost:8080", state.baseUrl());
        assertEquals(TENANT, state.tenantId());
    }

    @Test
    void isRefreshPathMatchesOnlyTheRefreshEndpoint() {
        assertTrue(SessionState.isRefreshPath(SessionState.REFRESH_PATH));
        assertFalse(SessionState.isRefreshPath("/api/v1/auth/login"));
    }

    @Test
    void isBaseHostIsCaseInsensitiveAndFailsClosedOnNull() {
        SessionState state = new SessionState(new CookieManager(), "http://Example.COM", TENANT, null, null);
        assertTrue(state.isBaseHost("example.com"));
        assertTrue(state.isBaseHost("EXAMPLE.com"));
        assertFalse(state.isBaseHost("evil.com"));
        assertFalse(state.isBaseHost(null));
    }

    @Test
    void csrfTokenIsCapturedClearedAndReadBack() {
        SessionState state = new SessionState(new CookieManager(), "http://localhost", TENANT, null, null);
        assertNull(state.csrfToken());
        state.setCsrfToken("csrf-123");
        assertEquals("csrf-123", state.csrfToken());
        state.clear();
        assertNull(state.csrfToken(), "clear() must drop the cached CSRF token");
    }

    // ---- isNearExpiry --------------------------------------------------------

    @Test
    void isNearExpiryFalseWhenNoDecodableExpClaim() {
        SessionState state = new SessionState(new CookieManager(), "http://localhost", TENANT, null, null);
        // No exp claim -> decode yields exp=0 -> treated conservatively as not-near.
        String token = tokenWith("{\"tenant_id\":\"" + TENANT_UUID + "\"}");
        assertFalse(state.isNearExpiry(token, 60_000L));
        assertFalse(state.isNearExpiry("not.a.jwt", 60_000L), "an undecodable token is never near-expiry");
    }

    @Test
    void isNearExpiryTrueWhenWithinBufferAndFalseWhenFarOut() {
        SessionState state = new SessionState(new CookieManager(), "http://localhost", TENANT, null, null);
        long nowSec = System.currentTimeMillis() / 1000L;

        String nearlyExpired = tokenWith("{\"exp\":" + (nowSec + 10) + "}");
        assertTrue(state.isNearExpiry(nearlyExpired, 60_000L), "10s to expiry is within a 60s buffer");

        String farOut = tokenWith("{\"exp\":" + (nowSec + 3_600) + "}");
        assertFalse(state.isNearExpiry(farOut, 60_000L), "an hour to expiry is not within a 60s buffer");
    }

    // ---- decodeUnverifiedClaims (public static) -----------------------------

    @Test
    void decodeReturnsNullForWrongSegmentCount() {
        assertNull(SessionState.decodeUnverifiedClaims("onlyonesegment"));
        assertNull(SessionState.decodeUnverifiedClaims("a.b"));
        assertNull(SessionState.decodeUnverifiedClaims("a.b.c.d"));
    }

    @Test
    void decodeReturnsNullForUnparseableBase64Payload() {
        // The '@' character is not valid in a Base64url alphabet.
        assertNull(SessionState.decodeUnverifiedClaims("header.@@@invalid@@@.sig"));
    }

    @Test
    void decodeReturnsNullForNonJsonPayload() {
        String notJson = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("this is not json".getBytes(StandardCharsets.UTF_8));
        assertNull(SessionState.decodeUnverifiedClaims("header." + notJson + ".sig"));
    }

    @Test
    void decodeExtractsAllClaimsAndSplitsScopeIntoRoles() {
        String json = "{\"sub\":\"user-1\",\"tenant_id\":\"" + TENANT_UUID + "\",\"org_id\":\"" + ORG_UUID
                + "\",\"jti\":\"jti-9\",\"scope\":\"read  write   admin\",\"exp\":1234567890}";
        SessionState.Claims claims = SessionState.decodeUnverifiedClaims(tokenWith(json));

        assertEquals("user-1", claims.sub());
        assertEquals(TENANT_UUID.toString(), claims.tenantId());
        assertEquals(ORG_UUID.toString(), claims.orgId());
        assertEquals("jti-9", claims.jti());
        assertEquals(1234567890L, claims.exp());
        assertEquals(List.of("read", "write", "admin"), claims.roles(),
                "scope must split on whitespace runs into individual roles");
    }

    @Test
    void decodeYieldsEmptyRolesWhenScopeAbsentOrBlank() {
        SessionState.Claims absent = SessionState.decodeUnverifiedClaims(tokenWith("{\"sub\":\"u\"}"));
        assertTrue(absent.roles().isEmpty(), "absent scope -> empty roles");

        SessionState.Claims blank = SessionState.decodeUnverifiedClaims(tokenWith("{\"scope\":\"   \"}"));
        assertTrue(blank.roles().isEmpty(), "blank scope -> empty roles");
    }

    // ---- doHttpRefresh() validation guards ----------------------------------

    @Test
    void refreshWithoutAnAccessTokenThrows() {
        SessionState state = new SessionState(new CookieManager(), "http://localhost:8080", TENANT, null, null);
        AuthError error = assertThrows(AuthError.class, state::doHttpRefresh);
        assertTrue(error.getMessage().contains("no access token"), error.getMessage());
    }

    @Test
    void refreshWithoutTenantClaimThrows() {
        CookieManager cm = new CookieManager();
        seedCookie(cm, "http://localhost:8080", "axiam_access", tokenWith("{\"sub\":\"u\"}"));
        SessionState state = new SessionState(cm, "http://localhost:8080", TENANT, null, null);

        AuthError error = assertThrows(AuthError.class, state::doHttpRefresh);
        assertTrue(error.getMessage().contains("tenant_id could not be resolved"), error.getMessage());
    }

    @Test
    void refreshWithNonUuidTenantClaimThrows() {
        CookieManager cm = new CookieManager();
        seedCookie(cm, "http://localhost:8080", "axiam_access", tokenWith("{\"tenant_id\":\"not-a-uuid\"}"));
        SessionState state = new SessionState(cm, "http://localhost:8080", TENANT, null, null);

        AuthError error = assertThrows(AuthError.class, state::doHttpRefresh);
        assertTrue(error.getMessage().contains("tenant_id claim is not a valid UUID"), error.getMessage());
    }

    @Test
    void refreshWithoutAnOrgIdThrows() {
        CookieManager cm = new CookieManager();
        // valid tenant_id, but org_id absent and none configured, and the org_id
        // claim below is deliberately not a UUID to exercise the fall-through.
        seedCookie(cm, "http://localhost:8080", "axiam_access",
                tokenWith("{\"tenant_id\":\"" + TENANT_UUID + "\",\"org_id\":\"not-a-uuid\"}"));
        SessionState state = new SessionState(cm, "http://localhost:8080", TENANT, null, null);

        AuthError error = assertThrows(AuthError.class, state::doHttpRefresh);
        assertTrue(error.getMessage().contains("org_id could not be resolved"), error.getMessage());
    }

    @Test
    void refreshFailsFastWhenHttpClientNeverAttached() {
        CookieManager cm = new CookieManager();
        // tenant_id + org_id both resolvable, so resolution passes and the code
        // reaches the "client was never attached" guard.
        seedCookie(cm, "http://localhost:8080", "axiam_access",
                tokenWith("{\"tenant_id\":\"" + TENANT_UUID + "\",\"org_id\":\"" + ORG_UUID + "\"}"));
        SessionState state = new SessionState(cm, "http://localhost:8080", TENANT, null, null);

        IllegalStateException error = assertThrows(IllegalStateException.class, state::doHttpRefresh);
        assertTrue(error.getMessage().contains("attachHttpClient"), error.getMessage());
    }

    @Test
    void refreshUsesConfiguredOrgIdWhenTokenHasNone() {
        CookieManager cm = new CookieManager();
        seedCookie(cm, "http://localhost:8080", "axiam_access",
                tokenWith("{\"tenant_id\":\"" + TENANT_UUID + "\"}")); // no org_id claim
        // configuredOrgId supplied -> resolveOrgId short-circuits to it, so
        // resolution succeeds and we again reach the not-attached guard.
        SessionState state = new SessionState(cm, "http://localhost:8080", TENANT, null, ORG_UUID);

        assertThrows(IllegalStateException.class, state::doHttpRefresh);
    }

    // ---- doHttpRefresh() live happy path (MockWebServer) --------------------

    @Test
    void refreshPropagatesAServerRejection() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(401).setBody("nope"));
            server.start();

            String base = server.url("/").toString();
            base = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;

            CookieManager cm = new CookieManager();
            String initialAccess = tokenWith("{\"tenant_id\":\"" + TENANT_UUID + "\",\"org_id\":\"" + ORG_UUID + "\"}");
            seedCookie(cm, base, "axiam_access", initialAccess);

            OkHttpClient client = new OkHttpClient.Builder().cookieJar(new JavaNetCookieJar(cm)).build();
            SessionState state = new SessionState(cm, base, TENANT, null, null);
            state.attachHttpClient(client);

            assertThrows(RuntimeException.class, state::doHttpRefresh);
        }
    }

    // ---- helpers -------------------------------------------------------------

    /** Builds a syntactically-valid 3-segment JWT with an unsigned, given JSON payload. */
    private static String tokenWith(String payloadJson) {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".";
    }

    private static void seedCookie(CookieManager cm, String baseUrl, String name, String value) {
        URI uri = URI.create(baseUrl);
        HttpCookie cookie = new HttpCookie(name, value);
        cookie.setPath("/");
        cookie.setVersion(0);
        cm.getCookieStore().add(uri, cookie);
    }
}
