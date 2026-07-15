package io.axiam.sdk.rest;

import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.SessionState;

import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;

import org.junit.jupiter.api.Test;

import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Unit coverage for {@link AuthAuthenticator}'s reactive-401 fallback
 * (CONTRACT.md §9). Exercises the give-up branches (refresh path, retry
 * ceiling, no cached token) and the "refresh itself failed" branch — all
 * without a live server, since a non-JWT stale token makes
 * {@link SessionState#doHttpRefresh()} throw before any network call.
 */
class AuthAuthenticatorTest {

    private static final String BASE = "http://localhost:8080";

    private static SessionState session(CookieManager cm) {
        return new SessionState(cm, BASE, "tenant-a", null, null);
    }

    /** A 401 Response for {@code path} with {@code priors} earlier 401s on the chain. */
    private static Response response(String path, int priors) {
        Request req = new Request.Builder().url(BASE + path).build();
        Response resp = new Response.Builder()
                .request(req)
                .protocol(Protocol.HTTP_1_1)
                .code(401)
                .message("Unauthorized")
                .build();
        for (int i = 0; i < priors; i++) {
            resp = resp.newBuilder().priorResponse(response(path, 0)).build();
        }
        return resp;
    }

    @Test
    void refreshPathResponseIsNotRetried() throws Exception {
        AuthAuthenticator auth = new AuthAuthenticator(new RefreshGuard(), session(new CookieManager()));
        assertNull(auth.authenticate(null, response("/api/v1/auth/refresh", 0)),
                "a 401 on the refresh path must not itself be retried (§9.3)");
    }

    @Test
    void twoPriorResponsesStopRetrying() throws Exception {
        AuthAuthenticator auth = new AuthAuthenticator(new RefreshGuard(), session(new CookieManager()));
        // this response + one prior == 2 → give up.
        assertNull(auth.authenticate(null, response("/api/v1/users", 1)),
                "OkHttp must give up once two responses are already on the chain");
    }

    @Test
    void noCachedTokenIsNotRetried() throws Exception {
        AuthAuthenticator auth = new AuthAuthenticator(new RefreshGuard(), session(new CookieManager()));
        assertNull(auth.authenticate(null, response("/api/v1/users", 0)),
                "with no cached access token there is nothing to refresh");
    }

    @Test
    void failedRefreshSurfacesOriginal401() throws Exception {
        CookieManager cm = new CookieManager();
        HttpCookie cookie = new HttpCookie("axiam_access", "not-a-valid-jwt");
        cookie.setPath("/");
        cm.getCookieStore().add(URI.create(BASE), cookie);

        AuthAuthenticator auth = new AuthAuthenticator(new RefreshGuard(), session(cm));
        // doHttpRefresh throws (the stale token is not a decodable JWT) → the
        // RuntimeException is swallowed and the original 401 is surfaced.
        assertNull(auth.authenticate(null, response("/api/v1/users", 0)),
                "a failed refresh must surface the original 401 without retrying");
    }
}
