package io.axiam.sdk.rest;

import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.SessionState;

import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.Set;

/**
 * Proactive (near-expiry) refresh + header injection (CONTRACT.md
 * &sect;3/&sect;5/&sect;9, D-08, RESEARCH.md Pattern 3). Registered as an
 * APPLICATION interceptor ({@code OkHttpClient.Builder.addInterceptor},
 * NOT {@code addNetworkInterceptor}) — application interceptors see the
 * logical request once, the correct layer for business-logic header
 * injection and proactive refresh.
 *
 * <p>Every same-host request gets {@code X-Tenant-Id} (&sect;5); a bearer
 * token is added when one is cached; the stored CSRF token is echoed on
 * POST/PUT/PATCH/DELETE (&sect;3); a fresh {@code X-CSRF-Token} response
 * header is captured for the next request. A discovery-document-derived
 * {@code /oauth2/*} request also gets {@code X-Tenant-Id} even when its host
 * differs from {@code base_url} (CONTRACT.md &sect;12.1 note 2 calls the
 * header unconditional there) — but never the bearer/CSRF headers, which
 * stay strictly same-host per &sect;3A (follow-up F-15, T9 conformance
 * review).
 *
 * <p>The proactive-refresh check performs a non-blocking cached-token read
 * ({@link SessionState#cachedAccessToken()}) — it never acquires
 * {@link RefreshGuard}'s lock synchronously on this hot path; refreshing
 * itself funnels through {@link RefreshGuard#refreshIfNeeded}, the SAME
 * guard {@link AuthAuthenticator}'s reactive 401 path uses (D-08).
 *
 * <p>The refresh call's own request path is special-cased (skipped) here:
 * {@link SessionState#doHttpRefresh()} sends its POST through this same
 * OkHttpClient, so without this guard a near-expiry access token observed
 * mid-refresh would recursively re-enter {@link RefreshGuard#refreshIfNeeded}
 * on the same thread and deadlock on its own in-flight future.
 */
public final class AuthInterceptor implements Interceptor {

    /** Proactive-refresh buffer — refresh once the access token is within this
     * many milliseconds of its {@code exp} claim. */
    private static final long NEAR_EXPIRY_BUFFER_MILLIS = 30_000;

    private static final Set<String> STATE_CHANGING_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");

    private final RefreshGuard guard;
    private final SessionState session;

    /**
     * Creates an interceptor bound to the given shared refresh guard and session.
     *
     * @param guard   the single-flight refresh guard shared with
     *                {@link AuthAuthenticator} and the gRPC transport (D-08) —
     *                never a second instance
     * @param session the client's session state (tenant id, cookie-jar-backed
     *                token, CSRF token)
     */
    public AuthInterceptor(RefreshGuard guard, SessionState session) {
        this.guard = guard;
        this.session = session;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request original = chain.request();
        String encodedPath = original.url().encodedPath();
        // §12.3 rule 3: an /oauth2/* call must never trigger a proactive
        // refresh either — grouped with the refresh-path exclusion above it,
        // for the same "never recursively/incidentally refresh" reason.
        boolean isRefreshCall = SessionState.isRefreshPath(encodedPath)
                || SessionState.isOauth2SkipRefreshPath(encodedPath);

        // Host-isolation (3A): only same-origin requests receive the bearer
        // token and CSRF token. A request built against an absolute
        // third-party URL (or a redirect resolved off-origin) is left
        // undecorated for those two so those secrets never leave our own host.
        boolean sameHost = session.isBaseHost(original.url().host());

        // F-15 (T9 conformance review): X-Tenant-Id is unconditional on
        // /oauth2/* (CONTRACT.md §12.1 note 2), including a discovery-
        // document-derived endpoint hosted off the configured base_url (e.g.
        // a proxy-fronted deployment) -- it is NOT a secret the way the
        // bearer/CSRF headers are, so widening its condition here does not
        // weaken 3A's host-isolation guarantee for those two.
        boolean tenantHeaderEligible = sameHost || SessionState.isOauth2Path(encodedPath);

        // Non-blocking read — never session/guard.lock() synchronously here.
        String access = session.cachedAccessToken();
        if (sameHost && !isRefreshCall && access != null && session.isNearExpiry(access, NEAR_EXPIRY_BUFFER_MILLIS)) {
            access = guard.refreshIfNeeded(access, session::doHttpRefresh).access();
        }

        Request.Builder builder = original.newBuilder();
        if (tenantHeaderEligible) {
            builder.header("X-Tenant-Id", session.tenantId());
        }
        if (sameHost) {
            if (access != null) {
                builder.header("Authorization", "Bearer " + access);
            }
            String csrf = session.csrfToken();
            if (csrf != null && STATE_CHANGING_METHODS.contains(original.method())) {
                builder.header("X-CSRF-Token", csrf);
            }
        }

        Response response = chain.proceed(builder.build());

        String newCsrf = response.header("X-CSRF-Token");
        if (newCsrf != null) {
            session.setCsrfToken(newCsrf);
        }
        return response;
    }
}
