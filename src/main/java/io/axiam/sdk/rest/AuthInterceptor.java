package io.axiam.sdk.rest;

import io.axiam.sdk.internal.ActingTenantTag;
import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.SessionState;

import okhttp3.Cookie;
import okhttp3.CookieJar;
import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.List;
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

        // §24.1 (contract 1.45): webauthn/setup/register/{start,finish} take
        // no session at all — the setup token in the body is the ONLY
        // credential they accept. An already-signed-in client's bearer token,
        // CSRF token and cookies must never ride along, so this call is
        // excluded from every credential-attaching branch below exactly as
        // isRefreshCall is excluded from the proactive-refresh branch.
        boolean isSessionlessSetupCall = SessionState.isWebauthnSetupRegisterPath(encodedPath);

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

        // CONTRACT.md §6.1 rule 6 (contract 1.51): a device token has no refresh
        // token at all, so the proactive near-expiry check below must never fire
        // for one — there is nothing for the §9 guard to spend, and attempting a
        // refresh would be a wire call this rule forbids. A later 401 on this
        // token is AuthAuthenticator's to leave alone, not this interceptor's.
        boolean hasAdoptedDeviceToken = session.hasAdoptedAccessToken();

        // Non-blocking read — never session/guard.lock() synchronously here.
        String access = session.cachedAccessToken();
        if (sameHost && !isRefreshCall && !isSessionlessSetupCall && !hasAdoptedDeviceToken
                && access != null && session.isNearExpiry(access, NEAR_EXPIRY_BUFFER_MILLIS)) {
            access = guard.refreshIfNeeded(access, session::doHttpRefresh).access();
        }

        Request.Builder builder = original.newBuilder();
        if (tenantHeaderEligible) {
            builder.header("X-Tenant-Id", session.tenantId());
        }
        // CONTRACT.md §5.2 rule 1 (contract 1.51): X-Axiam-Tenant, sent ONLY when the
        // specific call site that built this request tagged it — never unconditionally,
        // and never derived from session.tenantId(), which is the constructor tenant and
        // a different thing entirely (the §5 callout this section's own javadoc already
        // makes about X-Tenant-Id). REST-only: no gRPC twin exists anywhere in this SDK.
        ActingTenantTag actingTenant = original.tag(ActingTenantTag.class);
        if (actingTenant != null && sameHost) {
            builder.header("X-Axiam-Tenant", actingTenant.tenantId().toString());
        }
        if (sameHost) {
            if (access != null && !isSessionlessSetupCall) {
                builder.header("Authorization", "Bearer " + access);
            }
            String csrf = session.csrfToken();
            if (csrf != null && !isSessionlessSetupCall && STATE_CHANGING_METHODS.contains(original.method())) {
                builder.header("X-CSRF-Token", csrf);
            }
        }
        // okhttp3.internal.http.BridgeInterceptor (5.x) loads the outgoing
        // Cookie header from chain.getCookieJar() UNCONDITIONALLY — it no
        // longer skips a request that already carries one, so overriding the
        // header here would just be clobbered back. Chain#withCookieJar is
        // the supported way to swap the jar for the rest of THIS call only:
        // loadForRequest() returning empty is what keeps an already-signed-in
        // client's session cookie off the wire, while saveFromResponse()
        // still delegates to the real jar so a successful
        // setup/register/finish's Set-Cookie response is captured exactly as
        // it would be through the normal jar (§24.8's adoption test).
        // CONTRACT.md §6.1 rule 6: the server reads axiam_access BEFORE
        // Authorization, so a cookie left over from an earlier session would
        // otherwise silently outrank the device token this request means to
        // authenticate as. Withheld on the login call itself (isDeviceAuthPath
        // — this authenticates by mTLS alone and a stale cookie must not ride
        // along either) AND on every later same-host request for as long as a
        // device token is adopted, not only the call that adopted it.
        boolean isDeviceAuthCall = SessionState.isDeviceAuthPath(encodedPath);
        Chain effectiveChain = (isSessionlessSetupCall || isDeviceAuthCall
                || (sameHost && hasAdoptedDeviceToken))
                ? chain.withCookieJar(new LoadSuppressedCookieJar(chain.getCookieJar()))
                : chain;

        Response response = effectiveChain.proceed(builder.build());

        String newCsrf = response.header("X-CSRF-Token");
        if (newCsrf != null) {
            session.setCsrfToken(newCsrf);
        }
        return response;
    }

    /**
     * A {@link CookieJar} that never loads a cookie for an outgoing request
     * but still saves an incoming response's {@code Set-Cookie} headers into
     * the real jar it wraps.
     *
     * <p>Used only for &sect;24.1's session-less {@code setup/register/*}
     * pair (contract 1.45), via {@link Chain#withCookieJar}, and only for the
     * duration of that one call: the client's shared jar (and every other
     * request) is untouched.
     */
    private static final class LoadSuppressedCookieJar implements CookieJar {

        private final CookieJar delegate;

        LoadSuppressedCookieJar(CookieJar delegate) {
            this.delegate = delegate;
        }

        @Override
        public void saveFromResponse(HttpUrl url, List<Cookie> cookies) {
            delegate.saveFromResponse(url, cookies);
        }

        @Override
        public List<Cookie> loadForRequest(HttpUrl url) {
            return List.of();
        }
    }
}
