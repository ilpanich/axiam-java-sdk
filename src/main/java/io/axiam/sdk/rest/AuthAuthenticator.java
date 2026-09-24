package io.axiam.sdk.rest;

import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.SessionState;
import io.axiam.sdk.internal.TokenPair;

import okhttp3.Authenticator;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;

import org.jspecify.annotations.Nullable;

/**
 * Reactive 401 fallback (CONTRACT.md &sect;9, D-08, RESEARCH.md Pattern 3).
 * Funnels into the SAME {@link RefreshGuard} instance {@link AuthInterceptor}
 * uses for proactive refresh — never a second guard.
 *
 * <p><strong>No retry loop (&sect;9.3):</strong> once two prior responses are
 * already recorded on the response chain (i.e. this would be a third
 * consecutive 401 for the same logical call), {@code null} is returned so
 * OkHttp gives up rather than retrying indefinitely. The refresh call's own
 * 401 is also never retried here — that response IS the terminal
 * {@code AuthError} the caller (via {@link SessionState#doHttpRefresh()})
 * surfaces.
 */
public final class AuthAuthenticator implements Authenticator {

    private final RefreshGuard guard;
    private final SessionState session;

    /**
     * Creates an authenticator bound to the given shared refresh guard and session.
     *
     * @param guard   the single-flight refresh guard shared with {@link AuthInterceptor}'s
     *                proactive-refresh path (D-08) — never a second instance
     * @param session the client's session state (tenant id, cookie-jar-backed token)
     */
    public AuthAuthenticator(RefreshGuard guard, SessionState session) {
        this.guard = guard;
        this.session = session;
    }

    @Override
    public @Nullable Request authenticate(@Nullable Route route, Response response) throws java.io.IOException {
        String encodedPath = response.request().url().encodedPath();
        // CONTRACT.md §12.3 rule 3: a 401 from /oauth2/token, /oauth2/introspect,
        // or /oauth2/revoke is a client-credential failure, never a session
        // expiry — it must never enter this guard. The oidc engine's own
        // OAuth2ErrorResponse mapping (ErrorMapper.fromOAuth2Response) sees the
        // original, unretried 401 response.
        //
        // §24.1 (contract 1.45): a 401 from webauthn/setup/register/{start,
        // finish} means the SETUP TOKEN is invalid/expired/wrong-purpose —
        // never a session expiry, since this pair never carried a session in
        // the first place (AuthInterceptor withholds it on the way out). This
        // guard must not "fix" that 401 by attaching the caller's own session
        // credential on retry: that would attach exactly the credential §24.1
        // says an SDK MUST NOT attach to these two, the moment the server
        // rejects the setup token — the one scenario the request-side
        // exclusion alone would miss.
        // CONTRACT.md §6.1 rule 6 (contract 1.51): the device login's OWN 401 is
        // the terminal answer this operation defines — never a session expiry to
        // refresh past. Excluded here rather than only via
        // hasAdoptedAccessToken() below, because the login call ITSELF runs
        // before any token is adopted.
        if (SessionState.isRefreshPath(encodedPath) || SessionState.isOauth2SkipRefreshPath(encodedPath)
                || SessionState.isWebauthnSetupRegisterPath(encodedPath)
                || SessionState.isDeviceAuthPath(encodedPath)
                || responseCount(response) >= 2) {
            return null;
        }

        // CONTRACT.md §6.1 rule 6 (contract 1.51): a device token has no
        // refresh token. A later 401 on it is surfaced as AuthError verbatim,
        // never sent through this guard — there is nothing to spend, and the
        // recovery is calling authenticateDevice() again, not a retry here.
        if (session.hasAdoptedAccessToken()) {
            return null;
        }

        String staleAccess = session.cachedAccessToken();
        if (staleAccess == null) {
            return null; // never authenticated — nothing to refresh
        }

        TokenPair refreshed;
        try {
            refreshed = guard.refreshIfNeeded(staleAccess, session::doHttpRefresh);
        } catch (RuntimeException e) {
            // Refresh itself failed — surface the original 401, no retry (§9.3).
            return null;
        }

        return response.request().newBuilder()
                .header("Authorization", "Bearer " + refreshed.access())
                .build();
    }

    private static int responseCount(Response response) {
        int count = 1;
        Response prior = response.priorResponse();
        while (prior != null) {
            count++;
            prior = prior.priorResponse();
        }
        return count;
    }
}
