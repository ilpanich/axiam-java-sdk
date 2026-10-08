package io.axiam.sdk.internal;

import okhttp3.Authenticator;
import okhttp3.CookieJar;
import okhttp3.OkHttpClient;

/**
 * A transport that carries none of the SDK's session.
 *
 * <p>Some calls present a bearer of their own that is <em>not</em> the SDK's
 * session &mdash; an RFC 7592 registration access token (CONTRACT.md
 * &sect;28.12.2 rule 3), an SSF receiver's client-credentials token (&sect;32.7)
 * &mdash; and must go out with nothing else: no session cookie, no SDK access
 * token, no CSRF header, no &sect;9 refresh on a {@code 401}, and no redirect
 * that could carry the bearer to another host.
 *
 * <p>Derived from the client's own {@link OkHttpClient} via
 * {@link OkHttpClient#newBuilder()}, so the TLS policy (&sect;6: system trust
 * store, optional custom CA, the &sect;6.1 identity) and the connection pool
 * are the same; only the session-carrying parts are dropped. OkHttp's own
 * silent retry on a connection failure is off too: the writes this serves must
 * be sent at most once.
 *
 * <p>Internal plumbing; public only because the callers live in other packages.
 */
public final class Sessionless {

    private Sessionless() {
    }

    /**
     * Derives the session-free transport.
     *
     * @param client the client's decorated transport
     * @return a transport with the same TLS configuration and none of the session
     */
    public static OkHttpClient of(OkHttpClient client) {
        OkHttpClient.Builder builder = client.newBuilder();
        builder.interceptors().clear();
        builder.networkInterceptors().clear();
        return builder
                .cookieJar(CookieJar.NO_COOKIES)
                .authenticator(Authenticator.NONE)
                .proxyAuthenticator(Authenticator.NONE)
                .followRedirects(false)
                .followSslRedirects(false)
                .retryOnConnectionFailure(false)
                .build();
    }
}
