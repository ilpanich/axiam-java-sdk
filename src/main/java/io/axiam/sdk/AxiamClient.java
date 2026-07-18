package io.axiam.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.ErrorMapper;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.internal.JwksVerifier;
import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.Retry;
import io.axiam.sdk.internal.SessionState;

import okhttp3.java.net.cookiejar.JavaNetCookieJar;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

import org.jspecify.annotations.Nullable;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * The AXIAM Java SDK's public REST entry point (CONTRACT.md &sect;1&ndash;&sect;6,
 * &sect;9). {@link #builder(String, String)} is the ONLY construction path —
 * {@code tenantId} is a required, positional argument (SC#1); there is no
 * no-arg builder factory.
 *
 * <p>Owns exactly ONE {@link RefreshGuard}, ONE {@link SessionState}, and ONE
 * {@link JwksVerifier} per client — shared by the REST interceptor/
 * authenticator here and, by future plans, the gRPC transport (D-07/D-08:
 * "one guard"). Package-internal accessors ({@link #refreshGuard()},
 * {@link #tenantId()}, {@link #baseUrl()}, {@link #okHttpClient()},
 * {@link #customCa()}, {@link #session()}) expose this seam without
 * requiring the gRPC plan (20-08) or the examples (20-09) to edit this
 * class.
 */
public final class AxiamClient implements AutoCloseable {

    private static final String LOGIN_PATH = "/api/v1/auth/login";
    private static final String MFA_VERIFY_PATH = "/api/v1/auth/mfa/verify";
    private static final String LOGOUT_PATH = "/api/v1/auth/logout";
    private static final String CHECK_PATH = "/api/v1/authz/check";
    private static final String BATCH_CHECK_PATH = "/api/v1/authz/check/batch";

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String baseUrl;
    private final String tenantId;
    private final byte @Nullable [] customCaPem;
    private final OkHttpClient httpClient;
    private final RefreshGuard refreshGuard;
    private final JwksVerifier jwksVerifier;
    private final SessionState session;

    /**
     * The ONLY construction path (SC#1) — {@code tenantId} is required and
     * positional; there is no no-arg builder factory reachable from this
     * class. A blank {@code tenantId} is a runtime guard backing the
     * compile-time guarantee (this factory is the sole way to obtain a
     * {@link Builder}, whose constructor is private).
     *
     * @param baseUrl  the AXIAM server's base URL (e.g. {@code "https://axiam.example.com"})
     * @param tenantId the tenant identifier (CONTRACT.md &sect;5); required, never {@code null}/blank
     * @return a new {@link Builder} for further configuration
     * @throws AuthError if {@code tenantId} is {@code null} or blank
     *                    (CONTRACT.md &sect;5 — AXIAM is multi-tenant, there
     *                    is no default tenant)
     */
    public static Builder builder(String baseUrl, @Nullable String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new AuthError("tenantId is required — AXIAM is multi-tenant "
                    + "and there is no default tenant (CONTRACT.md §5)");
        }
        return new Builder(baseUrl, tenantId);
    }

    /** Fluent builder for {@link AxiamClient} — the ONLY construction path (SC#1);
     * obtain an instance via {@link AxiamClient#builder(String, String)}, never directly. */
    public static final class Builder {
        private final String baseUrl;
        private final String tenantId;
        private @Nullable String orgSlug;
        private @Nullable UUID orgId;
        private byte @Nullable [] customCaPem;
        private byte @Nullable [] clientCertPem;
        private byte @Nullable [] clientKeyPem;
        private @Nullable OkHttpClient overrideHttpClient;
        private Duration connectTimeout = Duration.ofSeconds(10);
        private Duration readTimeout = Duration.ofSeconds(30);
        private Duration writeTimeout = Duration.ofSeconds(30);

        private Builder(String baseUrl, String tenantId) {
            this.baseUrl = baseUrl;
            this.tenantId = tenantId;
        }

        /** Mutually exclusive with {@link #orgId(UUID)} — last call wins. The
         * real login/refresh endpoints need an org identifier beyond §5's
         * documented tenant-only minimum (Pitfall 2).
         *
         * @param slug the organization slug to resolve login/refresh calls against
         * @return this builder, for chaining
         */
        public Builder orgSlug(String slug) {
            this.orgSlug = slug;
            this.orgId = null;
            return this;
        }

        /** Mutually exclusive with {@link #orgSlug(String)} — last call wins.
         *
         * @param id the organization UUID to resolve login/refresh calls against
         * @return this builder, for chaining
         */
        public Builder orgId(UUID id) {
            this.orgId = id;
            this.orgSlug = null;
            return this;
        }

        /** The ONLY TLS escape hatch (§6) — adds a PEM-encoded CA certificate to
         * the verification chain, alongside (never instead of) the system trust
         * store. There is no API surface anywhere in this SDK that disables or
         * weakens certificate verification.
         *
         * @param pem a PEM-encoded X.509 CA certificate to trust in addition to
         *            the system trust store
         * @return this builder, for chaining
         */
        public Builder customCa(byte[] pem) {
            this.customCaPem = pem;
            return this;
        }

        /**
         * Configures the client-side X.509 identity presented for mutual TLS
         * (mTLS) authentication (CONTRACT.md &sect;6.1). AXIAM binds this
         * certificate to a service account / IoT device
         * ({@code POST /api/v1/auth/device}); presenting it lets the same
         * {@link AxiamClient} authenticate by client certificate on both its
         * REST and gRPC transports.
         *
         * <p>Both arguments are PEM-encoded: {@code certPem} is the client
         * certificate chain (leaf first; additional intermediates may be
         * concatenated), {@code keyPem} is the matching PKCS#8 private key
         * ({@code -----BEGIN PRIVATE KEY-----}; RSA, EC, or Ed25519). A
         * malformed value surfaces as a clear error at {@link #build()} time.
         *
         * <p><strong>mTLS is opt-in and never relaxes server verification</strong>
         * (CONTRACT.md &sect;6.1 rule 2): the SDK's strict system-trust-store +
         * optional {@link #customCa(byte[])} chain is applied unchanged. Both a
         * certificate and a private key are required together — supplying only
         * one throws {@link IllegalArgumentException} at {@link #build()}.
         *
         * <p>The private key is secret material (CONTRACT.md &sect;7): it is
         * consumed into an in-memory key store at build time, is never retained
         * in a way that a getter, {@code toString()}, or log can expose, and has
         * no public accessor.
         *
         * @param certPem the PEM-encoded client certificate chain (leaf certificate
         *                first); must not be {@code null}
         * @param keyPem  the PEM-encoded PKCS#8 private key matching {@code certPem}
         *                ({@code -----BEGIN PRIVATE KEY-----}); must not be {@code null}
         * @return this builder, for chaining
         */
        public Builder clientCertificate(byte[] certPem, byte[] keyPem) {
            this.clientCertPem = certPem;
            this.clientKeyPem = keyPem;
            return this;
        }

        /** Supplies a base {@code OkHttpClient} whose non-TLS/jar configuration
         * (e.g. connection pool, timeouts, custom interceptors) is adopted. The
         * SDK ALWAYS re-applies its own cookie jar and strict TLS config over
         * this via {@code newBuilder()} afterward (D-27, SC#4) — an override
         * can never silently drop the jar or weaken TLS verification.
         *
         * @param client the base {@code OkHttpClient} to adopt non-TLS/jar
         *               configuration from
         * @return this builder, for chaining
         */
        public Builder httpClient(OkHttpClient client) {
            this.overrideHttpClient = client;
            return this;
        }

        /** Sets the connect timeout (default 10s).
         *
         * @param d the connect timeout
         * @return this builder, for chaining
         */
        public Builder connectTimeout(Duration d) {
            this.connectTimeout = d;
            return this;
        }

        /** Sets the read timeout (default 30s).
         *
         * @param d the read timeout
         * @return this builder, for chaining
         */
        public Builder readTimeout(Duration d) {
            this.readTimeout = d;
            return this;
        }

        /** Sets the write timeout (default 30s).
         *
         * @param d the write timeout
         * @return this builder, for chaining
         */
        public Builder writeTimeout(Duration d) {
            this.writeTimeout = d;
            return this;
        }

        /** Builds the configured {@link AxiamClient}.
         *
         * @return a new, ready-to-use {@link AxiamClient}
         * @throws IllegalArgumentException if exactly one of the client
         *         certificate / private key was supplied via
         *         {@link #clientCertificate(byte[], byte[])} — mTLS requires
         *         both together (CONTRACT.md &sect;6.1)
         */
        public AxiamClient build() {
            boolean hasCert = clientCertPem != null;
            boolean hasKey = clientKeyPem != null;
            if (hasCert != hasKey) {
                throw new IllegalArgumentException(
                        "clientCertificate(...) requires BOTH a certificate and a private key — "
                                + (hasCert ? "the private key was null" : "the certificate was null")
                                + " (CONTRACT.md §6.1)");
            }
            return new AxiamClient(this);
        }
    }

    private AxiamClient(Builder b) {
        this.baseUrl = stripTrailingSlash(b.baseUrl);
        this.tenantId = b.tenantId;
        this.customCaPem = b.customCaPem;

        CookieManager cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        this.refreshGuard = new RefreshGuard();
        this.jwksVerifier = new JwksVerifier(this.baseUrl);
        this.session = new SessionState(cookieManager, this.baseUrl, this.tenantId, b.orgSlug, b.orgId);

        X509TrustManager trustManager = buildTrustManager(b.customCaPem);
        KeyManager[] keyManagers = (b.clientCertPem != null && b.clientKeyPem != null)
                ? buildKeyManagers(b.clientCertPem, b.clientKeyPem)
                : null;
        SSLContext sslContext = buildStrictSslContext(trustManager, keyManagers);

        OkHttpClient.Builder clientBuilder = b.overrideHttpClient != null
                ? b.overrideHttpClient.newBuilder()
                : new OkHttpClient.Builder();

        // D-27/SC#4: ALWAYS re-apply the SDK's own cookie jar + strict TLS
        // (system trust store + optional customCa, strict hostname
        // verification), regardless of what an overridden client had
        // configured — an override can never silently drop the jar or
        // weaken TLS.
        // Hostname verification is left at OkHttp's own default (the strict
        // okhttp3.internal.tls.OkHostnameVerifier, which performs full RFC 2818
        // SAN/CN matching). We deliberately do NOT override it with
        // HttpsURLConnection.getDefaultHostnameVerifier(): that JDK default is an
        // always-reject verifier (it returns false for every host, because
        // HttpsURLConnection does its own endpoint identification internally), so
        // wiring it into OkHttp — which relies solely on the configured verifier —
        // would reject EVERY HTTPS host, including a correctly-presented server
        // certificate. Not overriding keeps verification strict and correct.
        clientBuilder
                .cookieJar(new JavaNetCookieJar(cookieManager))
                .sslSocketFactory(sslContext.getSocketFactory(), trustManager)
                .connectTimeout(b.connectTimeout)
                .readTimeout(b.readTimeout)
                .writeTimeout(b.writeTimeout)
                .addInterceptor(new io.axiam.sdk.rest.AuthInterceptor(refreshGuard, session))
                .authenticator(new io.axiam.sdk.rest.AuthAuthenticator(refreshGuard, session));

        this.httpClient = clientBuilder.build();
        this.session.attachHttpClient(this.httpClient);
    }

    // ------------------------------------------------------------------
    // AutoCloseable (D-09)
    // ------------------------------------------------------------------

    @Override
    public void close() {
        httpClient.dispatcher().executorService().shutdown();
        httpClient.connectionPool().evictAll();
        okhttp3.Cache cache = httpClient.cache();
        if (cache != null) {
            try {
                cache.close();
            } catch (IOException ignored) {
                // best-effort — nothing actionable on a failed cache close.
            }
        }
    }

    // ------------------------------------------------------------------
    // SDK-internal accessors (gRPC seam, 20-08) — not part of the public API
    // contract, but Java has no cross-package "friend" visibility; the
    // `internal`-style comment here is the boundary marker, not enforced by
    // the language (mirrors the `internal` package's own convention).
    // ------------------------------------------------------------------

    /** The single {@link RefreshGuard} this client's REST transport uses; shared with
     * other transports (e.g. {@link io.axiam.sdk.grpc.GrpcAuthzClient}, D-07 "one guard").
     *
     * @return this client's {@link RefreshGuard} instance
     */
    public RefreshGuard refreshGuard() {
        return refreshGuard;
    }

    /** Returns this client's configured tenant identifier.
     *
     * @return this client's configured tenant identifier (CONTRACT.md &sect;5) */
    public String tenantId() {
        return tenantId;
    }

    /** Returns this client's base URL.
     *
     * @return this client's configured, trailing-slash-stripped base URL */
    public String baseUrl() {
        return baseUrl;
    }

    /** The shared, fully-configured {@code OkHttpClient} (cookie jar, strict TLS,
     * {@code AuthInterceptor}/{@code AuthAuthenticator}) this client's REST calls run through.
     *
     * @return this client's {@code OkHttpClient}
     */
    public OkHttpClient okHttpClient() {
        return httpClient;
    }

    /** Returns the configured custom CA certificate, if any.
     *
     * @return the PEM-encoded custom CA certificate supplied via {@link Builder#customCa(byte[])},
     *         or {@code null} if none was configured */
    public byte @Nullable [] customCa() {
        return customCaPem;
    }

    /**
     * The SAME {@link SessionState} instance this client's REST transport
     * uses — required by {@link io.axiam.sdk.grpc.GrpcAuthzClient}'s public
     * constructor so the gRPC transport shares one session/guard pair with
     * REST (D-07/D-08 "one guard"), never a second, independently
     * constructed session.
     *
     * @return this client's shared {@link SessionState} instance
     */
    public SessionState session() {
        return session;
    }

    // ------------------------------------------------------------------
    // Auth methods (CONTRACT.md §1): login / verifyMfa / refresh / logout
    // ------------------------------------------------------------------

    /**
     * {@code POST /api/v1/auth/login}. Returns a typed {@link LoginResult} —
     * an MFA challenge (HTTP 202) is an expected outcome, not an exception;
     * check {@link LoginResult#mfaRequired()} before assuming a session was
     * established.
     *
     * @param email    the username or email to authenticate with
     * @param password the account password
     * @return the login outcome: either an established session ({@code mfaRequired=false})
     *         or an MFA challenge to complete via {@link #verifyMfa}
     */
    public LoginResult login(String email, String password) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("tenant_slug", tenantId);
        UUID orgId = session.configuredOrgId();
        String orgSlug = session.configuredOrgSlug();
        if (orgId != null) {
            body.put("org_id", orgId.toString());
        } else if (orgSlug != null) {
            body.put("org_slug", orgSlug);
        }
        body.put("username_or_email", email);
        body.put("password", password);

        try (Response response = executeJsonPost(LOGIN_PATH, body)) {
            if (response.code() == 200) {
                consumeBody(response);
                return new LoginResult(false, null, buildUser());
            }
            if (response.code() == 202) {
                JsonNode wire = readJson(response);
                String challengeToken = wire.path("challenge_token").asText();
                return new LoginResult(true, Sensitive.of(challengeToken), null);
            }
            throw ErrorMapper.fromHttpStatus(response.code(), "login failed", response);
        }
    }

    /** {@code CompletableFuture} async twin of {@link #login}.
     *
     * @param email    the username or email to authenticate with
     * @param password the account password
     * @return a future resolving to the login outcome
     */
    public CompletableFuture<LoginResult> loginAsync(String email, String password) {
        return CompletableFuture.supplyAsync(() -> login(email, password));
    }

    /**
     * {@code POST /api/v1/auth/mfa/verify} (CONTRACT.md &sect;1), completing
     * the two-phase flow started by {@link #login} when {@code mfaRequired}
     * was {@code true}.
     *
     * @param mfaToken the MFA challenge token returned by {@link #login} (wrapped
     *                 in {@link Sensitive} so it never appears in a naive log/toString)
     * @param totpCode the current TOTP code from the user's authenticator app
     * @return the login outcome; {@code mfaRequired} is always {@code false} on success
     */
    public LoginResult verifyMfa(Sensitive mfaToken, String totpCode) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("challenge_token", mfaToken.expose());
        body.put("totp_code", totpCode);

        try (Response response = executeJsonPost(MFA_VERIFY_PATH, body)) {
            if (response.code() != 200) {
                throw ErrorMapper.fromHttpStatus(response.code(), "MFA verification failed", response);
            }
            consumeBody(response);
            return new LoginResult(false, null, buildUser());
        }
    }

    /** {@code CompletableFuture} async twin of {@link #verifyMfa}.
     *
     * @param mfaToken the MFA challenge token returned by {@link #login}
     * @param totpCode the current TOTP code from the user's authenticator app
     * @return a future resolving to the login outcome
     */
    public CompletableFuture<LoginResult> verifyMfaAsync(Sensitive mfaToken, String totpCode) {
        return CompletableFuture.supplyAsync(() -> verifyMfa(mfaToken, totpCode));
    }

    /**
     * {@code POST /api/v1/auth/refresh} (CONTRACT.md &sect;1), routed through
     * the single-flight {@link RefreshGuard} (&sect;9). A 401 on the refresh
     * call itself is {@link AuthError} with no retry (&sect;9.3).
     */
    public void refresh() {
        String observedAccess = session.cachedAccessToken();
        if (observedAccess == null) {
            throw new AuthError("no access token to refresh — call login() first");
        }
        refreshGuard.refreshIfNeeded(observedAccess, session::doHttpRefresh);
    }

    /** {@code CompletableFuture} async twin of {@link #refresh}.
     *
     * @return a future that completes once the refresh finishes
     */
    public CompletableFuture<Void> refreshAsync() {
        return CompletableFuture.runAsync(this::refresh);
    }

    /**
     * {@code POST /api/v1/auth/logout} (CONTRACT.md &sect;1) and clears
     * in-memory session state. The session id comes from the current access
     * token's {@code jti} claim.
     */
    public void logout() {
        String access = session.cachedAccessToken();
        if (access == null) {
            throw new AuthError("no active session to log out");
        }
        SessionState.Claims claims = SessionState.decodeUnverifiedClaims(access);
        if (claims == null || claims.jti() == null) {
            throw new AuthError("access token has no session id (jti) to log out");
        }

        ObjectNode body = MAPPER.createObjectNode();
        body.put("session_id", claims.jti());

        try (Response response = executeJsonPost(LOGOUT_PATH, body)) {
            if (response.code() >= 300) {
                throw ErrorMapper.fromHttpStatus(response.code(), "logout failed", response);
            }
            consumeBody(response);
            session.clear();
        }
    }

    /** {@code CompletableFuture} async twin of {@link #logout}.
     *
     * @return a future that completes once logout finishes
     */
    public CompletableFuture<Void> logoutAsync() {
        return CompletableFuture.runAsync(this::logout);
    }

    private AxiamUser buildUser() {
        String access = session.cachedAccessToken();
        if (access == null) {
            throw new AuthError("login succeeded but no access token was set");
        }
        SessionState.Claims claims = SessionState.decodeUnverifiedClaims(access);
        if (claims == null || claims.sub() == null || claims.tenantId() == null) {
            throw new AuthError("failed to decode access token claims after login");
        }
        return new AxiamUser(claims.sub(), claims.tenantId(), claims.roles());
    }

    // ------------------------------------------------------------------
    // Authz methods (CONTRACT.md §1): checkAccess / can / batchCheck
    // ------------------------------------------------------------------

    /** A single authorization check request (CONTRACT.md &sect;1).
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     */
    public record AccessCheck(String action, String resourceId, @Nullable String scope) {
        /** Convenience constructor for a check with no sub-resource scope.
         *
         * @param action     the action being checked
         * @param resourceId the resource identifier the action is checked against
         */
        public AccessCheck(String action, String resourceId) {
            this(action, resourceId, null);
        }
    }

    /** The outcome of a single authorization check (mirrors {@code CheckAccessResponse}).
     *
     * @param allowed whether the checked action is permitted
     * @param reason  a human-readable deny reason, or {@code null} when {@code allowed}
     *                is {@code true} or the server did not supply one
     */
    public record AccessResult(boolean allowed, @Nullable String reason) {
    }

    /**
     * {@code POST /api/v1/authz/check} — evaluates a single authorization
     * check. Read-only/idempotent: eligible for {@link Retry}'s bounded
     * backoff on a transient {@link NetworkError}.
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     * @return the check outcome (allowed/denied, with an optional deny reason)
     */
    public AccessResult checkAccess(String action, String resourceId, @Nullable String scope) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("action", action);
        body.put("resource_id", resourceId);
        if (scope != null) {
            body.put("scope", scope);
        }
        return Retry.withRetry(() -> sendCheckAccess(body), AxiamClient::isRetryableNetworkError);
    }

    /** {@link #checkAccess(String, String, String)} with no sub-resource scope.
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @return the check outcome (allowed/denied, with an optional deny reason)
     */
    public AccessResult checkAccess(String action, String resourceId) {
        return checkAccess(action, resourceId, null);
    }

    /**
     * {@code POST /api/v1/authz/check} for an <strong>explicit subject</strong>
     * (CONTRACT.md &sect;11.2 subject propagation). Additive subject-aware
     * overload: the existing {@link #checkAccess(String, String, String)}
     * signatures are unchanged and check the client's own session; this
     * overload sets {@code subject_id} in the request body so the check is
     * evaluated for {@code subjectId} rather than the caller's session. Used by
     * {@code AxiamAuthorizationInterceptor} to check the request's authenticated
     * end user, not the application's service-account session.
     *
     * <p>Read-only/idempotent: eligible for {@link Retry}'s bounded backoff on
     * a transient {@link NetworkError}.
     *
     * @param subjectId  the subject (user id) the check is evaluated for; sent
     *                   as {@code subject_id}
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     * @return the check outcome (allowed/denied, with an optional deny reason)
     */
    public AccessResult checkAccess(String subjectId, String action, String resourceId, @Nullable String scope) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("subject_id", subjectId);
        body.put("action", action);
        body.put("resource_id", resourceId);
        if (scope != null) {
            body.put("scope", scope);
        }
        return Retry.withRetry(() -> sendCheckAccess(body), AxiamClient::isRetryableNetworkError);
    }

    /** {@code CompletableFuture} async twin of
     * {@link #checkAccess(String, String, String, String)} (the subject-aware overload).
     *
     * @param subjectId  the subject (user id) the check is evaluated for
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     * @return a future resolving to the check outcome
     */
    public CompletableFuture<AccessResult> checkAccessAsync(
            String subjectId, String action, String resourceId, @Nullable String scope) {
        return CompletableFuture.supplyAsync(() -> checkAccess(subjectId, action, resourceId, scope));
    }

    /** {@code CompletableFuture} async twin of {@link #checkAccess(String, String, String)}.
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     * @return a future resolving to the check outcome
     */
    public CompletableFuture<AccessResult> checkAccessAsync(String action, String resourceId, @Nullable String scope) {
        return CompletableFuture.supplyAsync(() -> checkAccess(action, resourceId, scope));
    }

    /** {@link #checkAccessAsync(String, String, String)} with no sub-resource scope.
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @return a future resolving to the check outcome
     */
    public CompletableFuture<AccessResult> checkAccessAsync(String action, String resourceId) {
        return checkAccessAsync(action, resourceId, null);
    }

    /** Browser/UI-scenario alias for {@link #checkAccess} (CONTRACT.md &sect;1 note).
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     * @return {@code true} if the action is allowed
     */
    public boolean can(String action, String resourceId, @Nullable String scope) {
        return checkAccess(action, resourceId, scope).allowed();
    }

    /** {@link #can(String, String, String)} with no sub-resource scope.
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @return {@code true} if the action is allowed
     */
    public boolean can(String action, String resourceId) {
        return can(action, resourceId, null);
    }

    /** {@code CompletableFuture} async twin of {@link #can(String, String, String)}.
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     * @return a future resolving to {@code true} if the action is allowed
     */
    public CompletableFuture<Boolean> canAsync(String action, String resourceId, @Nullable String scope) {
        return CompletableFuture.supplyAsync(() -> can(action, resourceId, scope));
    }

    /** {@link #canAsync(String, String, String)} with no sub-resource scope.
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @return a future resolving to {@code true} if the action is allowed
     */
    public CompletableFuture<Boolean> canAsync(String action, String resourceId) {
        return canAsync(action, resourceId, null);
    }

    /**
     * {@code POST /api/v1/authz/check/batch} — evaluates an ordered list of
     * checks; results are returned in the same order as {@code checks}.
     * Read-only/idempotent: eligible for {@link Retry}'s bounded backoff.
     *
     * @param checks the ordered list of checks to evaluate
     * @return the outcomes, in the same order as {@code checks}
     */
    public List<AccessResult> batchCheck(List<AccessCheck> checks) {
        ArrayNode checksArray = MAPPER.createArrayNode();
        for (AccessCheck check : checks) {
            ObjectNode item = MAPPER.createObjectNode();
            item.put("action", check.action());
            item.put("resource_id", check.resourceId());
            if (check.scope() != null) {
                item.put("scope", check.scope());
            }
            checksArray.add(item);
        }
        ObjectNode body = MAPPER.createObjectNode();
        body.set("checks", checksArray);

        return Retry.withRetry(() -> sendBatchCheck(body), AxiamClient::isRetryableNetworkError);
    }

    /** {@code CompletableFuture} async twin of {@link #batchCheck}.
     *
     * @param checks the ordered list of checks to evaluate
     * @return a future resolving to the outcomes, in the same order as {@code checks}
     */
    public CompletableFuture<List<AccessResult>> batchCheckAsync(List<AccessCheck> checks) {
        return CompletableFuture.supplyAsync(() -> batchCheck(checks));
    }

    private AccessResult sendCheckAccess(ObjectNode body) {
        try (Response response = executeJsonPost(CHECK_PATH, body)) {
            if (!response.isSuccessful()) {
                throw ErrorMapper.fromHttpStatus(response.code(), "checkAccess failed", response);
            }
            JsonNode wire = readJson(response);
            boolean allowed = wire.path("allowed").asBoolean(false);
            String reason = wire.hasNonNull("reason") ? wire.get("reason").asText() : null;
            return new AccessResult(allowed, reason);
        }
    }

    private List<AccessResult> sendBatchCheck(ObjectNode body) {
        try (Response response = executeJsonPost(BATCH_CHECK_PATH, body)) {
            if (!response.isSuccessful()) {
                throw ErrorMapper.fromHttpStatus(response.code(), "batchCheck failed", response);
            }
            JsonNode wire = readJson(response);
            List<AccessResult> results = new ArrayList<>();
            for (JsonNode item : wire.path("results")) {
                boolean allowed = item.path("allowed").asBoolean(false);
                String reason = item.hasNonNull("reason") ? item.get("reason").asText() : null;
                results.add(new AccessResult(allowed, reason));
            }
            return results;
        }
    }

    private static boolean isRetryableNetworkError(RuntimeException e) {
        return e instanceof NetworkError;
    }

    // ------------------------------------------------------------------
    // Shared HTTP mechanics
    // ------------------------------------------------------------------

    private Response executeJsonPost(String path, ObjectNode body) {
        byte[] payload;
        try {
            payload = MAPPER.writeValueAsBytes(body);
        } catch (IOException e) {
            throw new NetworkError("failed to encode request: " + e.getMessage(), e);
        }
        Request request = new Request.Builder()
                .url(baseUrl + path)
                .post(RequestBody.create(payload, JSON))
                .build();
        try {
            return httpClient.newCall(request).execute();
        } catch (IOException e) {
            throw new NetworkError("request failed: " + e.getMessage(), e);
        }
    }

    private static JsonNode readJson(Response response) {
        try {
            ResponseBody responseBody = response.body();
            if (responseBody == null) {
                return MAPPER.createObjectNode();
            }
            return MAPPER.readTree(responseBody.byteStream());
        } catch (IOException e) {
            throw new NetworkError("failed to parse response body: " + e.getMessage(), e);
        }
    }

    private static void consumeBody(Response response) {
        ResponseBody body = response.body();
        if (body != null) {
            body.close();
        }
    }

    // ------------------------------------------------------------------
    // TLS setup (§6, D-27) — system trust store + optional customCa, never a
    // bypass. Composite trust manager: server certs are accepted if EITHER
    // the system trust store OR the custom CA validates the chain.
    // ------------------------------------------------------------------

    private static X509TrustManager buildTrustManager(byte @Nullable [] customCaPem) {
        try {
            TrustManagerFactory systemTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            systemTmf.init((KeyStore) null);
            X509TrustManager systemTm = firstX509(systemTmf.getTrustManagers());

            if (customCaPem == null || customCaPem.length == 0) {
                return systemTm;
            }

            KeyStore customStore = KeyStore.getInstance(KeyStore.getDefaultType());
            customStore.load(null, null);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate customCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(customCaPem));
            customStore.setCertificateEntry("custom-ca", customCert);

            TrustManagerFactory customTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            customTmf.init(customStore);
            X509TrustManager customTm = firstX509(customTmf.getTrustManagers());

            return new CompositeX509TrustManager(systemTm, customTm);
        } catch (GeneralSecurityException | IOException e) {
            // §6: a non-PEM/invalid custom CA MUST return a clear error at
            // construction time.
            throw new NetworkError("invalid custom CA PEM: " + e.getMessage(), e);
        }
    }

    private static X509TrustManager firstX509(TrustManager[] tms) {
        for (TrustManager tm : tms) {
            if (tm instanceof X509TrustManager x509) {
                return x509;
            }
        }
        throw new IllegalStateException("no X509TrustManager found in the default TrustManagerFactory");
    }

    private static SSLContext buildStrictSslContext(X509TrustManager trustManager,
                                                    KeyManager @Nullable [] keyManagers) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            // keyManagers is the client-identity (mTLS) chain when configured, else
            // null (no client cert). The trust manager (server verification) is the
            // SAME composite system-trust-store + optional customCa either way — a
            // client certificate NEVER relaxes server verification (CONTRACT.md §6.1).
            ctx.init(keyManagers, new TrustManager[]{trustManager}, new SecureRandom());
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new NetworkError("failed to initialize TLS context: " + e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------------
    // Client-identity (mTLS) KeyManager (§6.1) — kept deliberately separate
    // from the server-verification code above so CI TLS-bypass gates are not
    // tripped. The private key is consumed into an in-memory PKCS#12 store and
    // never retained on the client (§7 key secrecy).
    // ------------------------------------------------------------------

    private static KeyManager[] buildKeyManagers(byte[] certPem, byte[] keyPem) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs =
                    cf.generateCertificates(new ByteArrayInputStream(certPem));
            if (certs.isEmpty()) {
                throw new NetworkError("client certificate PEM contained no certificates");
            }
            Certificate[] chain = certs.toArray(new Certificate[0]);
            PrivateKey privateKey = parsePrivateKey(keyPem);

            // Random, throwaway password for the in-memory store — it is never
            // persisted or exposed.
            byte[] pwBytes = new byte[32];
            new SecureRandom().nextBytes(pwBytes);
            char[] password = Base64.getEncoder().encodeToString(pwBytes).toCharArray();

            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("client", privateKey, password, chain);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, password);
            Arrays.fill(password, '\0');
            return kmf.getKeyManagers();
        } catch (GeneralSecurityException | IOException e) {
            // §6.1 rule 1: a non-PEM / malformed cert or key MUST surface as a
            // clear error at construction time.
            throw new NetworkError("invalid client certificate/key PEM: " + e.getMessage(), e);
        }
    }

    /** Parses a PEM PKCS#8 private key ({@code -----BEGIN PRIVATE KEY-----}),
     * detecting the algorithm by trying RSA, then EC, then Ed25519/EdDSA. */
    private static PrivateKey parsePrivateKey(byte[] keyPem) throws GeneralSecurityException {
        String pem = new String(keyPem, StandardCharsets.UTF_8);
        String base64 = pem
                .replaceAll("-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "")
                .replaceAll("-----END (?:RSA |EC )?PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        if (base64.isEmpty()) {
            throw new InvalidKeySpecException("no PEM private key body found "
                    + "(expected -----BEGIN PRIVATE KEY----- PKCS#8)");
        }
        byte[] der;
        try {
            der = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException("client private key PEM body is not valid base64");
        }
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        for (String algorithm : List.of("RSA", "EC", "Ed25519")) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(spec);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException tryNext) {
                // Not this algorithm (or unavailable) — try the next candidate.
            }
        }
        throw new InvalidKeySpecException(
                "unsupported or malformed PKCS#8 private key (tried RSA, EC, Ed25519)");
    }

    private static final class CompositeX509TrustManager implements X509TrustManager {
        private final X509TrustManager primary;
        private final X509TrustManager secondary;

        CompositeX509TrustManager(X509TrustManager primary, X509TrustManager secondary) {
            this.primary = primary;
            this.secondary = secondary;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            primary.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                primary.checkServerTrusted(chain, authType);
            } catch (CertificateException primaryFailure) {
                // Strict: only trust if the secondary (custom CA) validates —
                // never silently bypass on a first-manager failure.
                secondary.checkServerTrusted(chain, authType);
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            X509Certificate[] a = primary.getAcceptedIssuers();
            X509Certificate[] b = secondary.getAcceptedIssuers();
            X509Certificate[] combined = Arrays.copyOf(a, a.length + b.length);
            System.arraycopy(b, 0, combined, a.length, b.length);
            return combined;
        }
    }

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
