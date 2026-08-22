package io.axiam.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import com.nimbusds.jwt.JWTClaimsSet;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.ErrorMapper;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.errors.OAuthProtocolError;
import io.axiam.sdk.internal.DiscoveryCache;
import io.axiam.sdk.internal.JwksVerifier;
import io.axiam.sdk.internal.DecisionMemo;
import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.TelemetryDispatcher;
import io.axiam.sdk.telemetry.TelemetryEvent;
import io.axiam.sdk.webauthn.WebauthnChallenge;
import io.axiam.sdk.webauthn.WebauthnCredential;
import io.axiam.sdk.webauthn.WebauthnLoginResult;
import io.axiam.sdk.webauthn.WebauthnWorkspace;
import io.axiam.sdk.telemetry.TelemetryHook;
import io.axiam.sdk.internal.Retry;
import io.axiam.sdk.internal.SessionState;
import io.axiam.sdk.internal.SingleFlight;
import io.axiam.sdk.oidc.AuthorizationRequest;
import io.axiam.sdk.oidc.DeviceAuthorization;
import io.axiam.sdk.oidc.ExchangedToken;
import io.axiam.sdk.oidc.RequestedPermission;
import io.axiam.sdk.oidc.RequestingPartyToken;
import io.axiam.sdk.oidc.ResourceSet;
import io.axiam.sdk.oidc.IdTokenClaims;
import io.axiam.sdk.oidc.IdTokenValidator;
import io.axiam.sdk.oidc.IntrospectionResult;
import io.axiam.sdk.oidc.OidcConfiguration;
import io.axiam.sdk.oidc.OidcOperations;
import io.axiam.sdk.oidc.OidcPkce;
import io.axiam.sdk.oidc.OidcTokenSet;
import io.axiam.sdk.oidc.PushedAuthorizationRequest;
import io.axiam.sdk.oidc.SsoCompleteResult;
import io.axiam.sdk.oidc.SsoStartResult;
import io.axiam.sdk.oidc.VerifiedLogoutToken;
import io.axiam.sdk.account.MfaEnrollment;
import io.axiam.sdk.account.PasswordResetConfirmation;
import io.axiam.sdk.account.PasswordResetContext;
import io.axiam.sdk.account.PasswordResetRequest;
import io.axiam.sdk.opaque.KsfParams;
import io.axiam.sdk.opaque.LoginExchange;
import io.axiam.sdk.opaque.Opaque;
import io.axiam.sdk.opaque.OpaqueEnrollment;
import io.axiam.sdk.opaque.RegistrationExchange;

import okhttp3.java.net.cookiejar.JavaNetCookieJar;
import okhttp3.FormBody;
import okhttp3.HttpUrl;
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
import java.net.URI;
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
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.regex.Pattern;

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
public final class AxiamClient implements AutoCloseable, OidcOperations {

    private static final String LOGIN_PATH = "/api/v1/auth/login";
    private static final String MFA_VERIFY_PATH = "/api/v1/auth/mfa/verify";

    // CONTRACT.md §24 — WebAuthn / passkeys.
    /** Only the first few KB of a §24.4 rule 1 attestation-policy body are read. */
    private static final long MAX_POLICY_MESSAGE_PEEK_BYTES = 8192;

    private static final String WEBAUTHN_REGISTER_START_PATH = "/api/v1/auth/webauthn/register/start";
    private static final String WEBAUTHN_REGISTER_FINISH_PATH = "/api/v1/auth/webauthn/register/finish";
    private static final String WEBAUTHN_AUTH_START_PATH = "/api/v1/auth/webauthn/authenticate/start";
    private static final String WEBAUTHN_AUTH_FINISH_PATH = "/api/v1/auth/webauthn/authenticate/finish";
    private static final String WEBAUTHN_DISCOVERABLE_START_PATH =
            "/api/v1/auth/webauthn/authenticate/discoverable/start";
    private static final String WEBAUTHN_DISCOVERABLE_FINISH_PATH =
            "/api/v1/auth/webauthn/authenticate/discoverable/finish";

    // CONTRACT.md §25 — account lifecycle and MFA enrolment.
    private static final String MFA_ENROLL_PATH = "/api/v1/auth/mfa/enroll";
    private static final String MFA_CONFIRM_PATH = "/api/v1/auth/mfa/confirm";
    private static final String MFA_SETUP_ENROLL_PATH = "/api/v1/auth/mfa/setup/enroll";
    private static final String MFA_SETUP_CONFIRM_PATH = "/api/v1/auth/mfa/setup/confirm";
    private static final String VERIFY_EMAIL_PATH = "/api/v1/auth/verify-email";
    private static final String RESEND_VERIFICATION_PATH = "/api/v1/auth/resend-verification";
    private static final String RESET_PATH = "/api/v1/auth/reset";
    private static final String RESET_CONFIRM_PATH = "/api/v1/auth/reset/confirm";
    private static final String RESET_CONTEXT_PATH = "/api/v1/auth/reset/context";
    private static final String OPAQUE_REGISTER_START_PATH = "/api/v1/auth/opaque/register/start";
    private static final String OPAQUE_LOGIN_START_PATH = "/api/v1/auth/opaque/login/start";
    private static final String OPAQUE_LOGIN_FINISH_PATH = "/api/v1/auth/opaque/login/finish";
    private static final String LOGOUT_PATH = "/api/v1/auth/logout";
    private static final String CHECK_PATH = "/api/v1/authz/check";
    private static final String BATCH_CHECK_PATH = "/api/v1/authz/check/batch";

    // CONTRACT.md §12 OIDC/SSO relying-party helpers.
    private static final String DISCOVERY_PATH = "/.well-known/openid-configuration";
    private static final String SSO_START_PATH = "/api/v1/auth/federation/oidc/start";
    private static final String SSO_CALLBACK_PATH = "/api/v1/auth/federation/oidc/callback";
    /** §12.3 rule 6 floor: the discovery cache TTL is never allowed below 5 minutes. */
    private static final long MIN_OIDC_DISCOVERY_TTL_MILLIS = 300_000L;
    /** The eight query parameters {@code oidcBegin} owns (§12.1 rule 5); {@code extraParams} may not override these. */
    private static final Set<String> RESERVED_AUTHORIZE_PARAMS = Set.of(
            "response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
            "code_challenge", "code_challenge_method");
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String baseUrl;
    private final String tenantId;
    private final byte @Nullable [] customCaPem;
    private final OkHttpClient httpClient;
    private final RefreshGuard refreshGuard;
    private final JwksVerifier jwksVerifier;
    private final SessionState session;

    // CONTRACT.md §12 OIDC/SSO relying-party state — see the Builder's
    // oidcClientId/oidcClientSecret/oidcDiscoveryTtl/oidcClockSkew.
    private final @Nullable String oidcClientId;
    private final @Nullable Sensitive oidcClientSecret;
    private final @Nullable Integer oidcClockSkewSec;
    private final DiscoveryCache<OidcConfiguration> oidcDiscoveryCache;
    private final Map<String, JwksVerifier> oidcJwksVerifiers = new ConcurrentHashMap<>();

    /**
     * §16.1 disable switch. There is deliberately no field for the attempt cap,
     * base delay or delay cap: §16.1 forbids raising them above the contract's
     * values, and eleven SDKs agreeing on one table is the point.
     */
    private final boolean retryEnabled;

    /** §17 decision memo. Disabled unless the builder was given a TTL. */
    private final DecisionMemo<AccessResult> decisionMemo;

    /** §19 telemetry dispatcher. Inert unless a hook was installed. */
    private final TelemetryDispatcher telemetry;

    /** §18 shutdown flag, read on every operation. */
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final SingleFlight<OidcTokenSet> oidcRefreshSingleFlight = new SingleFlight<>();

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
        private @Nullable String oidcClientId;
        private @Nullable Sensitive oidcClientSecret;
        private long oidcDiscoveryTtlMillis = MIN_OIDC_DISCOVERY_TTL_MILLIS;
        private @Nullable Integer oidcClockSkewSec;
        private boolean retryEnabled = true;
        private @Nullable Duration decisionMemoTtl;
        private @Nullable TelemetryHook telemetryHook;

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

        /**
         * The relying party's OAuth2 {@code client_id} (CONTRACT.md &sect;12),
         * required by every &sect;12 operation that builds a request (all
         * except {@link #oidcDiscover()}). Comes from client configuration,
         * never a per-call argument (CONTRACT.md &sect;12 T1 reference
         * judgment call 21) — it is also the value &sect;12.4 rule 4 matches
         * an ID token's {@code aud}/{@code azp} against, and two sources
         * could otherwise disagree.
         *
         * @param clientId the relying party's OAuth2 {@code client_id}
         * @return this builder, for chaining
         */
        public Builder oidcClientId(String clientId) {
            this.oidcClientId = clientId;
            return this;
        }

        /**
         * The {@code client_secret} for a confidential OIDC client (CONTRACT.md
         * &sect;12.1 note 4), held behind {@link Sensitive} (&sect;12.5). Omit
         * for a public client — {@code oidcExchange}/{@code oidcRefresh} then
         * never add {@code client_secret} to the form body (&sect;12.1 "MUST
         * omit rather than send empty/null"). {@code introspect}, {@code revoke},
         * and {@code loginClientCredentials} REQUIRE it and raise {@code AuthError}
         * client-side, without a wire call, when it is absent.
         *
         * @param clientSecret the confidential client's {@code client_secret}
         * @return this builder, for chaining
         */
        public Builder oidcClientSecret(Sensitive clientSecret) {
            this.oidcClientSecret = clientSecret;
            return this;
        }

        /**
         * Bare-string convenience for {@link #oidcClientSecret(Sensitive)}.
         *
         * @param clientSecret the confidential client's {@code client_secret}
         * @return this builder, for chaining
         */
        public Builder oidcClientSecret(String clientSecret) {
            return oidcClientSecret(Sensitive.of(clientSecret));
        }

        /**
         * The OIDC discovery-document cache TTL (CONTRACT.md &sect;12.3
         * rule 6). <strong>Floored</strong> at 5 minutes: a smaller value is
         * silently raised to it. Defaults to 5 minutes.
         *
         * @param ttl the requested discovery-cache TTL
         * @return this builder, for chaining
         */
        public Builder oidcDiscoveryTtl(Duration ttl) {
            this.oidcDiscoveryTtlMillis = ttl.toMillis();
            return this;
        }

        /**
         * Disables the CONTRACT.md §16 bounded read-only retry policy, making
         * every operation exactly one attempt.
         *
         * <p>That is the right choice for a caller who owns their own retry
         * layer — they know their deadline and this SDK does not — but it is
         * not a way to make failures quieter: a transient {@code NetworkError}
         * simply surfaces immediately.
         *
         * <p>§16.1 permits this switch but forbids raising the attempt cap,
         * base delay or delay cap above the contract's values, so there is no
         * builder method for those.
         *
         * @return this builder
         */
        public Builder retryDisabled() {
            this.retryEnabled = false;
            return this;
        }

        /**
         * Enables the CONTRACT.md §17 client-side decision memo.
         *
         * <p><strong>Disabled by default</strong> — §11.2 rule 6's ban on
         * caching authorization decisions is still the default behaviour, and
         * this is the single opt-in exception.
         *
         * <p><strong>What you are accepting:</strong> the staleness bound is
         * {@code ttl} in <em>both</em> directions. A grant revoked on the
         * server can still read as allowed for up to the TTL, and a grant just
         * added can still read as denied for up to the TTL.
         *
         * <p><strong>Reads-your-own-writes is not guaranteed.</strong> An admin
         * UI that grants a role and immediately re-checks is the case that
         * breaks, and it breaks silently. If that is your workload, do not set
         * this.
         *
         * <p>{@code ttl} is clamped to {@link DecisionMemo#MAX_TTL} rather than
         * rejected. Allows and denies are memoized identically (asymmetric
         * caching leaks the outcome through latency), failures are never
         * memoized, and the memo is cleared on any credential change.
         *
         * @param ttl how long a decision may be reused
         * @return this builder
         */
        public Builder decisionMemoTtl(Duration ttl) {
            this.decisionMemoTtl = ttl;
            return this;
        }

        /**
         * Installs a CONTRACT.md §19 telemetry sink.
         *
         * <p>It receives request start/end, §16 retry and §9 refresh events, so
         * metrics can be wired without this library depending on any metrics
         * API.
         *
         * <p>A hook that throws cannot fail the operation that fired it (§19.2
         * rule 2), and no event payload can carry a token — {@code
         * TelemetryEvent} is a sealed hierarchy of records with fixed component
         * lists (§19.2 rule 3). It is invoked on the calling thread, so it must
         * not block.
         *
         * @param hook the sink
         * @return this builder
         */
        public Builder telemetryHook(TelemetryHook hook) {
            this.telemetryHook = hook;
            return this;
        }

        /**
         * Permitted ID-token clock skew (CONTRACT.md &sect;12.4 rule 5).
         * <strong>Clamped</strong> at 60 seconds: a larger value is silently
         * reduced. Defaults to 60 seconds when never called.
         *
         * @param skew the requested permitted clock skew
         * @return this builder, for chaining
         */
        public Builder oidcClockSkew(Duration skew) {
            this.oidcClockSkewSec = (int) Math.min(skew.toSeconds(), IdTokenValidator.MAX_CLOCK_SKEW_SEC);
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
        this.oidcClientId = b.oidcClientId;
        this.oidcClientSecret = b.oidcClientSecret;
        this.oidcClockSkewSec = b.oidcClockSkewSec;
        this.oidcDiscoveryCache = new DiscoveryCache<>(b.oidcDiscoveryTtlMillis, MIN_OIDC_DISCOVERY_TTL_MILLIS);
        this.retryEnabled = b.retryEnabled;
        // §17.1 rule 1 — off unless the caller asked for it.
        this.decisionMemo = new DecisionMemo<>(b.decisionMemoTtl);
        this.telemetry = new TelemetryDispatcher(b.telemetryHook);
        // §19.2 rule 6: a clamped setting is reported, not swallowed. Emitted
        // once, here, because construction is the only moment an operator can
        // act on it.
        this.decisionMemo.reportClamp(b.decisionMemoTtl, this.telemetry);

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
        // Idempotent (CONTRACT.md §18.1 rule 2): cleanup runs from error paths,
        // and an error path that itself throws hides the original failure.
        // compareAndSet also means a concurrent double-close does the work once.
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        decisionMemo.clear();
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

    /**
     * Throws if {@link #close()} has been called (CONTRACT.md §18.1 rule 4).
     *
     * <p>Use-after-close is an error, not a silent reconnect: a client that
     * quietly rebuilt its transport would make {@code close()} meaningless and
     * hide the lifecycle bug that caused the call.
     */
    private void ensureOpen() {
        if (closed.get()) {
            throw new NetworkError("client is closed: this AxiamClient was shut down with close()");
        }
    }

    /**
     * Drops memoized decisions (CONTRACT.md §17.1 rule 9).
     *
     * <p>Entries are keyed by subject rather than session, so a
     * re-authentication as a <em>different</em> principal would otherwise
     * inherit the previous one's decisions.
     */
    private void onCredentialChange() {
        decisionMemo.clear();
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
        ensureOpen();
        onCredentialChange();
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
            if (response.code() == 403) {
                // CONTRACT.md §25.2 rule 1: a 403 carrying mfa_setup_required
                // is an OUTCOME, not a refusal. The tenant requires MFA, this
                // account has none, and the server handed back the token to
                // finish.
                //
                // Matched on the body's own discriminant rather than the status
                // alone: a genuine authorization refusal is also a 403, and
                // only one of the two carries a setup_token.
                //
                // Read with peekBody, not readJson: a 403 that is NOT this
                // outcome must reach ErrorMapper with its body still intact,
                // both so the §2 authz mapping can lift action/resource_id out
                // of it and so a non-JSON body stays an AuthzError rather than
                // becoming a parse failure.
                Sensitive setupToken = readSetupToken(response);
                if (setupToken != null) {
                    return LoginResult.mfaSetupRequired(setupToken);
                }
                throw ErrorMapper.fromHttpStatus(403, "login failed", response);
            }
            throw ErrorMapper.fromHttpStatus(response.code(), "login failed", response);
        }
    }

    /**
     * The {@code setup_token} from a &sect;25.2 rule 1 {@code 403}, or
     * {@code null} when this 403 is an ordinary authorization refusal.
     *
     * <p>Non-destructive: the response body is left exactly as received, so
     * the caller can still hand it to {@link ErrorMapper}.
     */
    private static @Nullable Sensitive readSetupToken(Response response) {
        if (response.body() == null) {
            return null;
        }
        try {
            JsonNode wire = MAPPER.readTree(
                    response.peekBody(MAX_POLICY_MESSAGE_PEEK_BYTES).string());
            String token = wire.path("setup_token").asText("");
            if (wire.path("mfa_setup_required").asBoolean(false) && !token.isEmpty()) {
                return Sensitive.of(token);
            }
        } catch (IOException | RuntimeException ignored) {
            // A non-JSON 403 is simply not this outcome.
        }
        return null;
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
        ensureOpen();
        onCredentialChange();
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
        ensureOpen();
        onCredentialChange();
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
        ensureOpen();
        onCredentialChange();
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

    // ------------------------------------------------------------------
    // OPAQUE, RFC 9807 (CONTRACT.md §23)
    // ------------------------------------------------------------------

    /**
     * {@code POST /api/v1/auth/opaque/login/start} followed by
     * {@code /finish} — OPAQUE login, RFC 9807 (CONTRACT.md &sect;23).
     *
     * <p>A sibling of {@link #login}, not a replacement. It takes the same
     * arguments and returns the same {@link LoginResult}, MFA branch included,
     * so an application can switch a tenant to OPAQUE without touching its own
     * code.
     *
     * <p><strong>What this does that {@code login} does not.</strong> The
     * password never leaves this process. What crosses the wire is a blinded
     * group element and a MAC, neither useful without the account's
     * registration record <em>and</em> the tenant's OPRF seed — so a
     * TLS-terminating proxy, an accidentally verbose request log, or a heap
     * dump on the server cannot capture a plaintext password, because the
     * server never has one. It also means a stolen record database is not
     * offline-crackable on its own, which is the pre-computation resistance
     * SRP could not offer. It does <strong>not</strong> protect against a
     * compromised AXIAM server.
     *
     * <p><strong>One round trip, and no server-proof step.</strong> SRP had to
     * guess a group before the server named one and restart the exchange if it
     * guessed wrong; {@code KE1} does not depend on the key-stretching
     * function. And where the old &sect;23.3 rule 6 had to mandate an
     * {@code M2} check in capitals — because skipping it kept only half the
     * protocol — RFC 9807's AKE authenticates the server during the handshake,
     * so opening {@code KE2} <em>is</em> the proof that it holds the record.
     * There is nothing left to skip.
     *
     * <p><strong>Cost.</strong> Runs the tenant's key-stretching function:
     * Argon2id at 19 MiB and t=2 by default, tens to hundreds of milliseconds
     * of CPU plus that memory, per attempt. That cost is the point — it is what
     * makes a stolen record expensive to attack even by someone holding the
     * OPRF seed.
     *
     * @param usernameOrEmail the username or email to authenticate with
     * @param password        the account password, as a {@code char[]} so the
     *                        caller can clear it; this SDK clears every copy it
     *                        makes but cannot clear the caller's
     * @return the login outcome, exactly as {@link #login} returns it
     * @throws NetworkError if the tenant has OPAQUE disabled (the endpoint
     *                      answers {@code 404} — a property of the tenant, not
     *                      of any user), if {@code libaxiam_opaque_ffi} is not
     *                      installed, or if the server names a key-stretching
     *                      function this SDK cannot ask for. Deliberately not
     *                      {@link AuthError}: reporting a configuration gap as
     *                      a credential failure would send a user off to reset
     *                      a password that works, and would stop a caller
     *                      falling back to {@link #login}
     * @throws AuthError    for a wrong password, an account that does not
     *                      exist, and a server that does not hold the record —
     *                      indistinguishable by design. <strong>Nothing is sent
     *                      to {@code login/finish} in that case</strong>
     *                      (&sect;23.4 rule 7), and a caller must not retry over
     *                      {@link #login}: that hands the plaintext to an
     *                      endpoint that just failed to prove itself
     */
    public LoginResult loginOpaque(String usernameOrEmail, char[] password) {
        ensureOpen();
        onCredentialChange();

        try (LoginExchange exchange = Opaque.startLogin(password)) {
            JsonNode started = opaqueStart(OPAQUE_LOGIN_START_PATH,
                    opaqueLoginStartBody(usernameOrEmail, exchange.ke1()), "login/start");

            JsonNode ke2 = started.get("ke2");
            if (ke2 == null || !ke2.isTextual()) {
                throw new NetworkError("OPAQUE: login/start returned no `ke2`");
            }
            String ke3 = exchange.finish(password, ke2.asText(), KsfParams.fromWire(started));

            ObjectNode body = MAPPER.createObjectNode();
            body.put("opaque_session", started.path("opaque_session").asText(""));
            body.put("ke3", ke3);

            try (Response response = executeJsonPost(OPAQUE_LOGIN_FINISH_PATH, body)) {
                int code = response.code();
                if (code != 200 && code != 202) {
                    throw ErrorMapper.fromHttpStatus(code, "OPAQUE login/finish failed", response);
                }
                if (code == 202) {
                    JsonNode wire = readJson(response);
                    return new LoginResult(true,
                            Sensitive.of(wire.path("challenge_token").asText()), null);
                }
                return new LoginResult(false, null, buildUser());
            }
        }
    }

    /** {@code CompletableFuture} async twin of {@link #loginOpaque}.
     *
     * @param usernameOrEmail the username or email to authenticate with
     * @param password        the account password
     * @return a future resolving to the login outcome
     */
    public CompletableFuture<LoginResult> loginOpaqueAsync(String usernameOrEmail, char[] password) {
        return CompletableFuture.supplyAsync(() -> loginOpaque(usernameOrEmail, password));
    }

    /**
     * Builds a registration record for {@code password}, to send with any
     * request that sets one: {@code POST /api/v1/users},
     * {@code /auth/password/change}, {@code /auth/reset/confirm} and
     * {@code /admin/bootstrap}.
     *
     * <p>The server cannot build this — it never sees the plaintext — so it has
     * to arrive with the request or not at all.
     *
     * <p>Unlike the {@code srpEnrollment} it replaces this performs I/O: one
     * {@code register/start} round trip. OPAQUE's envelope is sealed under the
     * server's oblivious PRF, so there is no offline computation that produces
     * a valid record.
     *
     * <p>Note the arguments that are gone. There is no {@code identity}: the
     * SRP version required the account's canonical <em>username</em>, and an
     * email there produced a verifier no login could ever satisfy, whereas a
     * record binds to a credential identifier the server chooses. And there is
     * no group or KDF, because those come from the {@code register/start}
     * response — a caller cannot pick a cost the server will not honour.
     *
     * @param password the plaintext being enrolled
     * @return the {@code opaque} object to attach to the request
     * @throws NetworkError if the tenant has OPAQUE disabled, if
     *                      {@code libaxiam_opaque_ffi} is not installed, or if
     *                      the server names a key-stretching function this SDK
     *                      cannot ask for
     */
    public OpaqueEnrollment opaqueEnrollment(char[] password) {
        ensureOpen();

        try (RegistrationExchange exchange = Opaque.startRegistration(password)) {
            JsonNode started = opaqueStart(OPAQUE_REGISTER_START_PATH,
                    opaqueRegisterStartBody(exchange.request()), "register/start");
            String record = exchange.finish(password,
                    started.path("registration_response").asText(""),
                    KsfParams.fromWire(started));
            return new OpaqueEnrollment(started.path("opaque_session").asText(""), record);
        }
    }

    /**
     * Whether this installation can perform OPAQUE (&sect;23.2).
     *
     * <p>Genuinely able to answer {@code false}, unlike the {@code srpAvailable}
     * it replaces — which was hard-coded {@code true} on the JVM because
     * {@code BigInteger} and BouncyCastle are always there. The protocol now
     * comes from {@code libaxiam_opaque_ffi} via JNA, and both are optional:
     * {@code net.java.dev.jna:jna} is an optional dependency of this SDK, and
     * the shared library is a per-platform release asset rather than a Maven
     * artifact. Ask before a login rather than discovering the gap mid-exchange.
     *
     * @return {@code true} when both are present and the library says it can
     */
    public boolean opaqueAvailable() {
        return Opaque.available();
    }

    /**
     * Sends one {@code &#42;/start} request and returns the parsed response.
     *
     * <p>Shared by both OPAQUE paths so the meaning of a failure cannot drift
     * between them. A {@code 404} is a property of the tenant ("OPAQUE is off
     * here"), not of the user and not of the credentials — so it is a
     * {@link NetworkError} a caller can fall back on, never an
     * {@link AuthError} that would be shown as "invalid password".
     */
    private JsonNode opaqueStart(String path, ObjectNode body, String what) {
        try (Response response = executeJsonPost(path, body)) {
            if (response.code() == 404) {
                throw new NetworkError("OPAQUE: this tenant does not offer OPAQUE "
                        + "(opaque_mode is disabled); use login() instead");
            }
            if (response.code() != 200) {
                throw ErrorMapper.fromHttpStatus(response.code(),
                        "OPAQUE " + what + " failed", response);
            }
            return readJson(response);
        }
    }

    /**
     * Builds the {@code login/start} body.
     *
     * <p>Carries the same tenant/org resolution as the password login so the
     * two paths cannot drift, and no {@code password} field — that absence is
     * the entire point of the exchange.
     */
    private ObjectNode opaqueLoginStartBody(String usernameOrEmail, String ke1) {
        ObjectNode body = opaqueWorkspaceBody();
        body.put("username_or_email", usernameOrEmail);
        body.put("ke1", ke1);
        return body;
    }

    /**
     * Builds the {@code register/start} body.
     *
     * <p>Names no account at all: enrolment binds to a credential identifier
     * the server chooses, which is why a later rename cannot invalidate a
     * credential.
     */
    private ObjectNode opaqueRegisterStartBody(String registrationRequest) {
        ObjectNode body = opaqueWorkspaceBody();
        body.put("registration_request", registrationRequest);
        return body;
    }

    /** The tenant/org fields every OPAQUE request carries. */
    private ObjectNode opaqueWorkspaceBody() {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("tenant_slug", tenantId);
        UUID orgId = session.configuredOrgId();
        String orgSlug = session.configuredOrgSlug();
        if (orgId != null) {
            body.put("org_id", orgId.toString());
        } else if (orgSlug != null) {
            body.put("org_slug", orgSlug);
        }
        return body;
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
     * @param reasonCode machine-readable decision reason (CONTRACT.md &sect;11 rule 9, B1 deny-override): {@code "allowed"}, {@code "no_grant"} or {@code "denied_by_rule"}. <strong>The two refusals mean opposite things to the person on the other end</strong> — {@code no_grant} says <em>ask an admin for access</em>, {@code denied_by_rule} says <em>an admin has already decided</em> — which is why the contract forbids collapsing them into a bare {@code false}. {@code null} when the server omits the field, so a newer SDK against an older server degrades rather than failing. An unrecognised value is surfaced verbatim and never changes {@code allowed}, which is why this is a {@code String} rather than an enum
     *                is {@code true} or the server did not supply one
     */
    public record AccessResult(boolean allowed, @Nullable String reason, @Nullable String reasonCode) {
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
        return memoizedCheck(null, action, resourceId, scope);
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
        return memoizedCheck(subjectId, action, resourceId, scope);
    }

    /**
     * The shared body of both {@code checkAccess} overloads: §18 guard, §17
     * memo, §16 retry, §19 telemetry.
     *
     * <p>The call is a {@code POST} but changes no server state, so it is
     * retry-eligible: §16.2's test is "changes no server state", <em>not</em>
     * "is a GET". Gating on the verb would exclude the single most important
     * operation this policy covers.
     */
    private AccessResult memoizedCheck(@Nullable String subjectId, String action,
                                       String resourceId, @Nullable String scope) {
        ensureOpen();

        // §17: consult the memo first. Disabled by default, in which case this
        // is one map lookup that always misses.
        String key = DecisionMemo.key(subjectId, resourceId, action, scope);
        AccessResult memoized = decisionMemo.get(key);
        if (memoized != null) {
            return memoized;
        }

        ObjectNode body = MAPPER.createObjectNode();
        if (subjectId != null) {
            body.put("subject_id", subjectId);
        }
        body.put("action", action);
        body.put("resource_id", resourceId);
        if (scope != null) {
            body.put("scope", scope);
        }

        AccessResult result = Retry.withRetry(
                retryEnabled ? Retry.DEFAULT_MAX_ATTEMPTS : 1,
                attempt -> sendCheckAccess(body, "checkAccess", attempt),
                AxiamClient::isRetryableNetworkError,
                telemetry,
                "checkAccess");

        // Only a decision the server actually returned is memoized: reaching
        // here means success, so §17.1 rule 7's ban on caching a failure is
        // structural rather than a check that could be forgotten.
        decisionMemo.put(key, result);
        return result;
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

        ensureOpen();
        return Retry.withRetry(
                retryEnabled ? Retry.DEFAULT_MAX_ATTEMPTS : 1,
                attempt -> sendBatchCheck(body, "batchCheck", attempt),
                AxiamClient::isRetryableNetworkError,
                telemetry,
                "batchCheck");
    }

    /** {@code CompletableFuture} async twin of {@link #batchCheck}.
     *
     * @param checks the ordered list of checks to evaluate
     * @return a future resolving to the outcomes, in the same order as {@code checks}
     */
    public CompletableFuture<List<AccessResult>> batchCheckAsync(List<AccessCheck> checks) {
        return CompletableFuture.supplyAsync(() -> batchCheck(checks));
    }

    private AccessResult sendCheckAccess(ObjectNode body, String operation, int attempt) {
        TelemetryDispatcher.Span span = telemetry.startRequest(operation, "POST", CHECK_PATH, attempt);
        try (Response response = executeJsonPost(CHECK_PATH, body)) {
            if (!response.isSuccessful()) {
                span.end(response.code(), TelemetryEvent.Outcome.FAILURE);
                throw ErrorMapper.fromHttpStatus(response.code(), "checkAccess failed", response);
            }
            span.end(response.code(), TelemetryEvent.Outcome.SUCCESS);
            JsonNode wire = readJson(response);
            boolean allowed = wire.path("allowed").asBoolean(false);
            String reason = wire.hasNonNull("reason") ? wire.get("reason").asText() : null;
            // §11 rule 9: surfaced verbatim, including a code this SDK has
            // never heard of — the outcome is carried by `allowed` alone, so
            // an unknown code can never change it.
            String reasonCode = wire.hasNonNull("reason_code") ? wire.get("reason_code").asText() : null;
            return new AccessResult(allowed, reason, reasonCode);
        }
    }

    private List<AccessResult> sendBatchCheck(ObjectNode body, String operation, int attempt) {
        TelemetryDispatcher.Span span = telemetry.startRequest(operation, "POST", BATCH_CHECK_PATH, attempt);
        try (Response response = executeJsonPost(BATCH_CHECK_PATH, body)) {
            if (!response.isSuccessful()) {
                span.end(response.code(), TelemetryEvent.Outcome.FAILURE);
                throw ErrorMapper.fromHttpStatus(response.code(), "batchCheck failed", response);
            }
            span.end(response.code(), TelemetryEvent.Outcome.SUCCESS);
            JsonNode wire = readJson(response);
            List<AccessResult> results = new ArrayList<>();
            for (JsonNode item : wire.path("results")) {
                boolean allowed = item.path("allowed").asBoolean(false);
                String reason = item.hasNonNull("reason") ? item.get("reason").asText() : null;
                String reasonCode = item.hasNonNull("reason_code") ? item.get("reason_code").asText() : null;
                results.add(new AccessResult(allowed, reason, reasonCode));
            }
            return results;
        }
    }

    private static boolean isRetryableNetworkError(RuntimeException e) {
        return e instanceof NetworkError;
    }

    // ------------------------------------------------------------------
    // OIDC / SSO relying-party helpers (CONTRACT.md §12): oidcDiscover,
    // oidcBegin, oidcExchange, oidcRefresh, loginClientCredentials,
    // introspect, revoke, ssoStart, ssoComplete. Built on this class's
    // existing httpClient/refreshGuard/session/jwksVerifier machinery —
    // §12 forbids forking any of it. See io.axiam.sdk.oidc.OidcOperations
    // for the canonical (full-argument) signatures; the overloads and
    // *Async companions here (§12.2 Java note) all delegate to them.
    // ------------------------------------------------------------------

    @Override
    public OidcConfiguration oidcDiscover() {
        String originKey = normalizeOrigin(baseUrl);
        return oidcDiscoveryCache.get(originKey, this::fetchDiscoveryDocument);
    }

    /** {@code CompletableFuture} async twin of {@link #oidcDiscover()}.
     *
     * @return a future resolving to the discovery document
     */
    public CompletableFuture<OidcConfiguration> oidcDiscoverAsync() {
        return CompletableFuture.supplyAsync(this::oidcDiscover);
    }

    /** {@link #oidcBegin(OidcConfiguration, String, String, Map)} with the default scope ({@code openid}) and no extra parameters.
     *
     * @param configuration the discovery document, as returned by {@link #oidcDiscover()}
     * @param redirectUri   the relying party's redirect URI
     * @return the built authorization request
     */
    public AuthorizationRequest oidcBegin(OidcConfiguration configuration, String redirectUri) {
        return oidcBegin(configuration, redirectUri, null, null);
    }

    @Override
    public AuthorizationRequest oidcBegin(OidcConfiguration configuration, String redirectUri,
            @Nullable String scope, @Nullable Map<String, String> extraParams) {
        requireOidcClientId();
        String state = OidcPkce.randomUrlSafeToken();
        String nonce = OidcPkce.randomUrlSafeToken();
        String codeVerifierRaw = OidcPkce.generateCodeVerifier();
        String codeChallenge = OidcPkce.computeCodeChallenge(codeVerifierRaw);

        HttpUrl authorizationEndpoint = HttpUrl.parse(configuration.authorization_endpoint());
        if (authorizationEndpoint == null) {
            throw new NetworkError(
                    "discovery document authorization_endpoint is not a valid URL: " + configuration.authorization_endpoint());
        }
        HttpUrl.Builder urlBuilder = authorizationEndpoint.newBuilder();

        if (extraParams != null) {
            for (Map.Entry<String, String> entry : extraParams.entrySet()) {
                if (RESERVED_AUTHORIZE_PARAMS.contains(entry.getKey())) {
                    throw new IllegalArgumentException("oidcBegin: extraParams may not override the SDK-owned "
                            + "authorization parameter \"" + entry.getKey() + "\" (CONTRACT.md §12.1 rule 5).");
                }
                urlBuilder.addQueryParameter(entry.getKey(), entry.getValue());
            }
        }

        urlBuilder.addQueryParameter("response_type", "code")
                .addQueryParameter("client_id", oidcClientId)
                .addQueryParameter("redirect_uri", redirectUri)
                .addQueryParameter("scope", normalizeScope(scope))
                .addQueryParameter("state", state)
                .addQueryParameter("nonce", nonce)
                .addQueryParameter("code_challenge", codeChallenge)
                .addQueryParameter("code_challenge_method", OidcPkce.CODE_CHALLENGE_METHOD_S256);

        return new AuthorizationRequest(urlBuilder.build().toString(), state, nonce, Sensitive.of(codeVerifierRaw));
    }

    @Override
    public OidcTokenSet oidcExchange(OidcConfiguration configuration, String code, Sensitive codeVerifier,
            String redirectUri, String nonce, @Nullable UUID tenantId) {
        FormBody.Builder form = new FormBody.Builder()
                .add("grant_type", "authorization_code")
                .add("code", code)
                .add("code_verifier", codeVerifier.expose())
                .add("redirect_uri", redirectUri)
                .add("client_id", requireOidcClientId());
        appendOidcClientSecret(form);

        JsonNode wire = postToken(configuration, form.build(), tenantId);
        return buildTokenSet(wire, configuration, nonce);
    }

    /** Bare-string convenience for {@link #oidcExchange(OidcConfiguration, String, Sensitive, String, String, UUID)}
     * (port-brief-addendum item 6: secret inputs accept either the wrapped or bare form), defaulting {@code tenantId}
     * to the client's configured tenant.
     *
     * @param configuration the discovery document the authorization request was built from
     * @param code          the authorization code the IdP redirected back with
     * @param codeVerifier  the verifier from the matching {@link AuthorizationRequest}
     * @param redirectUri   the same {@code redirect_uri} sent on the authorization request
     * @param nonce         the {@code nonce} from the matching {@link AuthorizationRequest}
     * @return the validated token set
     */
    public OidcTokenSet oidcExchange(OidcConfiguration configuration, String code, String codeVerifier,
            String redirectUri, String nonce) {
        return oidcExchange(configuration, code, Sensitive.of(codeVerifier), redirectUri, nonce, null);
    }

    /** {@code CompletableFuture} async twin of {@link #oidcExchange(OidcConfiguration, String, Sensitive, String, String, UUID)}.
     *
     * @param configuration the discovery document the authorization request was built from
     * @param code          the authorization code the IdP redirected back with
     * @param codeVerifier  the verifier from the matching {@link AuthorizationRequest}
     * @param redirectUri   the same {@code redirect_uri} sent on the authorization request
     * @param nonce         the {@code nonce} from the matching {@link AuthorizationRequest}
     * @param tenantId      tenant UUID for the {@code tenant_id} query parameter, or {@code null} to default
     * @return a future resolving to the validated token set
     */
    public CompletableFuture<OidcTokenSet> oidcExchangeAsync(OidcConfiguration configuration, String code,
            Sensitive codeVerifier, String redirectUri, String nonce, @Nullable UUID tenantId) {
        return CompletableFuture.supplyAsync(() -> oidcExchange(configuration, code, codeVerifier, redirectUri, nonce, tenantId));
    }

    @Override
    public OidcTokenSet oidcRefresh(Sensitive refreshToken, @Nullable String scope, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration) {
        // §9's single guard also serializes the cookie-session refresh() path
        // (RefreshGuard.runExclusive shares that SAME lock), so an oidcRefresh
        // and a concurrent cookie-session refresh can never interleave; the
        // SingleFlight coalesces concurrent oidcRefresh callers into one wire
        // call sharing its result (port-brief-addendum item 14).
        return oidcRefreshSingleFlight.run(() ->
                refreshGuard.runExclusive(() -> doOidcRefresh(refreshToken, scope, tenantId, configuration)));
    }

    private OidcTokenSet doOidcRefresh(Sensitive refreshToken, @Nullable String scope, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration) {
        OidcConfiguration config = configuration != null ? configuration : oidcDiscover();
        FormBody.Builder form = new FormBody.Builder()
                .add("grant_type", "refresh_token")
                .add("refresh_token", refreshToken.expose())
                .add("client_id", requireOidcClientId());
        appendOidcClientSecret(form);
        if (scope != null) {
            form.add("scope", scope);
        }
        JsonNode wire = postToken(config, form.build(), tenantId);
        // No nonce: rule 6 does not apply to a refresh-issued ID token.
        return buildTokenSet(wire, config, null);
    }

    /** {@link #oidcRefresh(Sensitive, String, UUID, OidcConfiguration)} with every optional argument defaulted.
     *
     * @param refreshToken the refresh token to redeem
     * @return the refreshed token set
     */
    public OidcTokenSet oidcRefresh(Sensitive refreshToken) {
        return oidcRefresh(refreshToken, null, null, null);
    }

    /** Bare-string convenience for {@link #oidcRefresh(Sensitive)}.
     *
     * @param refreshToken the refresh token to redeem
     * @return the refreshed token set
     */
    public OidcTokenSet oidcRefresh(String refreshToken) {
        return oidcRefresh(Sensitive.of(refreshToken), null, null, null);
    }

    /** {@code CompletableFuture} async twin of {@link #oidcRefresh(Sensitive)}.
     *
     * @param refreshToken the refresh token to redeem
     * @return a future resolving to the refreshed token set
     */
    public CompletableFuture<OidcTokenSet> oidcRefreshAsync(Sensitive refreshToken) {
        return CompletableFuture.supplyAsync(() -> oidcRefresh(refreshToken));
    }

    @Override
    public OidcTokenSet loginClientCredentials(@Nullable String scope, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration) {
        OidcConfiguration config = configuration != null ? configuration : oidcDiscover();
        FormBody.Builder form = new FormBody.Builder()
                .add("grant_type", "client_credentials")
                .add("client_id", requireOidcClientId())
                .add("client_secret", requireOidcClientSecret("loginClientCredentials"));
        if (scope != null) {
            form.add("scope", scope);
        }
        JsonNode wire = postToken(config, form.build(), tenantId);
        // No nonce: rule 6 does not apply to this grant, which requests no
        // openid scope and carries no id_token in practice.
        return buildTokenSet(wire, config, null);
    }

    /** {@link #loginClientCredentials(String, UUID, OidcConfiguration)} with every optional argument defaulted.
     *
     * @return the issued token set
     */
    public OidcTokenSet loginClientCredentials() {
        return loginClientCredentials(null, null, null);
    }

    /** {@code CompletableFuture} async twin of {@link #loginClientCredentials()}.
     *
     * @return a future resolving to the issued token set
     */
    public CompletableFuture<OidcTokenSet> loginClientCredentialsAsync() {
        return CompletableFuture.supplyAsync(this::loginClientCredentials);
    }

    @Override
    public IntrospectionResult introspect(Sensitive token, @Nullable String tokenTypeHint, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration) {
        OidcConfiguration config = configuration != null ? configuration : oidcDiscover();
        FormBody.Builder form = new FormBody.Builder()
                .add("token", token.expose())
                .add("client_id", requireOidcClientId())
                .add("client_secret", requireOidcClientSecret("introspect"));
        if (tokenTypeHint != null) {
            form.add("token_type_hint", tokenTypeHint);
        }
        String url = oauth2Url(config.introspection_endpoint(), tenantId);
        try (Response response = executeFormPost(url, form.build())) {
            if (!response.isSuccessful()) {
                throw ErrorMapper.fromOAuth2Response(response.code(), response, "introspect request failed");
            }
            JsonNode wire = readJson(response);
            return new IntrospectionResult(
                    wire.path("active").asBoolean(false),
                    wire.hasNonNull("sub") ? wire.get("sub").asText() : null,
                    wire.hasNonNull("client_id") ? wire.get("client_id").asText() : null,
                    wire.hasNonNull("scope") ? wire.get("scope").asText() : null,
                    wire.hasNonNull("token_type") ? wire.get("token_type").asText() : null,
                    wire.hasNonNull("exp") ? wire.get("exp").asLong() : null,
                    wire.hasNonNull("iat") ? wire.get("iat").asLong() : null);
        }
    }

    /** {@link #introspect(Sensitive, String, UUID, OidcConfiguration)} with every optional argument defaulted.
     *
     * @param token the token to introspect
     * @return the introspection result
     */
    public IntrospectionResult introspect(Sensitive token) {
        return introspect(token, null, null, null);
    }

    /** Bare-string convenience for {@link #introspect(Sensitive)}.
     *
     * @param token the token to introspect
     * @return the introspection result
     */
    public IntrospectionResult introspect(String token) {
        return introspect(Sensitive.of(token), null, null, null);
    }

    /** {@code CompletableFuture} async twin of {@link #introspect(Sensitive)}.
     *
     * @param token the token to introspect
     * @return a future resolving to the introspection result
     */
    public CompletableFuture<IntrospectionResult> introspectAsync(Sensitive token) {
        return CompletableFuture.supplyAsync(() -> introspect(token));
    }

    @Override
    public void revoke(Sensitive token, @Nullable String tokenTypeHint, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration) {
        OidcConfiguration config = configuration != null ? configuration : oidcDiscover();
        FormBody.Builder form = new FormBody.Builder()
                .add("token", token.expose())
                .add("client_id", requireOidcClientId())
                .add("client_secret", requireOidcClientSecret("revoke"));
        if (tokenTypeHint != null) {
            form.add("token_type_hint", tokenTypeHint);
        }
        String url = oauth2Url(config.revocation_endpoint(), tenantId);
        try (Response response = executeFormPost(url, form.build())) {
            if (!response.isSuccessful()) {
                throw ErrorMapper.fromOAuth2Response(response.code(), response, "revoke request failed");
            }
            consumeBody(response);
        }
    }

    /** {@link #revoke(Sensitive, String, UUID, OidcConfiguration)} with every optional argument defaulted.
     *
     * @param token the token to revoke
     */
    public void revoke(Sensitive token) {
        revoke(token, null, null, null);
    }

    /** Bare-string convenience for {@link #revoke(Sensitive)}.
     *
     * @param token the token to revoke
     */
    public void revoke(String token) {
        revoke(Sensitive.of(token), null, null, null);
    }

    /** {@code CompletableFuture} async twin of {@link #revoke(Sensitive)}.
     *
     * @param token the token to revoke
     * @return a future that completes once revocation finishes
     */
    public CompletableFuture<Void> revokeAsync(Sensitive token) {
        return CompletableFuture.runAsync(() -> revoke(token));
    }

    @Override
    public SsoStartResult ssoStart(String federationConfigId, String redirectUri, @Nullable UUID tenantId,
            @Nullable String tenantSlug, @Nullable UUID orgId, @Nullable String orgSlug) {
        UUID resolvedTenantId = tenantId;
        String resolvedTenantSlug = tenantSlug;
        if (resolvedTenantId == null && resolvedTenantSlug == null) {
            // Default from the client's own construction-time tenant identifier
            // (§5.1 by analogy with LoginRequest): the UUID form wins when the
            // configured value looks like one, else it is treated as a slug.
            if (UUID_PATTERN.matcher(this.tenantId).matches()) {
                resolvedTenantId = UUID.fromString(this.tenantId);
            } else {
                resolvedTenantSlug = this.tenantId;
            }
        }
        UUID resolvedOrgId = orgId != null ? orgId : session.configuredOrgId();
        String resolvedOrgSlug = orgSlug != null ? orgSlug : session.configuredOrgSlug();

        if (resolvedTenantId == null && resolvedTenantSlug == null) {
            throw new AuthError("ssoStart requires tenant context: pass tenantId or tenantSlug, or construct "
                    + "the client with one (CONTRACT.md §5.1).");
        }
        if (resolvedOrgId == null && resolvedOrgSlug == null) {
            throw new AuthError("ssoStart requires organization context: pass orgId or orgSlug, or construct "
                    + "the client with one (CONTRACT.md §5.1).");
        }

        ObjectNode body = MAPPER.createObjectNode();
        body.put("federation_config_id", federationConfigId);
        body.put("redirect_uri", redirectUri);
        if (resolvedTenantId != null) {
            body.put("tenant_id", resolvedTenantId.toString());
        } else {
            body.put("tenant_slug", resolvedTenantSlug);
        }
        if (resolvedOrgId != null) {
            body.put("org_id", resolvedOrgId.toString());
        } else {
            body.put("org_slug", resolvedOrgSlug);
        }

        // port-brief-addendum item 12: the federation start error body shape is
        // undocumented — this falls through to the generic §2 status mapping,
        // never OAuthProtocolError (reserved for /oauth2/* endpoints).
        try (Response response = executeJsonPost(SSO_START_PATH, body)) {
            if (!response.isSuccessful()) {
                throw ErrorMapper.fromHttpStatus(response.code(), "ssoStart request failed", response);
            }
            JsonNode wire = readJson(response);
            return new SsoStartResult(
                    wire.path("authorize_url").asText(),
                    wire.path("state").asText(),
                    wire.path("expires_in_secs").asLong());
        }
    }

    /** {@link #ssoStart(String, String, UUID, String, UUID, String)} defaulting tenant/org context from the client's own configuration.
     *
     * @param federationConfigId UUID of the server-side federation configuration identifying the upstream IdP
     * @param redirectUri        post-login destination, echoed back by {@code ssoComplete}
     * @return the federation start result
     */
    public SsoStartResult ssoStart(String federationConfigId, String redirectUri) {
        return ssoStart(federationConfigId, redirectUri, null, null, null, null);
    }

    /** {@code CompletableFuture} async twin of {@link #ssoStart(String, String)}.
     *
     * @param federationConfigId UUID of the server-side federation configuration identifying the upstream IdP
     * @param redirectUri        post-login destination, echoed back by {@code ssoComplete}
     * @return a future resolving to the federation start result
     */
    public CompletableFuture<SsoStartResult> ssoStartAsync(String federationConfigId, String redirectUri) {
        return CompletableFuture.supplyAsync(() -> ssoStart(federationConfigId, redirectUri));
    }

    @Override
    public SsoCompleteResult ssoComplete(String state, String code) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("state", state);
        body.put("code", code);

        // §4 cookie jar (JavaNetCookieJar, shared with the rest of this client)
        // absorbs the session Set-Cookie automatically, and AuthInterceptor
        // captures the response's X-CSRF-Token exactly as it does for every
        // other response through httpClient — the same post-login cookie-jar/
        // CSRF sync login()/verifyMfa() rely on, with no extra hook needed
        // here (port-brief-addendum item 16).
        try (Response response = executeJsonPost(SSO_CALLBACK_PATH, body)) {
            if (!response.isSuccessful()) {
                throw ErrorMapper.fromHttpStatus(response.code(), "ssoComplete request failed", response);
            }
            JsonNode wire = readJson(response);
            return new SsoCompleteResult(
                    wire.path("user_id").asText(),
                    wire.path("session_id").asText(),
                    wire.path("expires_in").asLong(),
                    wire.path("redirect_uri").asText());
        }
    }

    /** {@code CompletableFuture} async twin of {@link #ssoComplete(String, String)}.
     *
     * @param state the {@code state} value the IdP redirected back with
     * @param code  the authorization code the IdP redirected back with
     * @return a future resolving to the federation completion result
     */
    public CompletableFuture<SsoCompleteResult> ssoCompleteAsync(String state, String code) {
        return CompletableFuture.supplyAsync(() -> ssoComplete(state, code));
    }

    // ------------------------------------------------------------------
    // OIDC internals
    // ------------------------------------------------------------------

    private OidcConfiguration fetchDiscoveryDocument() {
        Request request = new Request.Builder().url(baseUrl + DISCOVERY_PATH).get().build();
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw ErrorMapper.fromHttpStatus(response.code(), "oidc discovery request failed", response);
            }
            return parseDiscoveryDocument(readJson(response));
        } catch (IOException e) {
            throw new NetworkError("oidc discovery request failed: " + e.getMessage(), e);
        }
    }

    private static OidcConfiguration parseDiscoveryDocument(JsonNode wire) {
        return new OidcConfiguration(
                wire.path("issuer").asText(""),
                wire.path("authorization_endpoint").asText(""),
                wire.path("token_endpoint").asText(""),
                wire.path("userinfo_endpoint").asText(""),
                wire.path("jwks_uri").asText(""),
                wire.path("revocation_endpoint").asText(""),
                wire.path("introspection_endpoint").asText(""),
                textList(wire, "response_types_supported"),
                textList(wire, "subject_types_supported"),
                textList(wire, "id_token_signing_alg_values_supported"),
                textList(wire, "scopes_supported"),
                textList(wire, "token_endpoint_auth_methods_supported"),
                textList(wire, "claims_supported"),
                textList(wire, "grant_types_supported"),
                wire.hasNonNull("device_authorization_endpoint")
                        ? wire.get("device_authorization_endpoint").asText() : null,
                wire.hasNonNull("pushed_authorization_request_endpoint")
                        ? wire.get("pushed_authorization_request_endpoint").asText() : null,
                wire.hasNonNull("end_session_endpoint")
                        ? wire.get("end_session_endpoint").asText() : null,
                wire.path("backchannel_logout_supported").asBoolean(false),
                wire.path("backchannel_logout_session_supported").asBoolean(false));
    }

    private static List<String> textList(JsonNode wire, String field) {
        List<String> values = new ArrayList<>();
        for (JsonNode item : wire.path(field)) {
            values.add(item.asText());
        }
        return values;
    }

    /**
     * Normalizes a URL to a discovery-cache key: lowercased scheme and host
     * with the port always explicit (CONTRACT.md &sect;12.3 rule 6).
     */
    private static String normalizeOrigin(String url) {
        URI uri = URI.create(url);
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        int port = uri.getPort();
        String portStr = port != -1
                ? String.valueOf(port)
                : ("https".equals(scheme) ? "443" : "http".equals(scheme) ? "80" : "");
        return scheme + "://" + host + ":" + portStr;
    }

    /**
     * Normalizes the requested scope to a space-separated string that always
     * contains {@code openid} (§12.1 rule 4). Duplicate entries are collapsed.
     */
    private static String normalizeScope(@Nullable String scope) {
        List<String> values = new ArrayList<>();
        if (scope != null) {
            for (String part : scope.trim().split("\\s+")) {
                if (!part.isEmpty()) {
                    values.add(part);
                }
            }
        }
        if (!values.contains("openid")) {
            values.add(0, "openid");
        }
        return String.join(" ", new LinkedHashSet<>(values));
    }

    private String requireOidcClientId() {
        if (oidcClientId == null || oidcClientId.isBlank()) {
            throw new AuthError("this OIDC operation requires Builder.oidcClientId(...) to be configured at "
                    + "AxiamClient construction time (CONTRACT.md §12).");
        }
        return oidcClientId;
    }

    // -----------------------------------------------------------------------
    // §14 Device Authorization Grant (RFC 8628)
    // -----------------------------------------------------------------------

    /** {@code grant_type} of the device access-token request (RFC 8628 §3.4). */
    private static final String DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

    /**
     * Polling interval used when the authorization response omits
     * {@code interval} (RFC 8628 §3.2, §14.2 rule 2). An SDK MUST NOT
     * hard-code a faster floor.
     */
    static final int DEFAULT_DEVICE_POLL_INTERVAL_SECONDS = 5;

    /**
     * Seconds added to the polling interval on each {@code slow_down}
     * (§14.2 rule 1). The increase is permanent and cumulative.
     */
    static final int SLOW_DOWN_INCREMENT_SECONDS = 5;

    @Override
    public DeviceAuthorization deviceAuthorize(@Nullable String scope, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration) {
        OidcConfiguration config = configuration != null ? configuration : oidcDiscover();
        String endpoint = config.device_authorization_endpoint();
        if (endpoint == null || endpoint.isEmpty()) {
            throw new AuthError("the authorization server's discovery document advertises no "
                    + "device_authorization_endpoint: this server does not support the device grant "
                    + "(CONTRACT.md §14.1)");
        }

        // No client_secret, ever: §14.1 makes this operation unauthenticated
        // because a device that cannot show a browser cannot keep a secret.
        FormBody.Builder form = new FormBody.Builder().add("client_id", requireOidcClientId());
        if (scope != null) {
            form.add("scope", scope);
        }

        String url = oauth2Url(endpoint, tenantId);
        try (Response response = executeFormPost(url, form.build())) {
            if (!response.isSuccessful()) {
                throw ErrorMapper.fromOAuth2Response(response.code(), response,
                        "device authorization request failed");
            }
            JsonNode wire = readJson(response);
            int interval = wire.path("interval").asInt(0);
            return new DeviceAuthorization(
                    Sensitive.of(wire.path("device_code").asText()),
                    wire.path("user_code").asText(),
                    wire.path("verification_uri").asText(),
                    wire.hasNonNull("verification_uri_complete")
                            ? wire.get("verification_uri_complete").asText() : null,
                    wire.path("expires_in").asInt(),
                    // §14.2 rule 2: the interval comes from the response; only
                    // its absence falls back to the RFC default. A server-sent
                    // 0 is treated as absent — polling with no delay is never
                    // what the server meant.
                    interval > 0 ? interval : DEFAULT_DEVICE_POLL_INTERVAL_SECONDS);
        }
    }

    /** {@link #deviceAuthorize(String, UUID, OidcConfiguration)} with every optional argument defaulted.
     *
     * @return the code pair the device shows its user
     */
    public DeviceAuthorization deviceAuthorize() {
        return deviceAuthorize(null, null, null);
    }

    @Override
    public OidcTokenSet devicePoll(Sensitive deviceCode, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration) {
        OidcConfiguration config = configuration != null ? configuration : oidcDiscover();
        FormBody form = new FormBody.Builder()
                .add("grant_type", DEVICE_CODE_GRANT_TYPE)
                .add("device_code", deviceCode.expose())
                .add("client_id", requireOidcClientId())
                .build();
        JsonNode wire = postToken(config, form, tenantId);
        // No nonce: the device grant has no authorization request to carry one.
        return buildTokenSet(wire, config, null);
    }

    @Override
    public OidcTokenSet deviceLogin(@Nullable String scope, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration, Consumer<DeviceAuthorization> onUserCode) {
        Objects.requireNonNull(onUserCode, "onUserCode");
        OidcConfiguration config = configuration != null ? configuration : oidcDiscover();
        DeviceAuthorization authorization = deviceAuthorize(scope, tenantId, config);

        // §14.3 rule 2 — before any polling.
        onUserCode.accept(authorization);

        int intervalSeconds = authorization.interval();
        long remainingSeconds = authorization.expiresIn();

        while (true) {
            // §14.2 rule 4: the deadline is authoritative. Checking before
            // sleeping keeps the SDK from issuing a request that can only be
            // refused, and reports it under the same expired_token code the
            // server would have used — so a caller's branch does not care
            // which side noticed first.
            if (intervalSeconds >= remainingSeconds) {
                throw new OAuthProtocolError("expired_token",
                        "the device authorization expired before the user completed it "
                                + "(client-side deadline from expires_in; CONTRACT.md §14.2 rule 4)");
            }
            remainingSeconds -= intervalSeconds;

            try {
                Thread.sleep(Duration.ofSeconds(intervalSeconds));
            } catch (InterruptedException e) {
                // Restore the flag rather than swallowing it: a caller
                // shutting the device down must be able to observe the
                // interrupt, and a swallowed one would leave this loop as the
                // only thing that noticed.
                Thread.currentThread().interrupt();
                throw new NetworkError("device polling was interrupted", e);
            }

            try {
                return devicePoll(authorization.deviceCode(), tenantId, config);
            } catch (OAuthProtocolError e) {
                switch (e.error()) {
                    case "authorization_pending" -> {
                        continue;
                    }
                    case "slow_down" -> {
                        // §14.2 rule 1: cumulative, never reset.
                        intervalSeconds += SLOW_DOWN_INCREMENT_SECONDS;
                        continue;
                    }
                    // expired_token / access_denied / invalid_grant — terminal.
                    default -> throw e;
                }
            } catch (NetworkError e) {
                // §14.2 rule 6: transport and 5xx failures are not among the
                // five protocol answers and are not terminal — a server
                // restart must not lose a grant the user has already approved.
                continue;
            }
        }
    }

    // -----------------------------------------------------------------------
    // §15 Token Exchange (RFC 8693)
    // -----------------------------------------------------------------------

    /** {@code grant_type} of an RFC 8693 exchange. */
    private static final String TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

    @Override
    public ExchangedToken tokenExchange(Sensitive subjectToken,
            String subjectTokenType, @Nullable Sensitive actorToken,
            @Nullable List<String> scopes, @Nullable String audience, @Nullable String resource,
            @Nullable UUID tenantId, @Nullable OidcConfiguration configuration) {
        // §15.1: subjectTokenType is required and has no default. Java cannot
        // demand a non-null argument at compile time, so the demand lands here —
        // client-side, with no wire call, rather than sending …:access_token on
        // the caller's behalf and letting the server refuse a token they never
        // described (§15.7).
        if (subjectTokenType == null || subjectTokenType.isBlank()) {
            throw new AuthError("tokenExchange requires subjectTokenType (§15.1): pass "
                    + "OidcOperations.ACCESS_TOKEN_TYPE for an AXIAM access token, or "
                    + "OidcOperations.JWT_TOKEN_TYPE for a trusted external issuer's JWT");
        }
        OidcConfiguration config = configuration != null ? configuration : oidcDiscover();
        FormBody.Builder form = new FormBody.Builder()
                .add("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
                .add("subject_token", subjectToken.expose())
                // Whatever the caller named, verbatim. The subject token is
                // NEVER decoded to pick this (§15.7): which kind of token the
                // caller holds is the caller's to know, and a guess here is
                // the difference between a request that is refused and one
                // that is silently reinterpreted.
                .add("subject_token_type", subjectTokenType);
        if (actorToken != null) {
            form.add("actor_token", actorToken.expose());
            // Sent exactly when actor_token is: RFC 8693 §2.1 requires the
            // pair, and the type alone is a malformed request.
            form.add("actor_token_type", ACCESS_TOKEN_TYPE);
        }
        if (scopes != null && !scopes.isEmpty()) {
            form.add("scope", String.join(" ", scopes));
        }
        if (audience != null) {
            form.add("audience", audience);
        }
        if (resource != null) {
            form.add("resource", resource);
        }
        form.add("client_id", requireOidcClientId());
        form.add("client_secret", requireOidcClientSecret("tokenExchange"));

        String url = oauth2Url(config.token_endpoint(), tenantId);
        try (Response response = executeFormPost(url, form.build())) {
            if (!response.isSuccessful()) {
                throw ErrorMapper.fromOAuth2Response(response.code(), response,
                        "token exchange request failed");
            }
            JsonNode wire = readJson(response);
            return new ExchangedToken(
                    Sensitive.of(wire.path("access_token").asText()),
                    wire.path("issued_token_type").asText(),
                    wire.path("token_type").asText(),
                    wire.path("expires_in").asInt(),
                    wire.hasNonNull("scope") ? wire.get("scope").asText() : null);
        }
    }

    /** {@link #tokenExchange} with every <em>optional</em> argument defaulted.
     *
     * <p>{@code subjectTokenType} is not among them. It was, through contract
     * 1.12, and this overload took only the subject token — which made it the
     * shortest path to the very default &sect;15.1 removed, since a caller
     * reaching for the convenience form would have had the type chosen for
     * them. It now takes both required arguments and nothing else.
     *
     * @param subjectToken     the token being exchanged
     * @param subjectTokenType what kind of token it is — {@link OidcOperations#ACCESS_TOKEN_TYPE}
     *                         or {@link OidcOperations#JWT_TOKEN_TYPE} (&sect;15.1)
     * @return the issued, narrower token
     */
    public ExchangedToken tokenExchange(Sensitive subjectToken, String subjectTokenType) {
        return tokenExchange(subjectToken, subjectTokenType, null, null, null, null, null, null);
    }

    // -----------------------------------------------------------------------
    // §20 UMA 2.0 — Protection API and ticket grant
    // -----------------------------------------------------------------------

    /** {@code grant_type} of the UMA ticket grant (UMA 2.0 §3.3.1). */
    private static final String UMA_TICKET_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:uma-ticket";

    /** The only {@code claim_token_format} AXIAM v1 accepts (§20.2 rule 2). */
    private static final String UMA_CLAIM_TOKEN_FORMAT = "urn:ietf:params:oauth:token-type:access_token";

    private static final String RREG_PATH = "/uma2/rreg/resource_set";

    @Override
    public ResourceSet umaRegisterResource(Sensitive pat, ResourceSet resource) {
        JsonNode wire = umaProtectionJson("POST", RREG_PATH, pat, umaResourcePayload(resource),
                "uma resource registration failed");
        return resourceSetFromWire(wire);
    }

    @Override
    public ResourceSet umaReadResource(Sensitive pat, UUID resourceId) {
        JsonNode wire = umaProtectionJson("GET", RREG_PATH + "/" + resourceId, pat, null,
                "uma resource read failed");
        return resourceSetFromWire(wire);
    }

    @Override
    public ResourceSet umaUpdateResource(Sensitive pat, UUID resourceId, ResourceSet resource) {
        JsonNode wire = umaProtectionJson("PUT", RREG_PATH + "/" + resourceId, pat,
                umaResourcePayload(resource), "uma resource update failed");
        return resourceSetFromWire(wire);
    }

    @Override
    public void umaDeleteResource(Sensitive pat, UUID resourceId) {
        umaProtectionJson("DELETE", RREG_PATH + "/" + resourceId, pat, null,
                "uma resource delete failed");
    }

    @Override
    public List<UUID> umaListResources(Sensitive pat) {
        JsonNode wire = umaProtectionJson("GET", RREG_PATH, pat, null, "uma resource list failed");
        List<UUID> ids = new ArrayList<>();
        if (wire != null && wire.isArray()) {
            for (JsonNode id : wire) {
                ids.add(UUID.fromString(id.asText()));
            }
        }
        return List.copyOf(ids);
    }

    @Override
    public Sensitive umaRequestTicket(Sensitive pat, List<RequestedPermission> permissions) {
        ArrayNode body = MAPPER.createArrayNode();
        for (RequestedPermission permission : permissions) {
            ObjectNode entry = body.addObject();
            entry.put("resource_id", permission.resourceId().toString());
            ArrayNode scopes = entry.putArray("resource_scopes");
            permission.resourceScopes().forEach(scopes::add);
        }
        JsonNode wire = umaProtectionJson("POST", "/uma2/perm", pat, body,
                "uma ticket request failed");
        return Sensitive.of(wire.path("ticket").asText());
    }

    @Override
    public RequestingPartyToken umaExchangeTicket(Sensitive ticket, Sensitive claimToken,
            @Nullable UUID tenantId, @Nullable OidcConfiguration configuration) {
        OidcConfiguration config = configuration != null ? configuration : oidcDiscover();
        FormBody.Builder form = new FormBody.Builder()
                .add("grant_type", UMA_TICKET_GRANT_TYPE)
                .add("ticket", ticket.expose())
                .add("claim_token", claimToken.expose())
                .add("claim_token_format", UMA_CLAIM_TOKEN_FORMAT)
                .add("client_id", requireOidcClientId())
                .add("client_secret", requireOidcClientSecret("umaExchangeTicket"));

        String url = oauth2Url(config.token_endpoint(), tenantId);
        // One POST, no retry wrapper. See the interface's rule-6 note — this is
        // the §16 exception, and it is load-bearing rather than stylistic.
        try (Response response = executeFormPost(url, form.build())) {
            if (!response.isSuccessful()) {
                throw mapUmaGrantError(response, "uma ticket exchange request failed");
            }
            JsonNode wire = readJson(response);
            return new RequestingPartyToken(
                    Sensitive.of(wire.path("access_token").asText()),
                    wire.path("token_type").asText(),
                    wire.path("expires_in").asInt());
        }
    }

    /**
     * Maps an error from the <strong>uma-ticket grant</strong>, where
     * {@code access_denied} arrives as HTTP <strong>403</strong> (UMA 2.0
     * §3.3.6) rather than the 400 every other OAuth2 error uses.
     *
     * <p>§20.4 requires dispatching on the {@code error} field rather than the
     * status, so the code reaches the caller whichever status carries it. This
     * is kept local to the ticket grant on purpose:
     * {@link ErrorMapper#fromOAuth2Response} applies the OAuth2 mapping to
     * 400/401 only, and widening that globally would change how every OAuth2
     * endpoint's 403 is reported — a cross-cutting change this grant does not
     * need and did not ask for. An ordinary REST 403 keeps mapping to
     * {@code AuthzError}.
     */
    private static RuntimeException mapUmaGrantError(Response response, String fallbackMessage) {
        if (response.code() == 403 && response.body() != null) {
            try {
                String body = response.peekBody(8192).string();
                if (!body.isBlank()) {
                    JsonNode root = MAPPER.readTree(body);
                    if (root.hasNonNull("error") && root.get("error").isTextual()) {
                        String description = root.hasNonNull("error_description")
                                ? root.get("error_description").asText()
                                : fallbackMessage;
                        return new OAuthProtocolError(root.get("error").asText(), description);
                    }
                }
            } catch (IOException | RuntimeException ignored) {
                // Malformed/non-JSON body: fall through rather than let a parse
                // failure mask the real status.
            }
        }
        return ErrorMapper.fromOAuth2Response(response.code(), response, fallbackMessage);
    }

    /**
     * The wire body for a register/update.
     *
     * <p>{@code resource_scopes} is always sent, even when empty: an update
     * <strong>replaces</strong> the scope list, and omitting the key would
     * leave the server's copy untouched (§20.2 rule 8).
     */
    private static ObjectNode umaResourcePayload(ResourceSet resource) {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("name", resource.name());
        if (resource.type() != null) {
            body.put("type", resource.type());
        }
        ArrayNode scopes = body.putArray("resource_scopes");
        resource.resourceScopes().forEach(scopes::add);
        return body;
    }

    private static ResourceSet resourceSetFromWire(JsonNode wire) {
        List<String> scopes = new ArrayList<>();
        for (JsonNode scope : wire.path("resource_scopes")) {
            scopes.add(scope.asText());
        }
        return new ResourceSet(
                wire.hasNonNull("_id") ? UUID.fromString(wire.get("_id").asText()) : null,
                wire.path("name").asText(),
                wire.hasNonNull("type") ? wire.get("type").asText() : null,
                List.copyOf(scopes));
    }

    /**
     * A PAT-authenticated Protection API request.
     *
     * <p>The PAT goes in {@code Authorization}. It is an explicit argument on
     * every Protection API call rather than this client's own session, because
     * a PAT must be a <strong>client-credentials</strong> token — a ticket
     * binds to the {@code client_id} that minted it — and this client's session
     * is usually a <em>user</em> session (§20.2 rule 1).
     */
    private @Nullable JsonNode umaProtectionJson(String method, String path, Sensitive pat,
            @Nullable JsonNode body, String fallbackMessage) {
        RequestBody payload = null;
        if (body != null) {
            try {
                payload = RequestBody.create(MAPPER.writeValueAsBytes(body), JSON);
            } catch (IOException e) {
                throw new NetworkError("failed to encode request: " + e.getMessage(), e);
            }
        }
        Request request = new Request.Builder()
                .url(baseUrl + path)
                .header("Authorization", "Bearer " + pat.expose())
                .method(method, payload)
                .build();
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw ErrorMapper.fromOAuth2Response(response.code(), response, fallbackMessage);
            }
            if (response.code() == 204) {
                return null;
            }
            return readJson(response);
        } catch (IOException e) {
            throw new NetworkError(fallbackMessage + ": " + e.getMessage(), e);
        }
    }

    // -----------------------------------------------------------------------
    // §12.7 Logout helpers
    // -----------------------------------------------------------------------

    /**
     * The {@code events} member that distinguishes a logout token from an ID
     * token (OIDC Back-Channel Logout 1.0 §2.4).
     */
    private static final String BACKCHANNEL_LOGOUT_EVENT =
            "http://schemas.openid.net/event/backchannel-logout";

    /**
     * Maximum accepted age for a logout token's {@code iat}, in seconds.
     * AXIAM issues them with a 120 s lifetime; this bound is the same order
     * and stops a token captured from a mis-configured RP being replayed days
     * later.
     */
    private static final long MAX_LOGOUT_TOKEN_AGE_SECONDS = 300L;

    @Override
    public String logoutUrl(Sensitive idToken, @Nullable String postLogoutRedirectUri,
            @Nullable String state, @Nullable OidcConfiguration configuration) {
        OidcConfiguration config = configuration != null ? configuration : oidcDiscover();
        String endpoint = config.end_session_endpoint();
        if (endpoint == null || endpoint.isEmpty()) {
            throw new AuthError("the authorization server's discovery document advertises no "
                    + "end_session_endpoint: this server does not support RP-initiated logout "
                    + "(CONTRACT.md §12.7.2 rule 1)");
        }
        HttpUrl url = HttpUrl.parse(endpoint);
        if (url == null) {
            throw new NetworkError("end_session_endpoint is not a valid URL");
        }
        HttpUrl.Builder builder = url.newBuilder().addQueryParameter("id_token_hint", idToken.expose());
        if (postLogoutRedirectUri != null) {
            builder.addQueryParameter("post_logout_redirect_uri", postLogoutRedirectUri);
        }
        if (state != null) {
            builder.addQueryParameter("state", state);
        }
        return builder.build().toString();
    }

    /** {@link #logoutUrl} with every optional argument defaulted.
     *
     * @param idToken a previously-issued ID token for {@code id_token_hint}
     * @return the absolute logout URL
     */
    public String logoutUrl(Sensitive idToken) {
        return logoutUrl(idToken, null, null, null);
    }

    @Override
    public VerifiedLogoutToken verifyLogoutToken(String logoutToken,
            @Nullable OidcConfiguration configuration) {
        OidcConfiguration config = configuration != null ? configuration : oidcDiscover();

        // Same JWKS path — and therefore the same EdDSA pinning and
        // kid-required discipline — as §12.4. No second key-fetching route.
        JWTClaimsSet claims = oidcJwksVerifierFor(config.jwks_uri()).verifyForOidc(logoutToken);

        if (!config.issuer().equals(claims.getIssuer())) {
            throw new AuthError("logout token issuer does not match the discovery document");
        }
        List<String> audiences = claims.getAudience();
        if (audiences == null || !audiences.contains(requireOidcClientId())) {
            throw new AuthError("logout token audience does not match this client_id");
        }

        // Without this check the whole method is an elaborate way to accept an
        // ID token.
        Object events = claims.getClaim("events");
        if (!(events instanceof Map<?, ?> eventMap)
                || !(eventMap.get(BACKCHANNEL_LOGOUT_EVENT) instanceof Map<?, ?>)) {
            throw new AuthError("not a logout token: the events claim does not carry "
                    + BACKCHANNEL_LOGOUT_EVENT);
        }

        if (claims.getClaim("nonce") != null) {
            throw new AuthError("logout token carries a nonce, which Back-Channel Logout 1.0 §2.4 "
                    + "forbids: this is an ID token being replayed as a logout token");
        }

        String sid = claims.getClaim("sid") instanceof String s ? s : null;
        String sub = claims.getSubject();
        if (sid == null && sub == null) {
            throw new AuthError("logout token names neither sid nor sub, so it identifies no session");
        }

        long nowSec = System.currentTimeMillis() / 1000L;
        long skew = oidcClockSkewSec != null ? oidcClockSkewSec : 0L;
        Date exp = claims.getExpirationTime();
        Date iat = claims.getIssueTime();
        if (exp == null || (exp.getTime() / 1000L) + skew < nowSec) {
            throw new AuthError("logout token has expired");
        }
        if (iat == null || (iat.getTime() / 1000L) - skew > nowSec) {
            throw new AuthError("logout token was issued in the future");
        }
        if (nowSec - (iat.getTime() / 1000L) > MAX_LOGOUT_TOKEN_AGE_SECONDS + skew) {
            throw new AuthError("logout token is too old to be a live delivery");
        }

        String jti = claims.getJWTID();
        if (jti == null || jti.isEmpty()) {
            throw new AuthError("logout token carries no jti, so the RP cannot dedup redeliveries");
        }

        return new VerifiedLogoutToken(sid, sub, jti);
    }

    private String requireOidcClientSecret(String operation) {
        if (oidcClientSecret == null) {
            throw new AuthError(operation + " requires confidential-client credentials: construct the client "
                    + "with Builder.oidcClientSecret(...) (CONTRACT.md §12.1 note 4).");
        }
        return oidcClientSecret.expose();
    }

    /** Adds {@code client_secret} to a form body for a confidential client, and omits it
     * entirely for a public client — §12.1 forbids sending an empty/null value for an
     * absent optional field. */
    private void appendOidcClientSecret(FormBody.Builder form) {
        if (oidcClientSecret != null) {
            form.add("client_secret", oidcClientSecret.expose());
        }
    }

    /**
     * Resolves the tenant UUID for the {@code /oauth2/*} {@code tenant_id}
     * query parameter (CONTRACT.md &sect;12.3 rule 4): the explicit argument,
     * else the client's configured tenant identifier when it is itself
     * UUID-shaped. A slug-only client without an explicit UUID raises the
     * taxonomy error client-side, with no wire call.
     */
    private UUID resolveOauth2TenantId(@Nullable UUID explicit) {
        if (explicit != null) {
            return explicit;
        }
        if (UUID_PATTERN.matcher(tenantId).matches()) {
            return UUID.fromString(tenantId);
        }
        throw new AuthError("this operation requires a tenant_id UUID for the /oauth2 query parameter: pass "
                + "tenantId explicitly, or construct the client with the tenantId UUID form (CONTRACT.md §12.3 rule 4).");
    }

    /** Builds the final endpoint URL: the discovery document's endpoint plus the
     * mandatory {@code ?tenant_id=<uuid>} query parameter (§12.1 note 2), RFC
     * 3986-percent-encoded via {@link HttpUrl} (space becomes {@code %20}, not
     * {@code +}). Existing query parameters on the endpoint are preserved. */
    private String oauth2Url(String endpoint, @Nullable UUID tenantId) {
        HttpUrl url = HttpUrl.parse(endpoint);
        if (url == null) {
            throw new NetworkError("discovery document endpoint is not a valid URL: " + endpoint);
        }
        return url.newBuilder().addQueryParameter("tenant_id", resolveOauth2TenantId(tenantId).toString()).build().toString();
    }

    private JsonNode postToken(OidcConfiguration configuration, RequestBody form, @Nullable UUID tenantId) {
        String url = oauth2Url(configuration.token_endpoint(), tenantId);
        try (Response response = executeFormPost(url, form)) {
            if (!response.isSuccessful()) {
                throw ErrorMapper.fromOAuth2Response(response.code(), response, "token request failed");
            }
            return readJson(response);
        }
    }

    private Response executeFormPost(String url, RequestBody form) {
        Request request = new Request.Builder().url(url).post(form).build();
        try {
            return httpClient.newCall(request).execute();
        } catch (IOException e) {
            throw new NetworkError("request failed: " + e.getMessage(), e);
        }
    }

    /**
     * Converts a raw {@code TokenResponse} JSON body into an {@link OidcTokenSet},
     * validating any {@code id_token} first (§12.4). Validation precedes
     * construction, so a failure discards the whole set — the caller never sees
     * the access or refresh token from a response whose ID token was rejected
     * (§12.4 rule 7).
     */
    private OidcTokenSet buildTokenSet(JsonNode wire, OidcConfiguration configuration, @Nullable String nonce) {
        String idTokenRaw = wire.hasNonNull("id_token") ? wire.get("id_token").asText() : null;
        IdTokenClaims idClaims = null;
        if (idTokenRaw != null) {
            JwksVerifier verifier = oidcJwksVerifierFor(configuration.jwks_uri());
            idClaims = IdTokenValidator.validate(
                    verifier, idTokenRaw, configuration.issuer(), requireOidcClientId(), nonce, oidcClockSkewSec);
        }

        String accessToken = wire.path("access_token").asText();
        String tokenType = wire.path("token_type").asText();
        long expiresIn = wire.path("expires_in").asLong();
        String scope = wire.hasNonNull("scope") ? wire.get("scope").asText() : null;
        String refreshTokenRaw = wire.hasNonNull("refresh_token") ? wire.get("refresh_token").asText() : null;

        return new OidcTokenSet(
                Sensitive.of(accessToken),
                tokenType,
                expiresIn,
                scope,
                refreshTokenRaw != null ? Sensitive.of(refreshTokenRaw) : null,
                idTokenRaw != null ? Sensitive.of(idTokenRaw) : null,
                idClaims);
    }

    /** Lazily builds (and reuses) the JWKS verifier for a {@code jwks_uri} (§12.3 rule 6) —
     * one verifier per URI, never process-global, and never re-derived from {@code baseUrl}. */
    private JwksVerifier oidcJwksVerifierFor(String jwksUri) {
        return oidcJwksVerifiers.computeIfAbsent(jwksUri, JwksVerifier::forJwksUri);
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
    // §26 Pushed Authorization Requests (RFC 9126)
    // ------------------------------------------------------------------

    /**
     * {@code POST /oauth2/par} (CONTRACT.md &sect;26.1) — push the authorization
     * request over the back channel and get an opaque handle to redirect with.
     *
     * <p>PAR moves the authorization request off the browser. Instead of
     * putting {@code scope}, {@code redirect_uri}, {@code state} and the PKCE
     * challenge into a URL the user agent carries, the client POSTs them
     * straight to AXIAM over an authenticated channel and puts an opaque
     * {@code request_uri} in the redirect. What travels through the browser is
     * then a random string that cannot be edited into meaning something else.
     *
     * <p><strong>Required for a FAPI 2.0 client</strong>: {@code profile:
     * "fapi2"} refuses a registration that does not set {@code require_par}, so
     * such a client cannot authorize any other way (&sect;21.1).
     *
     * <p>Not retried on a {@code 5xx} or a transport failure — it is a POST
     * that creates server state, so it falls outside &sect;16.2's read-only
     * eligibility exactly as {@code oidcExchange} does. The safe recovery is a
     * fresh push, which costs one round trip and cannot double-consume anything
     * (&sect;26.2 rule 4).
     *
     * @param configuration the discovery document, or {@code null} to discover
     * @param request       what {@code oidcBegin} returned
     * @param redirectUri   the same redirect URI that will be sent at exchange
     * @param scope         the requested scope; {@code openid} is added when absent
     * @param tenantId      a tenant override for the {@code ?tenant_id=} query parameter
     * @return the opaque handle and the URL to redirect the browser to
     */
    public PushedAuthorizationRequest oidcPar(@Nullable OidcConfiguration configuration,
            AuthorizationRequest request, String redirectUri, @Nullable String scope,
            @Nullable UUID tenantId) {
        ensureOpen();
        OidcConfiguration config = configuration != null ? configuration : oidcDiscover();
        String endpoint = config.pushed_authorization_request_endpoint();
        if (endpoint == null || endpoint.isEmpty()) {
            throw new AuthError("the authorization server's discovery document advertises no "
                    + "pushed_authorization_request_endpoint: this server does not support RFC 9126 "
                    + "(CONTRACT.md §26.1)");
        }

        // §26.2 rule 1: everything below was computed by oidcBegin. There is no
        // second generator here, and there must not be — two sources for state
        // or the PKCE pair are two things that can disagree.
        FormBody.Builder form = new FormBody.Builder()
                .add("client_id", requireOidcClientId())
                .add("response_type", "code")
                .add("redirect_uri", redirectUri)
                .add("scope", normalizeScope(scope))
                .add("state", request.state())
                .add("nonce", request.nonce())
                .add("code_challenge", OidcPkce.computeCodeChallenge(request.codeVerifier().expose()))
                .add("code_challenge_method", OidcPkce.CODE_CHALLENGE_METHOD_S256);
        if (oidcClientSecret != null) {
            form.add("client_secret", oidcClientSecret.expose());
        }

        String url = oauth2Url(endpoint, tenantId);
        JsonNode wire;
        // 201, not 200. RFC 9126 §2.2 specifies Created, and this is the one
        // thing an implementation of this section gets wrong: a success
        // predicate written == 200 treats every successful push as a failure
        // while passing every other assertion.
        try (Response response = executeFormPost(url, form.build())) {
            if (!response.isSuccessful()) {
                throw ErrorMapper.fromOAuth2Response(
                        response.code(), response, "pushed authorization request failed");
            }
            wire = readJson(response);
        }
        String requestUri = wire.path("request_uri").asText();

        // §26.2 rule 2: exactly two query parameters. The server REFUSES a
        // request carrying both a request_uri and any inline authorization
        // parameter rather than merging them: an attacker supplies the inline
        // value they want and lets the pushed copy satisfy whichever check
        // reads the other one. Re-adding them "for compatibility" restores the
        // attack.
        HttpUrl authorizationEndpoint = HttpUrl.parse(config.authorization_endpoint());
        if (authorizationEndpoint == null) {
            throw new NetworkError("discovery document authorization_endpoint is not a valid URL: "
                    + config.authorization_endpoint());
        }
        String authorizationUrl = authorizationEndpoint.newBuilder()
                .query(null)
                .addQueryParameter("client_id", requireOidcClientId())
                .addQueryParameter("request_uri", requestUri)
                .build()
                .toString();

        return new PushedAuthorizationRequest(
                authorizationUrl,
                Sensitive.of(requestUri),
                wire.path("expires_in").asLong(),
                request.state(),
                request.nonce(),
                request.codeVerifier());
    }

    /** {@code CompletableFuture} async twin of {@link #oidcPar}.
     *
     * @param configuration the discovery document, or {@code null} to discover
     * @param request       what {@code oidcBegin} returned
     * @param redirectUri   the same redirect URI that will be sent at exchange
     * @param scope         the requested scope
     * @param tenantId      a tenant override for the query parameter
     * @return a future resolving to the pushed request
     */
    public CompletableFuture<PushedAuthorizationRequest> oidcParAsync(
            @Nullable OidcConfiguration configuration, AuthorizationRequest request,
            String redirectUri, @Nullable String scope, @Nullable UUID tenantId) {
        return CompletableFuture.supplyAsync(
                () -> oidcPar(configuration, request, redirectUri, scope, tenantId));
    }

    // ------------------------------------------------------------------
    // §24 WebAuthn / passkeys — the relying-party layer
    //
    // The JVM has no authenticator, so §24.6b's linked-API helper is
    // deliberately absent: §24.6b rule 2 forbids emulating one in software,
    // and a "credential" held in process memory is not a second factor. What
    // is here is the half that talks to AXIAM, plus §24.6a's JSON bridge —
    // which is what lets an Android app pass requestJson straight into
    // CreatePublicKeyCredentialRequest and the response straight back.
    // ------------------------------------------------------------------

    /**
     * {@code POST /api/v1/auth/webauthn/register/start} (CONTRACT.md &sect;24.1).
     *
     * <p>Enrolling a passkey is something a signed-in user does to their own
     * account, so this requires a session and fails <strong>client-side with no
     * wire call</strong> when there is none.
     *
     * <p>A {@code 503} means the tenant's attestation policy requires
     * attestation and the FIDO metadata service has no usable snapshot. That is
     * a server configuration state, not a transient failure, so &sect;24.4
     * rule 2 deliberately does not retry it.
     *
     * @return the server's challenge and the state token binding a response to it
     */
    public WebauthnChallenge webauthnRegisterStart() {
        ensureOpen();
        requireWebauthnSession("webauthnRegisterStart");
        return webauthnStart(WEBAUTHN_REGISTER_START_PATH, MAPPER.createObjectNode());
    }

    /** {@code CompletableFuture} async twin of {@link #webauthnRegisterStart}.
     *
     * @return a future resolving to the challenge
     */
    public CompletableFuture<WebauthnChallenge> webauthnRegisterStartAsync() {
        return CompletableFuture.supplyAsync(this::webauthnRegisterStart);
    }

    /**
     * {@code POST /api/v1/auth/webauthn/register/finish} (CONTRACT.md &sect;24.1).
     *
     * <p>{@code response} is the authenticator's answer — pass the platform's
     * own JSON string (&sect;24.6a rule 2): Android's
     * {@code registrationResponseJson}, a browser's {@code credential.toJSON()}.
     * It reaches the server unchanged, because it is the input to a signature
     * check over bytes this SDK did not produce.
     *
     * <p>A {@code 403} is the tenant's attestation policy refusing
     * <strong>this authenticator</strong> — an AAGUID that is not allow-listed,
     * a missing FIDO certification, a revoked status — not a permission problem
     * with the user. The server's message is surfaced verbatim (&sect;24.4
     * rule 1), because it is the only way the person holding the key learns a
     * different one would work.
     *
     * @param stateToken     the token from {@link #webauthnRegisterStart}
     * @param credentialName the label to store the credential under
     * @param response       the authenticator's response JSON, verbatim
     * @return the credential just enrolled
     */
    public WebauthnCredential webauthnRegisterFinish(
            Sensitive stateToken, String credentialName, String response) {
        ensureOpen();
        requireWebauthnSession("webauthnRegisterFinish");

        ObjectNode body = MAPPER.createObjectNode();
        body.put("state_token", stateToken.expose());
        body.put("credential_name", credentialName);
        body.set("response", parseAuthenticatorResponse(response, "webauthnRegisterFinish"));

        try (Response http = executeJsonPost(WEBAUTHN_REGISTER_FINISH_PATH, body)) {
            if (http.code() != 200 && http.code() != 201) {
                throw registerFinishError(http);
            }
            JsonNode wire = readJson(http);
            String lastUsed = wire.path("last_used_at").asText("");
            return new WebauthnCredential(
                    UUID.fromString(wire.path("id").asText()),
                    wire.path("credential_id").asText(),
                    wire.path("name").asText(),
                    wire.path("credential_type").asText(),
                    wire.path("created_at").asText(),
                    lastUsed.isEmpty() ? null : lastUsed);
        }
    }

    /** {@code CompletableFuture} async twin of {@link #webauthnRegisterFinish}.
     *
     * @param stateToken     the token from {@link #webauthnRegisterStart}
     * @param credentialName the label to store the credential under
     * @param response       the authenticator's response JSON, verbatim
     * @return a future resolving to the enrolled credential
     */
    public CompletableFuture<WebauthnCredential> webauthnRegisterFinishAsync(
            Sensitive stateToken, String credentialName, String response) {
        return CompletableFuture.supplyAsync(
                () -> webauthnRegisterFinish(stateToken, credentialName, response));
    }

    /**
     * {@code POST /api/v1/auth/webauthn/authenticate/start} (CONTRACT.md &sect;24.1).
     *
     * <p>The <strong>second-factor</strong> ceremony: it continues a
     * {@link #login} that answered {@code mfaRequired} with {@code "webauthn"}
     * among its methods, and {@code challengeToken} is that result's token.
     *
     * <p>A different flow from {@link #webauthnDiscoverableStart}, not the same
     * one with an optional argument — see &sect;24.2 for why they cannot be
     * merged.
     *
     * @param challengeToken the MFA challenge token from {@link #login}
     * @return the server's challenge and its state token
     */
    public WebauthnChallenge webauthnAuthenticateStart(Sensitive challengeToken) {
        ensureOpen();
        ObjectNode body = MAPPER.createObjectNode();
        body.put("challenge_token", challengeToken.expose());
        return webauthnStart(WEBAUTHN_AUTH_START_PATH, body);
    }

    /** {@code CompletableFuture} async twin of {@link #webauthnAuthenticateStart}.
     *
     * @param challengeToken the MFA challenge token from {@link #login}
     * @return a future resolving to the challenge
     */
    public CompletableFuture<WebauthnChallenge> webauthnAuthenticateStartAsync(Sensitive challengeToken) {
        return CompletableFuture.supplyAsync(() -> webauthnAuthenticateStart(challengeToken));
    }

    /**
     * {@code POST /api/v1/auth/webauthn/authenticate/finish} (CONTRACT.md &sect;24.1).
     *
     * <p>Leaves this client authenticated (&sect;24.3 rule 1). That is not
     * &sect;14.3's "MAY adopt" posture: {@code deviceLogin} mints tokens a
     * caller may want to route elsewhere, and this is the SDK's own primary
     * authentication — returning a token set without adopting it would make a
     * passkey sign-in the one way to log in that does not log you in.
     *
     * @param stateToken the token from {@link #webauthnAuthenticateStart}
     * @param response   the authenticator's response JSON, verbatim
     * @return the token set, with the session already adopted
     */
    public WebauthnLoginResult webauthnAuthenticateFinish(Sensitive stateToken, String response) {
        return webauthnFinish(WEBAUTHN_AUTH_FINISH_PATH, stateToken, response, "webauthnAuthenticateFinish");
    }

    /** {@code CompletableFuture} async twin of {@link #webauthnAuthenticateFinish}.
     *
     * @param stateToken the token from {@link #webauthnAuthenticateStart}
     * @param response   the authenticator's response JSON, verbatim
     * @return a future resolving to the token set
     */
    public CompletableFuture<WebauthnLoginResult> webauthnAuthenticateFinishAsync(
            Sensitive stateToken, String response) {
        return CompletableFuture.supplyAsync(() -> webauthnAuthenticateFinish(stateToken, response));
    }

    /**
     * {@code POST /api/v1/auth/webauthn/authenticate/discoverable/start}
     * (CONTRACT.md &sect;24.1).
     *
     * <p>The <strong>primary-factor</strong> ceremony: nothing precedes it, the
     * server sends an empty {@code allowCredentials}, and the assertion itself
     * identifies the user.
     *
     * <p>The workspace still has to be named — a discoverable credential is
     * resolved inside one tenant's isolation boundary — but it comes from this
     * client's own configuration unless overridden, and slugs are accepted.
     *
     * @param workspace an override, or {@code null} for the configured workspace
     * @return the server's challenge and its state token
     */
    public WebauthnChallenge webauthnDiscoverableStart(@Nullable WebauthnWorkspace workspace) {
        ensureOpen();
        return webauthnStart(WEBAUTHN_DISCOVERABLE_START_PATH, webauthnWorkspaceBody(workspace));
    }

    /** {@code CompletableFuture} async twin of {@link #webauthnDiscoverableStart}.
     *
     * @param workspace an override, or {@code null} for the configured workspace
     * @return a future resolving to the challenge
     */
    public CompletableFuture<WebauthnChallenge> webauthnDiscoverableStartAsync(
            @Nullable WebauthnWorkspace workspace) {
        return CompletableFuture.supplyAsync(() -> webauthnDiscoverableStart(workspace));
    }

    /**
     * {@code POST /api/v1/auth/webauthn/authenticate/discoverable/finish}
     * (CONTRACT.md &sect;24.1).
     *
     * <p>Leaves this client authenticated (&sect;24.3). Unlike its
     * username-bound twin, this fires the server's {@code login.post_auth}
     * reactor hook (&sect;22.5): there was no password step for the event to
     * have been fired at.
     *
     * @param stateToken the token from {@link #webauthnDiscoverableStart}
     * @param response   the authenticator's response JSON, verbatim
     * @return the token set, with the session already adopted
     */
    public WebauthnLoginResult webauthnDiscoverableFinish(Sensitive stateToken, String response) {
        return webauthnFinish(
                WEBAUTHN_DISCOVERABLE_FINISH_PATH, stateToken, response, "webauthnDiscoverableFinish");
    }

    /** {@code CompletableFuture} async twin of {@link #webauthnDiscoverableFinish}.
     *
     * @param stateToken the token from {@link #webauthnDiscoverableStart}
     * @param response   the authenticator's response JSON, verbatim
     * @return a future resolving to the token set
     */
    public CompletableFuture<WebauthnLoginResult> webauthnDiscoverableFinishAsync(
            Sensitive stateToken, String response) {
        return CompletableFuture.supplyAsync(() -> webauthnDiscoverableFinish(stateToken, response));
    }

    /**
     * &sect;24.4 rule 1: the {@code 403} from {@code register/finish} is the
     * one whose <em>body</em> matters.
     *
     * <p>The generic &sect;2 mapping would raise an {@link AuthzError} reading
     * "webauthnRegisterFinish failed", which tells the person holding the key
     * nothing they can act on. The tenant's attestation policy rejected
     * <em>this</em> authenticator, and the server's message is the only place
     * that says which one would be accepted, so it is lifted into the
     * exception message.
     *
     * <p>Only the named {@code message} field is read — the rest of the body
     * is still discarded, exactly as {@link ErrorMapper}'s
     * {@code action}/{@code resource_id} peek does.
     */
    private static RuntimeException registerFinishError(Response http) {
        String message = "webauthnRegisterFinish failed";
        if (http.code() == 403) {
            try {
                JsonNode body = MAPPER.readTree(http.peekBody(MAX_POLICY_MESSAGE_PEEK_BYTES).string());
                String policy = body.path("message").asText("");
                if (!policy.isEmpty()) {
                    message = message + ": " + policy;
                }
            } catch (IOException | RuntimeException ignored) {
                // A malformed body must not mask the 403 itself.
            }
        }
        return ErrorMapper.fromHttpStatus(http.code(), message, http);
    }

    /** Run either {@code *_start} call and return the options untouched. */
    private WebauthnChallenge webauthnStart(String path, ObjectNode body) {
        try (Response http = executeJsonPost(path, body)) {
            if (http.code() != 200) {
                throw ErrorMapper.fromHttpStatus(http.code(), "webauthn start failed", http);
            }
            JsonNode wire = readJson(http);
            return new WebauthnChallenge(
                    wire.path("challenge"), Sensitive.of(wire.path("state_token").asText()));
        }
    }

    /** The shared tail of both authentication ceremonies. */
    private WebauthnLoginResult webauthnFinish(
            String path, Sensitive stateToken, String response, String operation) {
        ensureOpen();
        // §17.1 rule 9 / §24.3 rule 4: memo entries are keyed by subject, and
        // this call changes the subject.
        onCredentialChange();

        ObjectNode body = MAPPER.createObjectNode();
        body.put("state_token", stateToken.expose());
        body.set("response", parseAuthenticatorResponse(response, operation));

        try (Response http = executeJsonPost(path, body)) {
            if (http.code() != 200) {
                throw ErrorMapper.fromHttpStatus(http.code(), operation + " failed", http);
            }
            JsonNode wire = readJson(http);
            return new WebauthnLoginResult(
                    Sensitive.of(wire.path("access_token").asText()),
                    Sensitive.of(wire.path("refresh_token").asText()),
                    UUID.fromString(wire.path("session_id").asText()),
                    wire.path("expires_in").asLong());
        }
    }

    /**
     * &sect;24.1: {@code register/*} needs a session, and the refusal is raised
     * client-side with <strong>no wire call</strong> — the shape &sect;1.1
     * rule 3 requires of {@code getUserInfo}.
     *
     * <p>The signal is the cached access token rather than a separate flag:
     * this SDK has never kept one, and a second source of truth for "am I
     * signed in" is a second thing to get out of step with the jar.
     */
    private void requireWebauthnSession(String operation) {
        if (session.cachedAccessToken() == null) {
            throw new AuthError(operation
                    + " requires an authenticated session: enrol a passkey while signed in "
                    + "(CONTRACT.md §24.1)");
        }
    }

    /**
     * Accept the platform's own JSON string (&sect;24.6a rule 2).
     *
     * <p>Android's Credential Manager hands back
     * {@code registrationResponseJson} / {@code authenticationResponseJson},
     * and a browser hands back {@code credential.toJSON()}. Making a caller
     * model one of those as a Java type this SDK immediately re-serializes is
     * three chances to corrupt a signed buffer in service of nothing — so the
     * string is parsed straight into the tree that goes on the wire.
     */
    private static JsonNode parseAuthenticatorResponse(String response, String operation) {
        JsonNode parsed;
        try {
            parsed = MAPPER.readTree(response);
        } catch (IOException e) {
            throw new AuthError(operation
                    + ": the authenticator response string is not valid JSON. Pass the platform's "
                    + "response JSON verbatim (CONTRACT.md §24.6a)");
        }
        if (!parsed.isObject()) {
            throw new AuthError(operation
                    + ": the authenticator response must be a JSON object (CONTRACT.md §24.6a)");
        }
        return parsed;
    }

    /**
     * Fill the discoverable ceremony's workspace from this client's own
     * configuration when the caller passed none.
     *
     * <p>Only fields that actually have a value are emitted: the server takes
     * either form at either level, and sending {@code null} for the ones it
     * does not have is indistinguishable from asking it to resolve nothing.
     */
    private ObjectNode webauthnWorkspaceBody(@Nullable WebauthnWorkspace workspace) {
        ObjectNode body = MAPPER.createObjectNode();

        UUID orgId = workspace == null ? null : workspace.orgId();
        String orgSlug = workspace == null ? null : workspace.orgSlug();
        if (orgId == null && orgSlug == null) {
            orgId = session.configuredOrgId();
            orgSlug = session.configuredOrgSlug();
        }
        if (orgId != null) {
            body.put("org_id", orgId.toString());
        } else if (orgSlug != null) {
            body.put("org_slug", orgSlug);
        } else {
            throw new AuthError("webauthnDiscoverableStart needs an organization: construct the "
                    + "client with one, or pass it in the workspace argument (CONTRACT.md §24.1)");
        }

        UUID tenantUuid = workspace == null ? null : workspace.tenantId();
        String tenantSlug = workspace == null ? null : workspace.tenantSlug();
        if (tenantUuid != null) {
            body.put("tenant_id", tenantUuid.toString());
        } else {
            body.put("tenant_slug", tenantSlug != null ? tenantSlug : tenantId);
        }
        return body;
    }

    // ------------------------------------------------------------------
    // §25 Account lifecycle and MFA enrolment
    // ------------------------------------------------------------------

    /**
     * {@code POST /api/v1/auth/mfa/enroll} (CONTRACT.md &sect;25.1) — start
     * voluntary TOTP enrolment for the signed-in user.
     *
     * <p>Changes nothing about the current session. In particular it does
     * <strong>not</strong> clear the &sect;17 decision memo: the subject has
     * not changed, and discarding a warm memo on an unrelated profile action
     * costs a round trip on every check that follows (&sect;25.2 rule 3).
     *
     * @return the secret and its {@code otpauth://} URI
     */
    public MfaEnrollment mfaEnroll() {
        ensureOpen();
        try (Response http = executeJsonPost(MFA_ENROLL_PATH, MAPPER.createObjectNode())) {
            return readMfaEnrollment(http, "mfaEnroll");
        }
    }

    /** {@code CompletableFuture} async twin of {@link #mfaEnroll}.
     *
     * @return a future resolving to the enrolment offer
     */
    public CompletableFuture<MfaEnrollment> mfaEnrollAsync() {
        return CompletableFuture.supplyAsync(this::mfaEnroll);
    }

    /**
     * {@code POST /api/v1/auth/mfa/confirm} (CONTRACT.md &sect;25.1) — activate
     * the factor {@link #mfaEnroll} offered.
     *
     * @param totpCode a current code derived from the enrolment secret
     * @return whether MFA is now enabled
     */
    public boolean mfaConfirm(String totpCode) {
        ensureOpen();
        ObjectNode body = MAPPER.createObjectNode();
        body.put("totp_code", totpCode);
        try (Response http = executeJsonPost(MFA_CONFIRM_PATH, body)) {
            if (http.code() != 200) {
                throw ErrorMapper.fromHttpStatus(http.code(), "mfaConfirm failed", http);
            }
            return readJson(http).path("mfa_enabled").asBoolean(false);
        }
    }

    /** {@code CompletableFuture} async twin of {@link #mfaConfirm}.
     *
     * @param totpCode a current code derived from the enrolment secret
     * @return a future resolving to whether MFA is now enabled
     */
    public CompletableFuture<Boolean> mfaConfirmAsync(String totpCode) {
        return CompletableFuture.supplyAsync(() -> mfaConfirm(totpCode));
    }

    /**
     * {@code POST /api/v1/auth/mfa/setup/enroll} (CONTRACT.md &sect;25.1) —
     * start the enrolment a {@link #login} demanded.
     *
     * <p>Reached when {@code login()} returns {@code mfaSetupRequired}: the
     * tenant requires MFA and this account has none. There is no session yet —
     * the setup token <em>is</em> the credential.
     *
     * @param setupToken the token from the {@code mfaSetupRequired} outcome
     * @return the secret and its {@code otpauth://} URI
     */
    public MfaEnrollment mfaSetupEnroll(Sensitive setupToken) {
        ensureOpen();
        ObjectNode body = MAPPER.createObjectNode();
        body.put("setup_token", setupToken.expose());
        try (Response http = executeJsonPost(MFA_SETUP_ENROLL_PATH, body)) {
            return readMfaEnrollment(http, "mfaSetupEnroll");
        }
    }

    /** {@code CompletableFuture} async twin of {@link #mfaSetupEnroll}.
     *
     * @param setupToken the token from the {@code mfaSetupRequired} outcome
     * @return a future resolving to the enrolment offer
     */
    public CompletableFuture<MfaEnrollment> mfaSetupEnrollAsync(Sensitive setupToken) {
        return CompletableFuture.supplyAsync(() -> mfaSetupEnroll(setupToken));
    }

    /**
     * {@code POST /api/v1/auth/mfa/setup/confirm} (CONTRACT.md &sect;25.1) —
     * finish forced enrolment and, with it, the login that was interrupted.
     *
     * <p>Adopts credentials exactly as {@link #login} does, because it
     * <em>is</em> the completion of a login (&sect;25.2 rule 2).
     *
     * @param setupToken the token from the {@code mfaSetupRequired} outcome
     * @param totpCode   a current code derived from the enrolment secret
     * @return the completed login
     */
    public LoginResult mfaSetupConfirm(Sensitive setupToken, String totpCode) {
        ensureOpen();
        onCredentialChange();
        ObjectNode body = MAPPER.createObjectNode();
        body.put("setup_token", setupToken.expose());
        body.put("totp_code", totpCode);

        try (Response http = executeJsonPost(MFA_SETUP_CONFIRM_PATH, body)) {
            if (http.code() != 200) {
                throw ErrorMapper.fromHttpStatus(http.code(), "mfaSetupConfirm failed", http);
            }
            consumeBody(http);
            return new LoginResult(false, null, buildUser());
        }
    }

    /** {@code CompletableFuture} async twin of {@link #mfaSetupConfirm}.
     *
     * @param setupToken the token from the {@code mfaSetupRequired} outcome
     * @param totpCode   a current code derived from the enrolment secret
     * @return a future resolving to the completed login
     */
    public CompletableFuture<LoginResult> mfaSetupConfirmAsync(Sensitive setupToken, String totpCode) {
        return CompletableFuture.supplyAsync(() -> mfaSetupConfirm(setupToken, totpCode));
    }

    /**
     * {@code POST /api/v1/auth/verify-email} (CONTRACT.md &sect;25.1).
     *
     * <p>Unauthenticated: a user whose address is unverified may have no
     * session at all. {@code tenantId} is a <strong>body</strong> field here —
     * this is not an {@code /oauth2/*} endpoint, so &sect;12.1 rule 2's
     * query-parameter convention does not reach it.
     *
     * @param token    the token from the verification mail
     * @param tenantId the tenant the account belongs to
     */
    public void verifyEmail(Sensitive token, UUID tenantId) {
        ensureOpen();
        ObjectNode body = MAPPER.createObjectNode();
        body.put("token", token.expose());
        body.put("tenant_id", tenantId.toString());
        postExpectingNoContent(VERIFY_EMAIL_PATH, body, "verifyEmail");
    }

    /** {@code CompletableFuture} async twin of {@link #verifyEmail}.
     *
     * @param token    the token from the verification mail
     * @param tenantId the tenant the account belongs to
     * @return a future that completes once the address is verified
     */
    public CompletableFuture<Void> verifyEmailAsync(Sensitive token, UUID tenantId) {
        return CompletableFuture.runAsync(() -> verifyEmail(token, tenantId));
    }

    /**
     * {@code POST /api/v1/auth/resend-verification} (CONTRACT.md &sect;25.1).
     *
     * @param email    the address to resend to
     * @param tenantId the tenant the account belongs to
     */
    public void resendVerification(String email, UUID tenantId) {
        ensureOpen();
        ObjectNode body = MAPPER.createObjectNode();
        body.put("email", email);
        body.put("tenant_id", tenantId.toString());
        postExpectingNoContent(RESEND_VERIFICATION_PATH, body, "resendVerification");
    }

    /** {@code CompletableFuture} async twin of {@link #resendVerification}.
     *
     * @param email    the address to resend to
     * @param tenantId the tenant the account belongs to
     * @return a future that completes once the mail is enqueued
     */
    public CompletableFuture<Void> resendVerificationAsync(String email, UUID tenantId) {
        return CompletableFuture.runAsync(() -> resendVerification(email, tenantId));
    }

    /**
     * {@code POST /api/v1/auth/reset} (CONTRACT.md &sect;25.1) — ask for a
     * reset mail.
     *
     * <p><strong>Returns normally whether or not the address exists</strong>,
     * and this SDK exposes no way to tell the two apart. That is not an
     * omission to improve on: a client that surfaced a "no such user" state —
     * even one inferred from timing — would turn the endpoint into the account
     * enumeration oracle its uniform response exists to prevent (&sect;25.4).
     *
     * @param request the address, and optionally an explicit workspace
     */
    public void requestPasswordReset(PasswordResetRequest request) {
        ensureOpen();
        ObjectNode body = MAPPER.createObjectNode();
        body.put("email", request.email());

        String orgSlug = request.orgSlug() != null ? request.orgSlug() : session.configuredOrgSlug();
        if (orgSlug != null) {
            body.put("org_slug", orgSlug);
        }
        if (request.tenantId() != null) {
            body.put("tenant_id", request.tenantId().toString());
        } else {
            body.put("tenant_slug", request.tenantSlug() != null ? request.tenantSlug() : tenantId);
        }
        postExpectingNoContent(RESET_PATH, body, "requestPasswordReset");
    }

    /** {@code CompletableFuture} async twin of {@link #requestPasswordReset}.
     *
     * @param request the address, and optionally an explicit workspace
     * @return a future that completes once the request is accepted
     */
    public CompletableFuture<Void> requestPasswordResetAsync(PasswordResetRequest request) {
        return CompletableFuture.runAsync(() -> requestPasswordReset(request));
    }

    /**
     * {@code GET /api/v1/auth/reset/context} (CONTRACT.md &sect;25.1) — the
     * OPAQUE policy for the account a reset token belongs to.
     *
     * <p>Call this before {@link #confirmPasswordReset} on any tenant that
     * might have &sect;23 enabled: the client has to build a registration
     * record, and building one needs parameters it cannot know before it has a
     * token to ask with. Sending a plaintext password to a tenant in
     * {@code opaque_mode: required} is refused, and refused late (&sect;25.4
     * rule 1).
     *
     * <p>A {@code 404} means unknown, expired <strong>or</strong>
     * already-consumed, deliberately without distinguishing them; this SDK does
     * not distinguish them either (&sect;25.4 rule 3).
     *
     * @param token the token from the reset mail
     * @return the tenant's OPAQUE policy, if it has one
     */
    public PasswordResetContext passwordResetContext(Sensitive token) {
        ensureOpen();
        HttpUrl url = Objects.requireNonNull(HttpUrl.parse(baseUrl + RESET_CONTEXT_PATH))
                .newBuilder()
                .addQueryParameter("token", token.expose())
                .build();
        Request request = new Request.Builder().url(url).get().build();

        try (Response http = httpClient.newCall(request).execute()) {
            if (http.code() != 200) {
                throw ErrorMapper.fromHttpStatus(http.code(), "passwordResetContext failed", http);
            }
            JsonNode wire = readJson(http);
            JsonNode opaque = wire.get("opaque");
            return new PasswordResetContext(opaque == null || opaque.isNull() ? null : opaque);
        } catch (IOException e) {
            throw new NetworkError("passwordResetContext request failed: " + e.getMessage(), e);
        }
    }

    /** {@code CompletableFuture} async twin of {@link #passwordResetContext}.
     *
     * @param token the token from the reset mail
     * @return a future resolving to the OPAQUE policy
     */
    public CompletableFuture<PasswordResetContext> passwordResetContextAsync(Sensitive token) {
        return CompletableFuture.supplyAsync(() -> passwordResetContext(token));
    }

    /**
     * {@code POST /api/v1/auth/reset/confirm} (CONTRACT.md &sect;25.1) — set
     * the new password.
     *
     * @param confirmation the token, the new password, the tenant, and any
     *                     &sect;23 registration record
     */
    public void confirmPasswordReset(PasswordResetConfirmation confirmation) {
        ensureOpen();
        ObjectNode body = MAPPER.createObjectNode();
        body.put("token", confirmation.token().expose());
        body.put("new_password", confirmation.newPassword().expose());
        body.put("tenant_id", confirmation.tenantId().toString());
        if (confirmation.opaque() != null) {
            body.set("opaque", confirmation.opaque());
        }
        postExpectingNoContent(RESET_CONFIRM_PATH, body, "confirmPasswordReset");
    }

    /** {@code CompletableFuture} async twin of {@link #confirmPasswordReset}.
     *
     * @param confirmation the token, the new password, the tenant, and any record
     * @return a future that completes once the password is changed
     */
    public CompletableFuture<Void> confirmPasswordResetAsync(PasswordResetConfirmation confirmation) {
        return CompletableFuture.runAsync(() -> confirmPasswordReset(confirmation));
    }

    private MfaEnrollment readMfaEnrollment(Response http, String operation) {
        if (http.code() != 200) {
            throw ErrorMapper.fromHttpStatus(http.code(), operation + " failed", http);
        }
        JsonNode wire = readJson(http);
        return new MfaEnrollment(
                Sensitive.of(wire.path("secret_base32").asText()),
                Sensitive.of(wire.path("totp_uri").asText()));
    }

    private void postExpectingNoContent(String path, ObjectNode body, String operation) {
        try (Response http = executeJsonPost(path, body)) {
            int code = http.code();
            if (code != 200 && code != 202 && code != 204) {
                throw ErrorMapper.fromHttpStatus(code, operation + " failed", http);
            }
            consumeBody(http);
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
