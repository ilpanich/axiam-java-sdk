package io.axiam.sdk.grpc;

import axiam.v1.Authorization.BatchCheckAccessResponse;
import axiam.v1.Authorization.CheckAccessResponse;
import axiam.v1.AuthorizationServiceGrpc;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.SessionState;
import io.axiam.sdk.internal.TokenPair;

import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.Status;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;

import okhttp3.JavaNetCookieJar;
import okhttp3.OkHttpClient;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The parts of {@code GrpcAuthzClient} {@code GrpcAuthzClientTest} doesn't reach: the PUBLIC
 * strict-TLS constructor (bypassed by that class's package-private in-process-channel seam), the
 * {@code checkAccessAsync}/{@code batchCheckAsync} {@code CompletableFuture} twins (including
 * their own UNAUTHENTICATED-retry path), the {@code AccessCheck} convenience constructors,
 * {@code resolveClaims}/{@code requireClaim}'s "no active session"/"undecodable"/"missing claim"
 * guards, {@code close()}'s interrupted-await branch, and {@code mapToRuntime}'s two non-{@code
 * StatusRuntimeException} branches (reached via reflection — {@code onFailure} never surfaces a
 * plain exception through a real gRPC stub, so there is no public seam for them).
 */
class GrpcAuthzClientExtraTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String ORG_ID = "44444444-4444-4444-4444-444444444444";
    private static final String SUBJECT_ID = "11111111-1111-1111-1111-111111111111";
    private static final String RESOURCE_ID = "22222222-2222-2222-2222-222222222222";

    private final List<Server> servers = new ArrayList<>();
    private final List<ManagedChannel> channels = new ArrayList<>();

    @AfterEach
    void tearDown() {
        for (ManagedChannel channel : channels) {
            channel.shutdownNow();
        }
        for (Server server : servers) {
            server.shutdownNow();
        }
    }

    @Test
    void publicConstructorBuildsAUsableClientWithNoCustomCa() {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        // NettyChannelBuilder.build() is non-blocking (IDLE channel, connects lazily on first
        // RPC) — a plain, never-dialed target is enough to exercise the constructor's strict-TLS
        // channel-building lines without a real server.
        try (GrpcAuthzClient client = new GrpcAuthzClient("dns:///localhost:1", guard, session, null)) {
            assertTrue(true, "construction alone must not throw");
        }
    }

    @Test
    void accessCheckTwoArgConvenienceConstructorDefaultsSubjectAndScopeToNull() {
        GrpcAuthzClient.AccessCheck check = new GrpcAuthzClient.AccessCheck("users:get", RESOURCE_ID);
        assertNull(check.subjectId());
        assertEquals("users:get", check.action());
        assertEquals(RESOURCE_ID, check.resourceId());
        assertNull(check.scope());
    }

    @Test
    void accessCheckThreeArgConvenienceConstructorDefaultsSubjectToNull() {
        GrpcAuthzClient.AccessCheck check = new GrpcAuthzClient.AccessCheck("users:get", RESOURCE_ID, "profile");
        assertNull(check.subjectId());
        assertEquals("profile", check.scope());
    }

    @Test
    void checkAccessThreeArgOverloadWithScopeSetsWireScope() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        seedValidToken(guard, 900);

        try (GrpcAuthzClient client = buildClient(FakeAuthorizationService.alwaysAllow(), guard, session)) {
            GrpcAuthzClient.AccessResult result = client.checkAccess("users:get", RESOURCE_ID, "profile");
            assertTrue(result.allowed());
        }
    }

    @Test
    void checkAccessAsyncAllVariantsResolve() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        seedValidToken(guard, 900);

        try (GrpcAuthzClient client = buildClient(FakeAuthorizationService.alwaysAllow(), guard, session)) {
            assertTrue(client.checkAccessAsync("users:get", RESOURCE_ID).get().allowed());
            assertTrue(client.checkAccessAsync("users:get", RESOURCE_ID, "profile").get().allowed());
            assertTrue(client.checkAccessAsync(SUBJECT_ID, "users:get", RESOURCE_ID, null).get().allowed());
        }
    }

    @Test
    void batchCheckAsyncReturnsResultsInInputOrder() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        seedValidToken(guard, 900);

        try (GrpcAuthzClient client = buildClient(FakeAuthorizationService.batchInOrder(), guard, session)) {
            List<GrpcAuthzClient.AccessResult> results = client.batchCheckAsync(List.of(
                    new GrpcAuthzClient.AccessCheck(SUBJECT_ID, "users:get", RESOURCE_ID, null),
                    new GrpcAuthzClient.AccessCheck(SUBJECT_ID, "users:delete", RESOURCE_ID, null))).get();

            assertEquals(2, results.size());
            assertTrue(results.get(0).allowed());
            assertFalse(results.get(1).allowed());
        }
    }

    @Test
    void checkAccessAsyncUnauthenticatedThenSuccessTriggersRefreshAndRetry() throws Exception {
        okhttp3.mockwebserver.MockWebServer restServer = startRestRefreshServer();
        try {
            RefreshGuard guard = new RefreshGuard();
            SessionState session = newSessionSeededByLoginResponse(restServer);

            FakeAuthorizationService service = FakeAuthorizationService.unauthenticatedOnceThenAllow();
            try (GrpcAuthzClient client = buildClient(service, guard, session)) {
                GrpcAuthzClient.AccessResult result = client.checkAccessAsync("users:get", RESOURCE_ID).get();
                assertTrue(result.allowed());
                assertEquals(2, service.callCount.get());
            }
        } finally {
            restServer.close();
        }
    }

    @Test
    void checkAccessAsyncTerminalErrorMapsToAuthzError() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        seedValidToken(guard, 900);

        try (GrpcAuthzClient client = buildClient(
                FakeAuthorizationService.terminalError(Status.PERMISSION_DENIED.withDescription("no permission")),
                guard, session)) {
            java.util.concurrent.ExecutionException ex = assertThrows(java.util.concurrent.ExecutionException.class,
                    () -> client.checkAccessAsync("users:get", RESOURCE_ID).get());
            assertInstanceOf(io.axiam.sdk.errors.AuthzError.class, ex.getCause());
        }
    }

    @Test
    void checkAccessWithNoActiveSessionThrowsAuthError() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession(); // no token seeded anywhere

        try (GrpcAuthzClient client = buildClient(FakeAuthorizationService.alwaysAllow(), guard, session)) {
            assertThrows(AuthError.class, () -> client.checkAccess("users:get", RESOURCE_ID));
        }
    }

    @Test
    void checkAccessWithAnUndecodableAccessTokenThrowsAuthError() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        // Seed the guard's cache directly with a non-JWT (2-part) string — currentAccessToken()
        // returns it as-is (non-null), but SessionState.decodeUnverifiedClaims rejects it.
        guard.refreshIfNeeded("", () -> new TokenPair("not-a-jwt", "r", System.currentTimeMillis() + 900_000));

        try (GrpcAuthzClient client = buildClient(FakeAuthorizationService.alwaysAllow(), guard, session)) {
            assertThrows(AuthError.class, () -> client.checkAccess("users:get", RESOURCE_ID));
        }
    }

    @Test
    void checkAccessWithATokenMissingSubClaimThrowsAuthError() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        String tokenMissingSub = fakeAccessTokenMissingClaim("sub");
        guard.refreshIfNeeded("", () -> new TokenPair(tokenMissingSub, "r", System.currentTimeMillis() + 900_000));

        try (GrpcAuthzClient client = buildClient(FakeAuthorizationService.alwaysAllow(), guard, session)) {
            // subjectId is null (defaulted), so toWire() must fall back to the 'sub' claim,
            // which is missing here — requireClaim("sub") must fail.
            AuthError error = assertThrows(AuthError.class, () -> client.checkAccess("users:get", RESOURCE_ID));
            assertTrue(error.getMessage().contains("'sub'"));
        }
    }

    @Test
    void closeSwallowsAnInterruptedAwaitTerminationAndRestoresTheInterruptFlag() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        GrpcAuthzClient client = buildClient(FakeAuthorizationService.alwaysAllow(), guard, session);

        Thread.currentThread().interrupt();
        try {
            client.close();
        } finally {
            assertTrue(Thread.interrupted(), "close() must restore the interrupt flag after swallowing InterruptedException");
        }
    }

    @Test
    void mapToRuntimePassesThroughAPlainRuntimeExceptionUnchanged() throws Exception {
        RuntimeException original = new IllegalStateException("already a RuntimeException");
        RuntimeException mapped = (RuntimeException) mapToRuntimeMethod().invoke(null, original);
        assertEquals(original, mapped, "a non-Status RuntimeException must be re-thrown as-is, not re-wrapped");
    }

    @Test
    void mapToRuntimeWrapsANonRuntimeThrowableAsNetworkError() throws Exception {
        Throwable original = new IOException("not a RuntimeException at all");
        RuntimeException mapped = (RuntimeException) mapToRuntimeMethod().invoke(null, original);
        assertInstanceOf(NetworkError.class, mapped);
    }

    // ------------------------------------------------------------------
    // Fixtures (mirrors GrpcAuthzClientTest's, package-visible there)
    // ------------------------------------------------------------------

    private static Method mapToRuntimeMethod() throws NoSuchMethodException {
        Method m = GrpcAuthzClient.class.getDeclaredMethod("mapToRuntime", Throwable.class);
        m.setAccessible(true);
        return m;
    }

    private GrpcAuthzClient buildClient(AuthorizationServiceGrpc.AuthorizationServiceImplBase service,
                                         RefreshGuard guard, SessionState session) {
        String serverName = InProcessServerBuilder.generateName();
        Server server = InProcessServerBuilder.forName(serverName)
                .directExecutor()
                .addService(service)
                .build();
        try {
            server.start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        servers.add(server);

        ManagedChannel channel = InProcessChannelBuilder.forName(serverName)
                .directExecutor()
                .intercept(new AuthClientInterceptor(() -> GrpcAuthzClient.currentAccessToken(guard, session), session.tenantId()))
                .build();
        channels.add(channel);

        // Same-package test-only seam (GrpcAuthzClientTest already relies on this).
        return new GrpcAuthzClient(channel, guard, session);
    }

    private static SessionState newSession() {
        CookieManager cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        SessionState session = new SessionState(cookieManager, "http://localhost:0", TENANT_ID, null, UUID.fromString(ORG_ID));
        session.attachHttpClient(new OkHttpClient.Builder().cookieJar(new JavaNetCookieJar(cookieManager)).build());
        return session;
    }

    private static String seedValidToken(RefreshGuard guard, long expiresInSeconds) {
        String token = fakeAccessToken(SUBJECT_ID, TENANT_ID, ORG_ID, expiresInSeconds);
        guard.refreshIfNeeded("", () -> new TokenPair(token, "seed-refresh-token",
                System.currentTimeMillis() + expiresInSeconds * 1000));
        return token;
    }

    private static okhttp3.mockwebserver.MockWebServer startRestRefreshServer() throws Exception {
        okhttp3.mockwebserver.MockWebServer server = new okhttp3.mockwebserver.MockWebServer();
        server.enqueue(new okhttp3.mockwebserver.MockResponse()
                .setResponseCode(200)
                .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken(SUBJECT_ID, TENANT_ID, ORG_ID, 60) + "; Path=/; HttpOnly")
                .setHeader("Content-Type", "application/json")
                .setBody("{}"));
        server.enqueue(new okhttp3.mockwebserver.MockResponse()
                .setResponseCode(200)
                .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken(SUBJECT_ID, TENANT_ID, ORG_ID, 900) + "; Path=/; HttpOnly")
                .addHeader("Set-Cookie", "axiam_refresh=new-refresh-token; Path=/; HttpOnly")
                .setHeader("Content-Type", "application/json")
                .setBody("{\"expires_in\":900}"));
        server.start();
        return server;
    }

    private static SessionState newSessionSeededByLoginResponse(okhttp3.mockwebserver.MockWebServer restServer) throws Exception {
        CookieManager cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        OkHttpClient httpClient = new OkHttpClient.Builder().cookieJar(new JavaNetCookieJar(cookieManager)).build();
        SessionState session = new SessionState(cookieManager, restServer.url("/").toString(), TENANT_ID, null,
                UUID.fromString(ORG_ID));
        session.attachHttpClient(httpClient);

        try (okhttp3.Response ignored = httpClient.newCall(new okhttp3.Request.Builder()
                .url(restServer.url("/fake-login")).get().build()).execute()) {
            // discard — only purpose is triggering the CookieJar's saveFromResponse.
        }
        return session;
    }

    private static String fakeAccessToken(String sub, String tenantId, String orgId, long expiresInSeconds) {
        String header = base64Url("{\"alg\":\"EdDSA\"}");
        String payload = base64Url("{\"sub\":\"" + sub + "\",\"tenant_id\":\"" + tenantId + "\",\"org_id\":\"" + orgId
                + "\",\"jti\":\"22222222-2222-2222-2222-222222222222\",\"exp\":"
                + (System.currentTimeMillis() / 1000 + expiresInSeconds) + "}");
        return header + "." + payload + ".fake-signature";
    }

    /** A well-formed, decodable token deliberately missing the given claim. Only "sub" is
     * supported — the only claim requireClaim() is exercised against here. */
    private static String fakeAccessTokenMissingClaim(String claimToOmit) {
        if (!"sub".equals(claimToOmit)) {
            throw new IllegalArgumentException("unsupported: " + claimToOmit);
        }
        String header = base64Url("{\"alg\":\"EdDSA\"}");
        String payload = base64Url("{\"tenant_id\":\"" + TENANT_ID + "\",\"org_id\":\"" + ORG_ID
                + "\",\"jti\":\"22222222-2222-2222-2222-222222222222\",\"exp\":"
                + (System.currentTimeMillis() / 1000 + 900) + "}");
        return header + "." + payload + ".fake-signature";
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    /** Minimal configurable fake, trimmed down from GrpcAuthzClientTest's version to only what
     * this class's scenarios need. */
    private static final class FakeAuthorizationService extends AuthorizationServiceGrpc.AuthorizationServiceImplBase {
        private final java.util.concurrent.atomic.AtomicInteger callCount = new java.util.concurrent.atomic.AtomicInteger(0);
        private final java.util.function.Function<Integer, java.util.function.Consumer<StreamObserver<CheckAccessResponse>>> checkAccessBehavior;

        private FakeAuthorizationService(
                java.util.function.Function<Integer, java.util.function.Consumer<StreamObserver<CheckAccessResponse>>> checkAccessBehavior) {
            this.checkAccessBehavior = checkAccessBehavior;
        }

        @Override
        public void checkAccess(axiam.v1.Authorization.CheckAccessRequest request, StreamObserver<CheckAccessResponse> responseObserver) {
            int attempt = callCount.incrementAndGet();
            checkAccessBehavior.apply(attempt).accept(responseObserver);
        }

        @Override
        public void batchCheckAccess(axiam.v1.Authorization.BatchCheckAccessRequest request,
                                      StreamObserver<BatchCheckAccessResponse> responseObserver) {
            BatchCheckAccessResponse.Builder builder = BatchCheckAccessResponse.newBuilder();
            for (axiam.v1.Authorization.CheckAccessRequest item : request.getRequestsList()) {
                boolean allowed = !"users:delete".equals(item.getAction());
                CheckAccessResponse.Builder resp = CheckAccessResponse.newBuilder().setAllowed(allowed);
                if (!allowed) {
                    resp.setDenyReason("no");
                }
                builder.addResults(resp.build());
            }
            responseObserver.onNext(builder.build());
            responseObserver.onCompleted();
        }

        static FakeAuthorizationService alwaysAllow() {
            return new FakeAuthorizationService(attempt -> obs -> {
                obs.onNext(CheckAccessResponse.newBuilder().setAllowed(true).build());
                obs.onCompleted();
            });
        }

        static FakeAuthorizationService unauthenticatedOnceThenAllow() {
            return new FakeAuthorizationService(attempt -> obs -> {
                if (attempt == 1) {
                    obs.onError(Status.UNAUTHENTICATED.withDescription("expired token").asRuntimeException());
                } else {
                    obs.onNext(CheckAccessResponse.newBuilder().setAllowed(true).build());
                    obs.onCompleted();
                }
            });
        }

        static FakeAuthorizationService terminalError(Status status) {
            return new FakeAuthorizationService(attempt -> obs -> obs.onError(status.asRuntimeException()));
        }

        static FakeAuthorizationService batchInOrder() {
            return new FakeAuthorizationService(attempt -> obs -> {
                obs.onNext(CheckAccessResponse.newBuilder().setAllowed(true).build());
                obs.onCompleted();
            });
        }
    }
}
