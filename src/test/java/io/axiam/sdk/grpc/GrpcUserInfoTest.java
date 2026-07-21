package io.axiam.sdk.grpc;

import axiam.v1.Userinfo.GetUserInfoRequest;
import axiam.v1.Userinfo.GetUserInfoResponse;
import axiam.v1.UserInfoServiceGrpc;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.AuthzError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.SessionState;
import io.axiam.sdk.internal.TokenPair;

import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.Status;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;

import okhttp3.java.net.cookiejar.JavaNetCookieJar;
import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code GrpcAuthzClient.getUserInfo}/{@code getUserInfoAsync} acceptance
 * (CONTRACT.md &sect;1.1/&sect;2/&sect;5/&sect;9): full-claim mapping, absent
 * optionals, outgoing {@code authorization}/{@code x-tenant-id} metadata,
 * pre-flight {@link AuthError} without a wire call, &sect;2 error mapping, and
 * exactly-one shared-guard refresh-and-retry-once on {@code UNAUTHENTICATED} —
 * all driven over an in-process gRPC server (no live network dependency),
 * mirroring {@code GrpcAuthzClientTest}.
 */
class GrpcUserInfoTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String ORG_ID = "44444444-4444-4444-4444-444444444444";
    private static final String SUBJECT_ID = "11111111-1111-1111-1111-111111111111";

    private final List<Server> servers = new ArrayList<>();
    private final List<ManagedChannel> channels = new ArrayList<>();
    private MockWebServer restServer;

    @AfterEach
    void tearDown() throws Exception {
        for (ManagedChannel channel : channels) {
            channel.shutdownNow();
        }
        for (Server server : servers) {
            server.shutdownNow();
        }
        if (restServer != null) {
            restServer.close();
        }
    }

    @Test
    void getUserInfoMapsAllClaimsIncludingScopedOptionals() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession(newCookieManager());
        seedValidToken(guard, 900);

        GetUserInfoResponse full = GetUserInfoResponse.newBuilder()
                .setSub(SUBJECT_ID)
                .setTenantId(TENANT_ID)
                .setOrgId(ORG_ID)
                .setEmail("alice@example.com")
                .setPreferredUsername("alice")
                .build();

        try (GrpcAuthzClient client = buildClient(FakeUserInfoService.returning(full), guard, session,
                new CopyOnWriteArrayList<>())) {
            GrpcAuthzClient.UserInfo info = client.getUserInfo();
            assertEquals(SUBJECT_ID, info.sub());
            assertEquals(TENANT_ID, info.tenantId());
            assertEquals(ORG_ID, info.orgId());
            assertEquals(Optional.of("alice@example.com"), info.email());
            assertEquals(Optional.of("alice"), info.preferredUsername());
        }
    }

    @Test
    void getUserInfoLeavesUnscopedOptionalsEmpty() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession(newCookieManager());
        seedValidToken(guard, 900);

        // No email/preferred_username set — the token carried neither the "email" nor
        // "profile" scope, so the server omits both optional fields.
        GetUserInfoResponse minimal = GetUserInfoResponse.newBuilder()
                .setSub(SUBJECT_ID)
                .setTenantId(TENANT_ID)
                .setOrgId(ORG_ID)
                .build();

        try (GrpcAuthzClient client = buildClient(FakeUserInfoService.returning(minimal), guard, session,
                new CopyOnWriteArrayList<>())) {
            GrpcAuthzClient.UserInfo info = client.getUserInfo();
            assertEquals(SUBJECT_ID, info.sub());
            assertEquals(TENANT_ID, info.tenantId());
            assertEquals(ORG_ID, info.orgId());
            assertTrue(info.email().isEmpty());
            assertTrue(info.preferredUsername().isEmpty());
        }
    }

    @Test
    void getUserInfoAsyncMapsClaims() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession(newCookieManager());
        seedValidToken(guard, 900);

        GetUserInfoResponse full = GetUserInfoResponse.newBuilder()
                .setSub(SUBJECT_ID)
                .setTenantId(TENANT_ID)
                .setOrgId(ORG_ID)
                .setEmail("bob@example.com")
                .build();

        try (GrpcAuthzClient client = buildClient(FakeUserInfoService.returning(full), guard, session,
                new CopyOnWriteArrayList<>())) {
            GrpcAuthzClient.UserInfo info = client.getUserInfoAsync().get();
            assertEquals(SUBJECT_ID, info.sub());
            assertEquals(Optional.of("bob@example.com"), info.email());
            assertTrue(info.preferredUsername().isEmpty());
        }
    }

    @Test
    void getUserInfoWithNoTokenRaisesAuthErrorWithoutWireCall() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession(newCookieManager());
        // No token seeded on either the guard or the session's cookie jar.

        FakeUserInfoService service = FakeUserInfoService.returning(GetUserInfoResponse.getDefaultInstance());
        try (GrpcAuthzClient client = buildClient(service, guard, session, new CopyOnWriteArrayList<>())) {
            assertThrows(AuthError.class, client::getUserInfo);
            assertEquals(0, service.callCount(), "pre-flight AuthError must be raised without any wire call (§1.1 point 3)");
        }
    }

    @Test
    void getUserInfoAsyncWithNoTokenFailsFutureWithAuthErrorWithoutWireCall() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession(newCookieManager());

        FakeUserInfoService service = FakeUserInfoService.returning(GetUserInfoResponse.getDefaultInstance());
        try (GrpcAuthzClient client = buildClient(service, guard, session, new CopyOnWriteArrayList<>())) {
            java.util.concurrent.ExecutionException ex = assertThrows(java.util.concurrent.ExecutionException.class,
                    () -> client.getUserInfoAsync().get());
            assertTrue(ex.getCause() instanceof AuthError);
            assertEquals(0, service.callCount(), "pre-flight AuthError must be raised without any wire call (§1.1 point 3)");
        }
    }

    @Test
    void outgoingMetadataCarriesAuthorizationAndTenantId() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession(newCookieManager());
        String token = seedValidToken(guard, 900);

        GetUserInfoResponse resp = GetUserInfoResponse.newBuilder()
                .setSub(SUBJECT_ID).setTenantId(TENANT_ID).setOrgId(ORG_ID).build();
        List<Metadata> captured = new CopyOnWriteArrayList<>();
        try (GrpcAuthzClient client = buildClient(FakeUserInfoService.returning(resp), guard, session, captured)) {
            client.getUserInfo();
        }

        assertEquals(1, captured.size());
        Metadata headers = captured.get(0);
        Metadata.Key<String> tenantKey = Metadata.Key.of("x-tenant-id", Metadata.ASCII_STRING_MARSHALLER);
        Metadata.Key<String> authKey = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
        assertEquals(TENANT_ID, headers.get(tenantKey));
        assertEquals("Bearer " + token, headers.get(authKey));
    }

    @Test
    void unauthenticatedThenSuccessTriggersExactlyOneSharedGuardRefreshAndOneRetry() throws Exception {
        restServer = startRestRefreshServer();
        RefreshGuard guard = new RefreshGuard();
        // Seed the SESSION's cookie jar (not the guard) via a REAL Set-Cookie round-trip — the
        // guard starts empty, mirroring the gap between login() (cookies only) and the first
        // refresh (which populates the guard). See GrpcAuthzClientTest for the same rationale.
        SessionState session = newSessionSeededByLoginResponse(restServer);
        String staleToken = session.cachedAccessToken();
        assertNotNull(staleToken);
        long requestsBefore = restServer.getRequestCount();

        GetUserInfoResponse resp = GetUserInfoResponse.newBuilder()
                .setSub(SUBJECT_ID).setTenantId(TENANT_ID).setOrgId(ORG_ID).build();
        FakeUserInfoService service = FakeUserInfoService.unauthenticatedOnceThen(resp);
        try (GrpcAuthzClient client = buildClient(service, guard, session, new CopyOnWriteArrayList<>())) {
            GrpcAuthzClient.UserInfo info = client.getUserInfo();

            assertEquals(SUBJECT_ID, info.sub());
            assertEquals(2, service.callCount(), "expected the RPC to be attempted exactly twice (fail once, retry once)");
            assertEquals(1, restServer.getRequestCount() - requestsBefore,
                    "expected exactly one refresh POST across the retry (§9.3)");
            assertNotNull(guard.cachedAccessToken(), "the shared RefreshGuard must now hold the refreshed token");
            assertNotEquals(staleToken, guard.cachedAccessToken(), "the guard's cache must reflect the NEW token");
        }
    }

    @Test
    void permissionDeniedMapsToAuthzErrorAndUnavailableMapsToNetworkError() throws Exception {
        RefreshGuard guard1 = new RefreshGuard();
        SessionState session1 = newSession(newCookieManager());
        seedValidToken(guard1, 900);
        try (GrpcAuthzClient client = buildClient(
                FakeUserInfoService.terminalError(Status.PERMISSION_DENIED.withDescription("no permission")),
                guard1, session1, new CopyOnWriteArrayList<>())) {
            assertThrows(AuthzError.class, client::getUserInfo);
        }

        RefreshGuard guard2 = new RefreshGuard();
        SessionState session2 = newSession(newCookieManager());
        seedValidToken(guard2, 900);
        try (GrpcAuthzClient client = buildClient(
                FakeUserInfoService.terminalError(Status.UNAVAILABLE.withDescription("server unreachable")),
                guard2, session2, new CopyOnWriteArrayList<>())) {
            assertThrows(NetworkError.class, client::getUserInfo);
        }
    }

    // ------------------------------------------------------------------
    // Fixtures (mirror GrpcAuthzClientTest)
    // ------------------------------------------------------------------

    private GrpcAuthzClient buildClient(UserInfoServiceGrpc.UserInfoServiceImplBase service,
                                         RefreshGuard guard, SessionState session,
                                         List<Metadata> capturedMetadata) throws Exception {
        String serverName = InProcessServerBuilder.generateName();
        ServerInterceptor captureInterceptor = new ServerInterceptor() {
            @Override
            public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
                    ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
                capturedMetadata.add(headers);
                return next.startCall(call, headers);
            }
        };
        Server server = InProcessServerBuilder.forName(serverName)
                .directExecutor()
                .addService(ServerInterceptors.intercept(service, captureInterceptor))
                .build()
                .start();
        servers.add(server);

        ManagedChannel channel = InProcessChannelBuilder.forName(serverName)
                .directExecutor()
                .intercept(new AuthClientInterceptor(() -> GrpcAuthzClient.currentAccessToken(guard, session), session.tenantId()))
                .build();
        channels.add(channel);

        return new GrpcAuthzClient(channel, guard, session);
    }

    private static CookieManager newCookieManager() {
        return new CookieManager(null, CookiePolicy.ACCEPT_ALL);
    }

    private static SessionState newSession(CookieManager cookieManager) {
        SessionState session = new SessionState(cookieManager, "http://localhost:0", TENANT_ID, null,
                UUID.fromString(ORG_ID));
        session.attachHttpClient(new OkHttpClient.Builder().cookieJar(new JavaNetCookieJar(cookieManager)).build());
        return session;
    }

    private static String seedValidToken(RefreshGuard guard, long expiresInSeconds) {
        String token = fakeAccessToken(SUBJECT_ID, TENANT_ID, ORG_ID, expiresInSeconds);
        guard.refreshIfNeeded("", () -> new TokenPair(token, "seed-refresh-token",
                System.currentTimeMillis() + expiresInSeconds * 1000));
        return token;
    }

    private static MockWebServer startRestRefreshServer() throws Exception {
        MockWebServer server = new MockWebServer();
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken(SUBJECT_ID, TENANT_ID, ORG_ID, 60) + "; Path=/; HttpOnly")
                .setHeader("Content-Type", "application/json")
                .setBody("{}"));
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .addHeader("Set-Cookie", "axiam_access=" + fakeAccessToken(SUBJECT_ID, TENANT_ID, ORG_ID, 900) + "; Path=/; HttpOnly")
                .addHeader("Set-Cookie", "axiam_refresh=new-refresh-token; Path=/; HttpOnly")
                .setHeader("Content-Type", "application/json")
                .setBody("{\"expires_in\":900}"));
        server.start();
        return server;
    }

    private static SessionState newSessionSeededByLoginResponse(MockWebServer restServer) throws Exception {
        CookieManager cookieManager = newCookieManager();
        OkHttpClient httpClient = new OkHttpClient.Builder().cookieJar(new JavaNetCookieJar(cookieManager)).build();
        SessionState session = new SessionState(cookieManager, restServer.url("/").toString(), TENANT_ID, null,
                UUID.fromString(ORG_ID));
        session.attachHttpClient(httpClient);

        try (okhttp3.Response ignored = httpClient.newCall(new okhttp3.Request.Builder()
                .url(restServer.url("/fake-login")).get().build()).execute()) {
            // discard — this call's only purpose is to trigger the CookieJar's saveFromResponse.
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

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    /** Configurable fake {@code UserInfoService} implementation. */
    private static final class FakeUserInfoService extends UserInfoServiceGrpc.UserInfoServiceImplBase {
        private final AtomicInteger callCount = new AtomicInteger(0);
        private final Function<Integer, StreamObserverAction> behavior;

        private FakeUserInfoService(Function<Integer, StreamObserverAction> behavior) {
            this.behavior = behavior;
        }

        int callCount() {
            return callCount.get();
        }

        @Override
        public void getUserInfo(GetUserInfoRequest request, StreamObserver<GetUserInfoResponse> responseObserver) {
            int attempt = callCount.incrementAndGet();
            behavior.apply(attempt).run(responseObserver);
        }

        static FakeUserInfoService returning(GetUserInfoResponse response) {
            return new FakeUserInfoService(attempt -> obs -> {
                obs.onNext(response);
                obs.onCompleted();
            });
        }

        static FakeUserInfoService unauthenticatedOnceThen(GetUserInfoResponse response) {
            return new FakeUserInfoService(attempt -> obs -> {
                if (attempt == 1) {
                    obs.onError(Status.UNAUTHENTICATED.withDescription("expired token").asRuntimeException());
                } else {
                    obs.onNext(response);
                    obs.onCompleted();
                }
            });
        }

        static FakeUserInfoService terminalError(Status status) {
            return new FakeUserInfoService(attempt -> obs -> obs.onError(status.asRuntimeException()));
        }

        @FunctionalInterface
        private interface StreamObserverAction {
            void run(StreamObserver<GetUserInfoResponse> observer);
        }
    }
}
