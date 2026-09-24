package io.axiam.sdk.grpc;

import axiam.v1.Token.CnfClaim;
import axiam.v1.Token.IntrospectTokenRequest;
import axiam.v1.Token.IntrospectTokenResponse;
import axiam.v1.Token.ValidateTokenRequest;
import axiam.v1.Token.ValidateTokenResponse;
import axiam.v1.TokenServiceGrpc;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.AuthError;
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
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;

import okhttp3.OkHttpClient;
import okhttp3.java.net.cookiejar.JavaNetCookieJar;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code GrpcAuthzClient#validateToken}/{@code #introspectToken} — CONTRACT.md
 * &sect;1.1.1/&sect;10.3 (contract 1.51), against an in-process {@code TokenService}.
 */
class GrpcTokenTest {

    private static final String TENANT_ID = "33333333-3333-3333-3333-333333333333";
    private static final String ORG_ID = "44444444-4444-4444-4444-444444444444";
    private static final String SUBJECT_ID = "11111111-1111-1111-1111-111111111111";

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

    /** A fake TokenService that echoes the inspected token back so a test can assert it,
     * and records every ValidateToken/IntrospectToken request + the metadata it arrived with. */
    private static final class FakeTokenService extends TokenServiceGrpc.TokenServiceImplBase {
        final List<ValidateTokenRequest> validateRequests = new CopyOnWriteArrayList<>();
        final List<IntrospectTokenRequest> introspectRequests = new CopyOnWriteArrayList<>();
        ValidateTokenResponse nextValidateResponse = ValidateTokenResponse.newBuilder().setValid(false).build();
        IntrospectTokenResponse nextIntrospectResponse =
                IntrospectTokenResponse.newBuilder().setActive(false).build();

        @Override
        public void validateToken(ValidateTokenRequest request, StreamObserver<ValidateTokenResponse> obs) {
            validateRequests.add(request);
            obs.onNext(nextValidateResponse);
            obs.onCompleted();
        }

        @Override
        public void introspectToken(IntrospectTokenRequest request, StreamObserver<IntrospectTokenResponse> obs) {
            introspectRequests.add(request);
            obs.onNext(nextIntrospectResponse);
            obs.onCompleted();
        }
    }

    private GrpcAuthzClient buildClient(FakeTokenService service, RefreshGuard guard, SessionState session,
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

    private static SessionState newSession() {
        CookieManager cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        SessionState session = new SessionState(cookieManager, "http://localhost:0", TENANT_ID, null,
                UUID.fromString(ORG_ID));
        session.attachHttpClient(new OkHttpClient.Builder().cookieJar(new JavaNetCookieJar(cookieManager)).build());
        return session;
    }

    private static String seedCallerToken(RefreshGuard guard) {
        String token = fakeAccessToken(SUBJECT_ID, TENANT_ID, ORG_ID, 900);
        guard.refreshIfNeeded("", () -> new TokenPair(token, "seed-refresh", System.currentTimeMillis() + 900_000));
        return token;
    }

    private static String fakeAccessToken(String sub, String tenantId, String orgId, long expiresInSeconds) {
        String header = base64Url("{\"alg\":\"EdDSA\"}");
        String payload = base64Url("{\"sub\":\"" + sub + "\",\"tenant_id\":\"" + tenantId + "\",\"org_id\":\"" + orgId
                + "\",\"exp\":" + (System.currentTimeMillis() / 1000 + expiresInSeconds) + "}");
        return header + "." + payload + ".fake-signature";
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    // -----------------------------------------------------------------
    // Rule 1/2: two tokens kept apart; no caller token -> AuthError, zero calls.
    // -----------------------------------------------------------------

    @Test
    void noCallerTokenRefusesClientSideWithZeroWireCalls() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        FakeTokenService service = new FakeTokenService();
        List<Metadata> captured = new ArrayList<>();
        try (GrpcAuthzClient client = buildClient(service, guard, session, captured)) {
            assertThrows(AuthError.class,
                    () -> client.validateToken(Sensitive.of("inspected-token")));
            assertTrue(service.validateRequests.isEmpty(),
                    "no caller token means zero wire calls, mirroring getUserInfo's rule 2");
        }
    }

    @Test
    void theCallerTokenAndTheInspectedTokenAreKeptApart() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        String callerToken = seedCallerToken(guard);
        FakeTokenService service = new FakeTokenService();
        service.nextValidateResponse = ValidateTokenResponse.newBuilder().setValid(true).build();
        List<Metadata> captured = new ArrayList<>();

        try (GrpcAuthzClient client = buildClient(service, guard, session, captured)) {
            client.validateToken(Sensitive.of("a-completely-different-inspected-token"));
        }

        assertEquals(1, service.validateRequests.size());
        assertEquals("a-completely-different-inspected-token",
                service.validateRequests.get(0).getAccessToken(),
                "the inspected token travels in the request message");
        Metadata.Key<String> authKey = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
        assertEquals("Bearer " + callerToken, captured.get(0).get(authKey),
                "the CALLER's own token authenticates the call through the interceptor, "
                        + "never defaulted from the inspected token");
    }

    // -----------------------------------------------------------------
    // Rule 3: cnf is optional; present-but-empty stays distinct from absent.
    // -----------------------------------------------------------------

    @Test
    void cnfAbsentMapsToNull() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        seedCallerToken(guard);
        FakeTokenService service = new FakeTokenService();
        service.nextValidateResponse = ValidateTokenResponse.newBuilder().setValid(true).build();
        List<Metadata> captured = new ArrayList<>();

        GrpcAuthzClient.TokenValidation result;
        try (GrpcAuthzClient client = buildClient(service, guard, session, captured)) {
            result = client.validateToken(Sensitive.of("t"));
        }
        assertNull(result.cnf(), "an unbound token's cnf must map to null, not an empty confirmation");
    }

    @Test
    void anEmptyCnfIsDistinctFromAnAbsentOne() throws Exception {
        // §10.3 rule 3 / §10.1 rule 9 detail 3: proto3 delivers an empty CnfClaim message for
        // a token with no confirmation — this is how "bound by a method I cannot verify"
        // travels over the wire, and it MUST NOT collapse into cnf() == null.
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        seedCallerToken(guard);
        FakeTokenService service = new FakeTokenService();
        service.nextValidateResponse = ValidateTokenResponse.newBuilder()
                .setValid(true)
                .setCnf(CnfClaim.newBuilder().build()) // present, both fields empty
                .build();
        List<Metadata> captured = new ArrayList<>();

        GrpcAuthzClient.TokenValidation result;
        try (GrpcAuthzClient client = buildClient(service, guard, session, captured)) {
            result = client.validateToken(Sensitive.of("t"));
        }
        assertTrue(result.cnf() != null, "an empty CnfClaim message is PRESENT, not absent");
        assertTrue(result.cnf().namesNoMethod());
    }

    @Test
    void aCertificateBoundCnfMapsThroughTyped() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        seedCallerToken(guard);
        FakeTokenService service = new FakeTokenService();
        service.nextValidateResponse = ValidateTokenResponse.newBuilder()
                .setValid(true)
                .setTokenType("Bearer") // rule 5: certificate-bound still reports "Bearer"
                .setCnf(CnfClaim.newBuilder().setX5TS256("thumbprint-value").build())
                .build();
        List<Metadata> captured = new ArrayList<>();

        GrpcAuthzClient.TokenValidation result;
        try (GrpcAuthzClient client = buildClient(service, guard, session, captured)) {
            result = client.validateToken(Sensitive.of("t"));
        }
        assertEquals("thumbprint-value", result.cnf().x5tS256());
        assertNull(result.cnf().jkt());
        assertEquals("Bearer", result.tokenType(),
                "rule 5: token_type MUST NOT be read as deciding boundness");
    }

    // -----------------------------------------------------------------
    // Rule 6: another tenant's token is valid:false / active:false — an answer, not an error.
    // -----------------------------------------------------------------

    @Test
    void anotherTenantsTokenIsAnAnswerNotAnError() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        seedCallerToken(guard);
        FakeTokenService service = new FakeTokenService();
        service.nextIntrospectResponse = IntrospectTokenResponse.newBuilder().setActive(false).build();
        List<Metadata> captured = new ArrayList<>();

        GrpcAuthzClient.TokenIntrospection result;
        try (GrpcAuthzClient client = buildClient(service, guard, session, captured)) {
            result = client.introspectToken(Sensitive.of("foreign-tenant-token"));
        }
        assertFalse(result.active());
    }

    // -----------------------------------------------------------------
    // Rule 3 (full set): every IntrospectTokenResponse field maps, including
    // the §10.3 parity fields the REST introspection response also carries.
    // -----------------------------------------------------------------

    @Test
    void everyIntrospectionFieldMaps() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        seedCallerToken(guard);
        FakeTokenService service = new FakeTokenService();
        service.nextIntrospectResponse = IntrospectTokenResponse.newBuilder()
                .setActive(true)
                .setSub(SUBJECT_ID)
                .setTenantId(TENANT_ID)
                .setOrgId(ORG_ID)
                .setIss("https://axiam.example.test")
                .setIat(1000)
                .setExp(2000)
                .setJti("jti-value")
                .setScope("read write")
                .setClientId("client-1")
                .setTokenType("Bearer")
                .setExtExchangeIss("https://foreign.example.test")
                .build();
        List<Metadata> captured = new ArrayList<>();

        GrpcAuthzClient.TokenIntrospection result;
        try (GrpcAuthzClient client = buildClient(service, guard, session, captured)) {
            result = client.introspectToken(Sensitive.of("t"));
        }
        assertTrue(result.active());
        assertEquals(SUBJECT_ID, result.sub());
        assertEquals(TENANT_ID, result.tenantId());
        assertEquals(ORG_ID, result.orgId());
        assertEquals("https://axiam.example.test", result.iss());
        assertEquals(1000L, result.iat());
        assertEquals(2000L, result.exp());
        assertEquals("jti-value", result.jti());
        assertEquals("read write", result.scope());
        assertEquals("client-1", result.clientId());
        assertEquals("Bearer", result.tokenType());
        assertEquals("https://foreign.example.test", result.extExchangeIss());
        assertTrue(result.permissions().isEmpty());
    }

    // -----------------------------------------------------------------
    // Async twins
    // -----------------------------------------------------------------

    @Test
    void validateTokenAsyncSucceeds() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        seedCallerToken(guard);
        FakeTokenService service = new FakeTokenService();
        service.nextValidateResponse = ValidateTokenResponse.newBuilder().setValid(true).build();
        List<Metadata> captured = new ArrayList<>();

        GrpcAuthzClient.TokenValidation result;
        try (GrpcAuthzClient client = buildClient(service, guard, session, captured)) {
            result = client.validateTokenAsync(Sensitive.of("t")).get();
        }
        assertTrue(result.valid());
    }

    @Test
    void introspectTokenAsyncSucceeds() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        seedCallerToken(guard);
        FakeTokenService service = new FakeTokenService();
        service.nextIntrospectResponse = IntrospectTokenResponse.newBuilder().setActive(true).build();
        List<Metadata> captured = new ArrayList<>();

        GrpcAuthzClient.TokenIntrospection result;
        try (GrpcAuthzClient client = buildClient(service, guard, session, captured)) {
            result = client.introspectTokenAsync(Sensitive.of("t")).get();
        }
        assertTrue(result.active());
    }

    @Test
    void validateTokenAsyncWithNoCallerTokenFailsTheFutureWithoutAWireCall() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        FakeTokenService service = new FakeTokenService();
        List<Metadata> captured = new ArrayList<>();

        try (GrpcAuthzClient client = buildClient(service, guard, session, captured)) {
            var future = client.validateTokenAsync(Sensitive.of("t"));
            assertTrue(future.isCompletedExceptionally());
        }
        assertTrue(service.validateRequests.isEmpty());
    }

    @Test
    void introspectTokenAsyncWithNoCallerTokenFailsTheFutureWithoutAWireCall() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        FakeTokenService service = new FakeTokenService();
        List<Metadata> captured = new ArrayList<>();

        try (GrpcAuthzClient client = buildClient(service, guard, session, captured)) {
            var future = client.introspectTokenAsync(Sensitive.of("t"));
            assertTrue(future.isCompletedExceptionally());
        }
        assertTrue(service.introspectRequests.isEmpty());
    }
}
