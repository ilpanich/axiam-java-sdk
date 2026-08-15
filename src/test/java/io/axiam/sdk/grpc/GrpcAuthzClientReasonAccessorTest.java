package io.axiam.sdk.grpc;

import axiam.v1.Authorization.CheckAccessResponse;
import axiam.v1.AuthorizationServiceGrpc;

import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.SessionState;
import io.axiam.sdk.internal.TokenPair;

import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;

import okhttp3.java.net.cookiejar.JavaNetCookieJar;
import okhttp3.OkHttpClient;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins {@code GrpcAuthzClient#toAccessResult}'s SDK-Q10 / CONTRACT.md &sect;11.2 rule 9 (contract
 * 1.19) reason-accessor behaviour: read {@code reason} (field 4), fall back to the deprecated
 * {@code deny_reason} (field 2) <strong>only</strong> when {@code reason} is absent, and expose
 * exactly ONE reason accessor ({@link GrpcAuthzClient.AccessResult#reason()}) on the public
 * surface.
 *
 * <p>The case that motivates guarding the fallback with {@code hasReason()} rather than
 * truthiness/emptiness is {@link #reasonPresentButExplicitlyEmptyOnARefusalDoesNotFallBack}: a
 * refusal whose {@code reason} field was explicitly set to {@code ""} must be reported as
 * {@code null}, never silently replaced by the legacy {@code deny_reason} string — an
 * emptiness-guarded fallback (rather than a presence-guarded one) would get this wrong.
 */
class GrpcAuthzClientReasonAccessorTest {

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
    void reasonPresentAndNonEmptyIsUsedVerbatimOverDenyReason() throws Exception {
        // `reason` (field 4) set to a value distinct from `deny_reason` (field 2) — a current
        // server always ships identical strings on both, but this proves the mapping reads
        // `reason` rather than `deny_reason` when both are present.
        GrpcAuthzClient.AccessResult result = checkAccessAgainst(response -> response
                .setAllowed(false)
                .setReason("current reason")
                .setDenyReason("legacy reason"));

        assertFalse(result.allowed());
        assertEquals("current reason", result.reason());
    }

    @Test
    void reasonPresentButExplicitlyEmptyOnARefusalDoesNotFallBack() throws Exception {
        // `reason` IS present (hasReason() == true) but carries "" — must NOT fall back to the
        // populated `deny_reason`. A truthiness/emptiness-guarded fallback (instead of a
        // presence/hasReason()-guarded one) would misread this as "reason absent" and wrongly
        // surface "legacy reason".
        GrpcAuthzClient.AccessResult result = checkAccessAgainst(response -> response
                .setAllowed(false)
                .setReason("")
                .setDenyReason("legacy reason"));

        assertFalse(result.allowed());
        assertNull(result.reason(), "an explicitly-empty `reason` must surface as null, not fall back to deny_reason");
    }

    @Test
    void reasonAbsentOnARefusalFallsBackToDenyReason() throws Exception {
        // `reason` (field 4) is never set — hasReason() == false, exactly a pre-SDK-Q10 server —
        // so the deprecated `deny_reason` (field 2) is the only source of a reason string.
        GrpcAuthzClient.AccessResult result = checkAccessAgainst(response -> response
                .setAllowed(false)
                .setDenyReason("legacy reason"));

        assertFalse(result.allowed());
        assertEquals("legacy reason", result.reason());
    }

    @Test
    void reasonAbsentOnAnAllowYieldsNullWithNoFallback() throws Exception {
        // Neither field is set on an allow (the server never populates deny_reason on an
        // allow) — fallback is refusal-only in effect, and there is nothing to surface either way.
        GrpcAuthzClient.AccessResult result = checkAccessAgainst(response -> response.setAllowed(true));

        assertTrue(result.allowed());
        assertNull(result.reason());
    }

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    /** Runs a single {@code checkAccess} call against an in-process server whose response is
     * built by {@code responseCustomizer}, returning the mapped {@link GrpcAuthzClient.AccessResult}. */
    private GrpcAuthzClient.AccessResult checkAccessAgainst(
            Consumer<CheckAccessResponse.Builder> responseCustomizer) throws Exception {
        RefreshGuard guard = new RefreshGuard();
        SessionState session = newSession();
        seedValidToken(guard, 900);

        AuthorizationServiceGrpc.AuthorizationServiceImplBase service =
                new AuthorizationServiceGrpc.AuthorizationServiceImplBase() {
                    @Override
                    public void checkAccess(axiam.v1.Authorization.CheckAccessRequest request,
                                             StreamObserver<CheckAccessResponse> responseObserver) {
                        CheckAccessResponse.Builder builder = CheckAccessResponse.newBuilder();
                        responseCustomizer.accept(builder);
                        responseObserver.onNext(builder.build());
                        responseObserver.onCompleted();
                    }
                };

        try (GrpcAuthzClient client = buildClient(service, guard, session)) {
            return client.checkAccess("users:get", RESOURCE_ID);
        }
    }

    private GrpcAuthzClient buildClient(AuthorizationServiceGrpc.AuthorizationServiceImplBase service,
                                         RefreshGuard guard, SessionState session) throws Exception {
        String serverName = InProcessServerBuilder.generateName();
        Server server = InProcessServerBuilder.forName(serverName)
                .directExecutor()
                .addService(service)
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
}
