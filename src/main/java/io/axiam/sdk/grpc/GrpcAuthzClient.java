package io.axiam.sdk.grpc;

import axiam.v1.Authorization.BatchCheckAccessRequest;
import axiam.v1.Authorization.BatchCheckAccessResponse;
import axiam.v1.Authorization.CheckAccessRequest;
import axiam.v1.Authorization.CheckAccessResponse;
import axiam.v1.AuthorizationServiceGrpc;
import axiam.v1.AuthorizationServiceGrpc.AuthorizationServiceBlockingStub;
import axiam.v1.AuthorizationServiceGrpc.AuthorizationServiceFutureStub;
import axiam.v1.Userinfo.GetUserInfoRequest;
import axiam.v1.Userinfo.GetUserInfoResponse;
import axiam.v1.UserInfoServiceGrpc;
import axiam.v1.UserInfoServiceGrpc.UserInfoServiceBlockingStub;
import axiam.v1.UserInfoServiceGrpc.UserInfoServiceFutureStub;

import axiam.v1.Token.CnfClaim;
import axiam.v1.Token.IntrospectTokenRequest;
import axiam.v1.Token.IntrospectTokenResponse;
import axiam.v1.Token.RptPermission;
import axiam.v1.Token.ValidateTokenRequest;
import axiam.v1.Token.ValidateTokenResponse;
import axiam.v1.TokenServiceGrpc;
import axiam.v1.TokenServiceGrpc.TokenServiceBlockingStub;
import axiam.v1.TokenServiceGrpc.TokenServiceFutureStub;

import io.axiam.sdk.Sensitive;

import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.MoreExecutors;

import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.ErrorMapper;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.internal.RefreshGuard;
import io.axiam.sdk.internal.SessionState;

import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * gRPC authz transport (CONTRACT.md &sect;1/&sect;2/&sect;5/&sect;9, D-11).
 * Wraps ONE long-lived {@code ManagedChannel} (via
 * {@link AuthClientInterceptor#channelBuilder}, strict TLS + the
 * metadata-injecting interceptor), sharing both a blocking and a
 * {@code CompletableFuture}-adapted async ({@code ListenableFuture}-backed)
 * stub over that same channel.
 *
 * <p>Constructed from the SAME {@link RefreshGuard} + {@link SessionState}
 * {@code AxiamClient}'s REST transport uses (D-07/D-11's "one guard") — never
 * a second guard instance. On {@code UNAUTHENTICATED}, drives exactly one
 * {@link RefreshGuard#refreshIfNeeded} call then retries exactly once
 * (&sect;9.3); a terminal error routes through the central
 * {@link ErrorMapper#fromGrpcStatus}.
 *
 * <p>{@code tenant_id}/{@code subject_id} on the wire request are resolved
 * from the CURRENT access token's (unverified-decode) claims, not the raw
 * configured tenant identifier — the real server
 * ({@code axiam-api-grpc/src/services/authorization.rs}) cross-validates
 * both body fields against the verified JWT claims and rejects on any
 * mismatch (PERMISSION_DENIED), so a human-readable {@code tenantSlug}
 * would never pass that check.
 */
public final class GrpcAuthzClient implements AutoCloseable {

    private final RefreshGuard refreshGuard;
    private final SessionState session;
    private final ManagedChannel channel;
    private final AuthorizationServiceBlockingStub blockingStub;
    private final AuthorizationServiceFutureStub futureStub;
    // UserInfoService (CONTRACT.md §1.1) rides the SAME channel/interceptor as the
    // authz stubs above — a second gRPC-only operation, never a second channel.
    private final UserInfoServiceBlockingStub userInfoBlockingStub;
    private final UserInfoServiceFutureStub userInfoFutureStub;
    // TokenService (CONTRACT.md §1.1.1/§10.3, contract 1.51) — the SAME channel and
    // interceptor as every other stub on this client, never a second connection.
    private final TokenServiceBlockingStub tokenBlockingStub;
    private final TokenServiceFutureStub tokenFutureStub;

    /**
     * Creates a gRPC authz client bound to {@code target}, sharing the given refresh
     * guard and session with the SDK's REST transport.
     *
     * @param target       a plain gRPC target (e.g. {@code "dns:///host:9443"}) for
     *                      AXIAM's {@code AuthorizationService} — distinct from the
     *                      REST {@code baseUrl}
     * @param refreshGuard the SAME {@link RefreshGuard} instance the client's REST
     *                      transport uses (D-07) — never a second guard
     * @param session       the client's shared {@link SessionState} (tenant id,
     *                      cached access token, {@code doHttpRefresh()})
     * @param customCaPem   optional PEM-encoded custom CA (&sect;6) — {@code null}
     *                      to trust only the system trust store
     */
    public GrpcAuthzClient(String target, RefreshGuard refreshGuard, SessionState session,
                            byte @Nullable [] customCaPem) {
        this(target, refreshGuard, session, customCaPem, null, null);
    }

    /**
     * mTLS overload (CONTRACT.md &sect;6.1): builds the gRPC channel presenting
     * a client-side X.509 identity (PEM cert chain + PKCS#8 private key) so this
     * gRPC transport authenticates by client certificate, matching the REST
     * transport of the same {@code AxiamClient}. When {@code clientCertPem}/
     * {@code clientKeyPem} are {@code null} this behaves exactly like
     * {@link #GrpcAuthzClient(String, RefreshGuard, SessionState, byte[])}.
     * Server verification (strict system trust store + optional
     * {@code customCaPem}) is unchanged — a client certificate never relaxes it.
     *
     * @param target        a plain gRPC target (e.g. {@code "dns:///host:9443"}) for
     *                      AXIAM's {@code AuthorizationService}
     * @param refreshGuard  the SAME {@link RefreshGuard} instance the client's REST
     *                      transport uses (D-07) — never a second guard
     * @param session       the client's shared {@link SessionState}
     * @param customCaPem   optional PEM-encoded custom CA (&sect;6), or {@code null}
     * @param clientCertPem optional PEM-encoded client certificate chain for mTLS
     *                      (leaf first), or {@code null}
     * @param clientKeyPem  the PEM-encoded PKCS#8 private key matching
     *                      {@code clientCertPem}, or {@code null}
     */
    public GrpcAuthzClient(String target, RefreshGuard refreshGuard, SessionState session,
                            byte @Nullable [] customCaPem, byte @Nullable [] clientCertPem,
                            byte @Nullable [] clientKeyPem) {
        this.refreshGuard = refreshGuard;
        this.session = session;

        NettyChannelBuilder channelBuilder =
                AuthClientInterceptor.channelBuilder(target, customCaPem, clientCertPem, clientKeyPem)
                .intercept(new AuthClientInterceptor(() -> currentAccessToken(refreshGuard, session), session.tenantId()));
        this.channel = channelBuilder.build();
        this.blockingStub = AuthorizationServiceGrpc.newBlockingStub(channel);
        this.futureStub = AuthorizationServiceGrpc.newFutureStub(channel);
        this.userInfoBlockingStub = UserInfoServiceGrpc.newBlockingStub(channel);
        this.userInfoFutureStub = UserInfoServiceGrpc.newFutureStub(channel);
        this.tokenBlockingStub = TokenServiceGrpc.newBlockingStub(channel);
        this.tokenFutureStub = TokenServiceGrpc.newFutureStub(channel);
    }

    /**
     * Test-only seam: builds from an already-constructed {@link ManagedChannel} (e.g. an
     * in-process channel with its own {@link AuthClientInterceptor} attached by the caller),
     * bypassing the public constructor's strict-TLS Netty channel construction.
     * Package-private — only {@code GrpcAuthzClientTest} (same package) uses this.
     */
    GrpcAuthzClient(ManagedChannel channel, RefreshGuard refreshGuard, SessionState session) {
        this.refreshGuard = refreshGuard;
        this.session = session;
        this.channel = channel;
        this.blockingStub = AuthorizationServiceGrpc.newBlockingStub(channel);
        this.futureStub = AuthorizationServiceGrpc.newFutureStub(channel);
        this.userInfoBlockingStub = UserInfoServiceGrpc.newBlockingStub(channel);
        this.userInfoFutureStub = UserInfoServiceGrpc.newFutureStub(channel);
        this.tokenBlockingStub = TokenServiceGrpc.newBlockingStub(channel);
        this.tokenFutureStub = TokenServiceGrpc.newFutureStub(channel);
    }

    // ------------------------------------------------------------------
    // AutoCloseable (D-09) — the channel is shut down with the client.
    // ------------------------------------------------------------------

    @Override
    public void close() {
        channel.shutdown();
        try {
            if (!channel.awaitTermination(5, TimeUnit.SECONDS)) {
                channel.shutdownNow();
            }
        } catch (InterruptedException e) {
            channel.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    // ------------------------------------------------------------------
    // Public request/result shapes (CONTRACT.md §1)
    // ------------------------------------------------------------------

    /** The outcome of a single authorization check (mirrors {@code CheckAccessResponse}).
     *
     * @param allowed whether the checked action is permitted
     * @param reason  a human-readable deny reason, or {@code null} when {@code allowed} is
     *                {@code true} or the server did not supply one. Sourced from the wire
     *                response's {@code reason} (field 4, contract 1.19), falling back to the
     *                deprecated {@code deny_reason} (field 2) only when {@code reason} is absent
     *                (CONTRACT.md &sect;11.2 rule 9, SDK-Q10). This is the SDK's ONE reason
     *                accessor; {@code deny_reason} is never exposed on the public surface
     * @param reasonCode machine-readable decision reason (CONTRACT.md &sect;11 rule 9, B1 deny-override): {@code "allowed"}, {@code "no_grant"} or {@code "denied_by_rule"}. <strong>The two refusals mean opposite things to the person on the other end</strong> — {@code no_grant} says <em>ask an admin for access</em>, {@code denied_by_rule} says <em>an admin has already decided</em> — which is why the contract forbids collapsing them into a bare {@code false}. {@code null} when the server omits the field, so a newer SDK against an older server degrades rather than failing. An unrecognised value is surfaced verbatim and never changes {@code allowed}, which is why this is a {@code String} rather than an enum
     */
    public record AccessResult(boolean allowed, @Nullable String reason, @Nullable String reasonCode) {
    }

    /** A single access check request for {@link #batchCheck}. {@code subjectId} defaults to
     * the caller (the current access token's {@code sub} claim) when {@code null}.
     *
     * @param subjectId  the subject to check, or {@code null} to default to the caller
     *                   (the current access token's {@code sub} claim)
     * @param action     the action being checked (CONTRACT.md &sect;1)
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     */
    public record AccessCheck(@Nullable String subjectId, String action, String resourceId,
                               @Nullable String scope) {
        /** Convenience constructor for a check on the caller's own subject, with no scope.
         *
         * @param action     the action being checked
         * @param resourceId the resource identifier the action is checked against
         */
        public AccessCheck(String action, String resourceId) {
            this(null, action, resourceId, null);
        }

        /** Convenience constructor for a check on the caller's own subject.
         *
         * @param action     the action being checked
         * @param resourceId the resource identifier the action is checked against
         * @param scope      an optional sub-resource scope qualifier, or {@code null}
         */
        public AccessCheck(String action, String resourceId, @Nullable String scope) {
            this(null, action, resourceId, scope);
        }
    }

    /**
     * The authenticated caller's identity claims (CONTRACT.md &sect;1.1), mirroring
     * the server's REST {@code GET /oauth2/userinfo} claim set. {@code sub},
     * {@code tenantId}, and {@code orgId} are always populated; {@code email} is
     * present only when the access token carries the {@code "email"} scope and
     * {@code preferredUsername} only with the {@code "profile"} scope (the server
     * gates these exactly as the REST endpoint does).
     *
     * @param sub               the subject (user) UUID — always present
     * @param tenantId          the tenant UUID — always present
     * @param orgId             the organization UUID — always present
     * @param email             the user email, present only with the {@code "email"} scope
     * @param preferredUsername the preferred username, present only with the {@code "profile"} scope
     */
    public record UserInfo(String sub, String tenantId, String orgId, Optional<String> email,
                            Optional<String> preferredUsername) {
    }

    // ------------------------------------------------------------------
    // checkAccess (blocking + async)
    // ------------------------------------------------------------------

    /** {@link #checkAccess(String, String, String, String)} on the caller's own subject, with no scope.
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @return the check outcome (allowed/denied, with an optional deny reason)
     */
    public AccessResult checkAccess(String action, String resourceId) {
        return checkAccess(null, action, resourceId, null);
    }

    /** {@link #checkAccess(String, String, String, String)} on the caller's own subject.
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     * @return the check outcome (allowed/denied, with an optional deny reason)
     */
    public AccessResult checkAccess(String action, String resourceId, @Nullable String scope) {
        return checkAccess(null, action, resourceId, scope);
    }

    /**
     * {@code CheckAccess} (CONTRACT.md &sect;1). On {@code UNAUTHENTICATED}, drives the shared
     * {@link RefreshGuard} exactly once and retries the RPC exactly once (&sect;9.3); a terminal
     * error maps via {@link ErrorMapper#fromGrpcStatus}.
     *
     * @param subjectId  the subject to check, or {@code null} to default to the caller
     *                   (the current access token's {@code sub} claim)
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     * @return the check outcome (allowed/denied, with an optional deny reason)
     */
    public AccessResult checkAccess(@Nullable String subjectId, String action, String resourceId,
                                     @Nullable String scope) {
        CheckAccessRequest wire = toWire(subjectId, action, resourceId, scope);
        AuthorizationServiceBlockingStub stub = deadlinedBlockingStub(AuthClientInterceptor.CHECK_ACCESS_DEADLINE);
        return callWithRefreshRetry(() -> toAccessResult(stub.checkAccess(wire)));
    }

    /** {@link #checkAccessAsync(String, String, String, String)} on the caller's own subject, with no scope.
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @return a future resolving to the check outcome
     */
    public CompletableFuture<AccessResult> checkAccessAsync(String action, String resourceId) {
        return checkAccessAsync(null, action, resourceId, null);
    }

    /** {@link #checkAccessAsync(String, String, String, String)} on the caller's own subject.
     *
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     * @return a future resolving to the check outcome
     */
    public CompletableFuture<AccessResult> checkAccessAsync(String action, String resourceId, @Nullable String scope) {
        return checkAccessAsync(null, action, resourceId, scope);
    }

    /** {@code CompletableFuture} async twin of {@link #checkAccess}, adapting the
     * {@code ListenableFuture}-based future stub (D-02). Same shared-guard refresh-retry
     * semantics as the blocking path.
     *
     * @param subjectId  the subject to check, or {@code null} to default to the caller
     *                   (the current access token's {@code sub} claim)
     * @param action     the action being checked
     * @param resourceId the resource identifier the action is checked against
     * @param scope      an optional sub-resource scope qualifier, or {@code null}
     * @return a future resolving to the check outcome
     */
    public CompletableFuture<AccessResult> checkAccessAsync(@Nullable String subjectId, String action,
                                                              String resourceId, @Nullable String scope) {
        CheckAccessRequest wire = toWire(subjectId, action, resourceId, scope);
        AuthorizationServiceFutureStub stub = deadlinedFutureStub(AuthClientInterceptor.CHECK_ACCESS_DEADLINE);
        return callAsyncWithRefreshRetry(() -> stub.checkAccess(wire)).thenApply(GrpcAuthzClient::toAccessResult);
    }

    // ------------------------------------------------------------------
    // batchCheck (blocking + async) — results preserve input order
    // ------------------------------------------------------------------

    /**
     * {@code BatchCheckAccess} (CONTRACT.md &sect;1); results are returned in the same order as
     * {@code checks}. Shares the same UNAUTHENTICATED single-flight-retry behavior as
     * {@link #checkAccess}.
     *
     * @param checks the ordered list of checks to evaluate
     * @return the outcomes, in the same order as {@code checks}
     */
    public List<AccessResult> batchCheck(List<AccessCheck> checks) {
        BatchCheckAccessRequest wire = toWireBatch(checks);
        AuthorizationServiceBlockingStub stub = deadlinedBlockingStub(AuthClientInterceptor.BATCH_CHECK_ACCESS_DEADLINE);
        return callWithRefreshRetry(() -> toAccessResults(stub.batchCheckAccess(wire)));
    }

    /** {@code CompletableFuture} async twin of {@link #batchCheck}.
     *
     * @param checks the ordered list of checks to evaluate
     * @return a future resolving to the outcomes, in the same order as {@code checks}
     */
    public CompletableFuture<List<AccessResult>> batchCheckAsync(List<AccessCheck> checks) {
        BatchCheckAccessRequest wire = toWireBatch(checks);
        AuthorizationServiceFutureStub stub = deadlinedFutureStub(AuthClientInterceptor.BATCH_CHECK_ACCESS_DEADLINE);
        return callAsyncWithRefreshRetry(() -> stub.batchCheckAccess(wire)).thenApply(GrpcAuthzClient::toAccessResults);
    }

    // ------------------------------------------------------------------
    // getUserInfo (blocking + async) — gRPC-only (CONTRACT.md §1.1)
    // ------------------------------------------------------------------

    /**
     * {@code GetUserInfo} (CONTRACT.md &sect;1.1) — the low-latency gRPC counterpart of the
     * server's REST {@code GET /oauth2/userinfo} endpoint. The request is empty; identity is
     * derived entirely server-side from the {@code authorization} bearer token this transport
     * already injects (&sect;5). Requires a prior successful {@code login()} (or an injected
     * token): calling it with no token raises {@link AuthError} client-side without a wire call
     * (&sect;1.1 point 3). On {@code UNAUTHENTICATED}, drives the shared {@link RefreshGuard}
     * exactly once and retries the RPC exactly once (&sect;9.3); a terminal error maps via
     * {@link ErrorMapper#fromGrpcStatus}.
     *
     * @return the caller's identity claims ({@code sub}/{@code tenantId}/{@code orgId} always
     *         present; {@code email}/{@code preferredUsername} gated on the {@code "email"}/
     *         {@code "profile"} scopes)
     */
    public UserInfo getUserInfo() {
        requireTokenPreflight();
        GetUserInfoRequest wire = GetUserInfoRequest.getDefaultInstance();
        UserInfoServiceBlockingStub stub = deadlinedUserInfoBlockingStub(AuthClientInterceptor.USER_INFO_DEADLINE);
        return callWithRefreshRetry(() -> toUserInfo(stub.getUserInfo(wire)));
    }

    /** {@code CompletableFuture} async twin of {@link #getUserInfo}, adapting the
     * {@code ListenableFuture}-based future stub (D-02). Same pre-flight token check and
     * shared-guard refresh-retry semantics as the blocking path; the pre-flight
     * {@link AuthError} surfaces as a failed future.
     *
     * @return a future resolving to the caller's identity claims
     */
    public CompletableFuture<UserInfo> getUserInfoAsync() {
        try {
            requireTokenPreflight();
        } catch (RuntimeException preflightFailure) {
            CompletableFuture<UserInfo> failed = new CompletableFuture<>();
            failed.completeExceptionally(preflightFailure);
            return failed;
        }
        GetUserInfoRequest wire = GetUserInfoRequest.getDefaultInstance();
        UserInfoServiceFutureStub stub = deadlinedUserInfoFutureStub(AuthClientInterceptor.USER_INFO_DEADLINE);
        return callAsyncWithRefreshRetry(() -> stub.getUserInfo(wire)).thenApply(GrpcAuthzClient::toUserInfo);
    }

    /** Pre-flight guard (CONTRACT.md &sect;1.1 point 3): {@code get_user_info} carries no wire
     * fields to resolve claims from, so a missing token is caught here — client-side, without a
     * wire call — as an {@link AuthError}, mirroring {@link #resolveClaims}'s no-session error. */
    private void requireTokenPreflight() {
        if (currentAccessToken(refreshGuard, session) == null) {
            throw new AuthError("no active session — call login() before getUserInfo()");
        }
    }

    private static UserInfo toUserInfo(GetUserInfoResponse resp) {
        return new UserInfo(
                resp.getSub(),
                resp.getTenantId(),
                resp.getOrgId(),
                resp.hasEmail() ? Optional.of(resp.getEmail()) : Optional.empty(),
                resp.hasPreferredUsername() ? Optional.of(resp.getPreferredUsername()) : Optional.empty());
    }

    // ------------------------------------------------------------------
    // validateToken / introspectToken (blocking + async) — gRPC-only
    // (CONTRACT.md §1.1.1/§10.3, contract 1.51)
    // ------------------------------------------------------------------

    /**
     * A confirmation claim (RFC 7800), exactly as the wire carries it — no method named is an
     * <strong>unverifiable</strong> constraint, never an absent one (CONTRACT.md &sect;10.1 rule
     * 9 detail 3, &sect;10.3 rule 3).
     *
     * @param x5tS256 the RFC 8705 &sect;3.1 certificate-bound confirmation, or {@code null} when
     *                this token does not name one
     * @param jkt     the RFC 9449 &sect;6.1 DPoP-bound confirmation, or {@code null} when this
     *                token does not name one
     */
    public record CnfConfirmation(@Nullable String x5tS256, @Nullable String jkt) {

        /**
         * Whether this confirmation names a method neither field above carries — present, but
         * empty. That is not the same as no confirmation at all: an absent {@code cnf} (this
         * record itself being {@code null} on the enclosing response) means unbound; a non-null
         * {@code CnfConfirmation} with both fields {@code null} means bound by a method this
         * response could not name, and CONTRACT.md &sect;10.1 rule 9's "present, but an empty
         * object" row applies — reject, never read as unconstrained.
         *
         * @return {@code true} when neither {@link #x5tS256()} nor {@link #jkt()} is set
         */
        public boolean namesNoMethod() {
            return x5tS256 == null && jkt == null;
        }
    }

    /**
     * {@code ValidateToken} (CONTRACT.md &sect;1.1.1) — the typed value every field of {@code
     * ValidateTokenResponse} maps onto.
     *
     * <p><strong>{@code valid} is not "usable as presented"</strong> (&sect;10.3 rule 2): when
     * {@link #cnf()} is present, this SDK does not — cannot, from this response alone — verify
     * possession against the caller's own connection. Combine it with the evidence your own
     * transport can offer (a peer certificate, a verified DPoP proof) the same way {@code
     * JwksVerifier#verifyTokenBinding} does for a locally-verified token, per CONTRACT.md
     * &sect;10.1 rule 9's table. {@link #tokenType()} MUST NOT be read as deciding boundness —
     * a certificate-bound token still reports {@code "Bearer"} (&sect;1.1.1 rule 5).
     *
     * @param valid     whether the signature, expiry and tenant check out (NOT "usable as
     *                  presented" — see above)
     * @param subjectId the subject UUID, empty when {@code valid} is {@code false}
     * @param tenantId  the tenant UUID, empty when {@code valid} is {@code false}
     * @param orgId     the organization UUID, empty when {@code valid} is {@code false}
     * @param exp       the expiry (Unix seconds), zero when {@code valid} is {@code false}
     * @param cnf       the confirmation claim, or {@code null} when this token is unbound —
     *                  distinct from a present-but-empty {@link CnfConfirmation}
     * @param tokenType {@code "Bearer"} or {@code "DPoP"} (&sect;1.1.1 rule 5)
     */
    public record TokenValidation(boolean valid, String subjectId, String tenantId, String orgId,
                                  long exp, @Nullable CnfConfirmation cnf, String tokenType) {
    }

    /**
     * {@code IntrospectToken} (CONTRACT.md &sect;1.1.1) — the RFC 7662 set, plus &sect;10.3's
     * parity fields. The same &sect;10.3 rule 2 caveat as {@link TokenValidation#valid()} applies
     * to {@link #active()}.
     *
     * @param active          RFC 7662's active flag — see the {@link TokenValidation} javadoc's
     *                        "not usable as presented" note; the same rule governs this field
     * @param sub             the subject UUID
     * @param tenantId        the tenant UUID
     * @param orgId           the organization UUID
     * @param iss             the issuer
     * @param iat             issued-at (Unix seconds)
     * @param exp             expiry (Unix seconds)
     * @param jti             the token's unique id
     * @param scope           space-separated granted scopes, or {@code null} when the token
     *                        carries no scope claim
     * @param clientId        the client the token was issued to, or {@code null}
     * @param tokenType       {@code "Bearer"} or {@code "DPoP"} — never decides boundness alone
     * @param cnf             the confirmation claim, or {@code null} when unbound
     * @param permissions     UMA 2.0 permissions, present only on an RPT
     * @param extExchangeIss  the foreign issuer whose subject token bought this one via RFC 8693
     *                        cross-domain exchange, or {@code null}
     */
    public record TokenIntrospection(boolean active, String sub, String tenantId, String orgId,
                                     String iss, long iat, long exp, String jti,
                                     @Nullable String scope, @Nullable String clientId,
                                     String tokenType, @Nullable CnfConfirmation cnf,
                                     List<RptPermissionInfo> permissions,
                                     @Nullable String extExchangeIss) {
    }

    /**
     * One UMA 2.0 permission carried by an RPT (X2).
     *
     * @param resourceId the resource UUID
     * @param resourceScopes the scopes granted on that resource
     * @param exp the absolute expiry of THIS permission (Unix seconds)
     */
    public record RptPermissionInfo(String resourceId, List<String> resourceScopes, long exp) {
    }

    /**
     * {@code TokenService/ValidateToken} (CONTRACT.md &sect;1.1.1, &sect;10.3). Two tokens are
     * kept apart (rule 1): the CALLER's own bearer token authenticates this call through the
     * interceptor exactly like every other RPC on this client, and {@code accessToken} — the
     * token being inspected — travels only in the request message. The two are never the same
     * parameter, and this method never defaults one to the other.
     *
     * <p>With no caller token this refuses client-side, with <strong>zero wire calls</strong>
     * (rule 2), exactly as {@link #getUserInfo()} does.
     *
     * @param accessToken the token to validate — secret material, {@link Sensitive}
     * @return every field the response carries, typed
     * @throws AuthError if this client has no active session to authenticate the CALL itself
     */
    public TokenValidation validateToken(Sensitive accessToken) {
        requireTokenPreflight();
        ValidateTokenRequest wire = ValidateTokenRequest.newBuilder()
                .setAccessToken(accessToken.expose())
                .build();
        TokenServiceBlockingStub stub = deadlinedTokenBlockingStub(AuthClientInterceptor.USER_INFO_DEADLINE);
        return callWithRefreshRetry(() -> toTokenValidation(stub.validateToken(wire)));
    }

    /** {@code CompletableFuture} async twin of {@link #validateToken(Sensitive)}.
     *
     * @param accessToken the token to validate — secret material, {@link Sensitive}
     * @return a future resolving to every field the response carries
     */
    public CompletableFuture<TokenValidation> validateTokenAsync(Sensitive accessToken) {
        try {
            requireTokenPreflight();
        } catch (RuntimeException preflightFailure) {
            CompletableFuture<TokenValidation> failed = new CompletableFuture<>();
            failed.completeExceptionally(preflightFailure);
            return failed;
        }
        ValidateTokenRequest wire = ValidateTokenRequest.newBuilder()
                .setAccessToken(accessToken.expose())
                .build();
        TokenServiceFutureStub stub = deadlinedTokenFutureStub(AuthClientInterceptor.USER_INFO_DEADLINE);
        return callAsyncWithRefreshRetry(() -> stub.validateToken(wire)).thenApply(GrpcAuthzClient::toTokenValidation);
    }

    /**
     * {@code TokenService/IntrospectToken} (CONTRACT.md &sect;1.1.1, &sect;10.3) — the RFC 7662
     * counterpart of {@link #validateToken(Sensitive)}, with the same rules 1 and 2.
     *
     * @param accessToken the token to introspect — secret material, {@link Sensitive}
     * @return every field the response carries, typed
     * @throws AuthError if this client has no active session to authenticate the CALL itself
     */
    public TokenIntrospection introspectToken(Sensitive accessToken) {
        requireTokenPreflight();
        IntrospectTokenRequest wire = IntrospectTokenRequest.newBuilder()
                .setAccessToken(accessToken.expose())
                .build();
        TokenServiceBlockingStub stub = deadlinedTokenBlockingStub(AuthClientInterceptor.USER_INFO_DEADLINE);
        return callWithRefreshRetry(() -> toTokenIntrospection(stub.introspectToken(wire)));
    }

    /** {@code CompletableFuture} async twin of {@link #introspectToken(Sensitive)}.
     *
     * @param accessToken the token to introspect — secret material, {@link Sensitive}
     * @return a future resolving to every field the response carries
     */
    public CompletableFuture<TokenIntrospection> introspectTokenAsync(Sensitive accessToken) {
        try {
            requireTokenPreflight();
        } catch (RuntimeException preflightFailure) {
            CompletableFuture<TokenIntrospection> failed = new CompletableFuture<>();
            failed.completeExceptionally(preflightFailure);
            return failed;
        }
        IntrospectTokenRequest wire = IntrospectTokenRequest.newBuilder()
                .setAccessToken(accessToken.expose())
                .build();
        TokenServiceFutureStub stub = deadlinedTokenFutureStub(AuthClientInterceptor.USER_INFO_DEADLINE);
        return callAsyncWithRefreshRetry(() -> stub.introspectToken(wire))
                .thenApply(GrpcAuthzClient::toTokenIntrospection);
    }

    private TokenServiceBlockingStub deadlinedTokenBlockingStub(java.time.Duration deadline) {
        return tokenBlockingStub.withDeadlineAfter(deadline.toMillis(), TimeUnit.MILLISECONDS);
    }

    private TokenServiceFutureStub deadlinedTokenFutureStub(java.time.Duration deadline) {
        return tokenFutureStub.withDeadlineAfter(deadline.toMillis(), TimeUnit.MILLISECONDS);
    }

    /**
     * proto3 delivers an EMPTY {@code CnfClaim} message for a token with no confirmation (there
     * is no separate "absent" wire state for a nested message field short of {@code has_cnf}),
     * so {@code hasCnf()} — not field defaults — is what distinguishes "unbound" from "bound by
     * an empty confirmation" (CONTRACT.md &sect;10.3 rule 3). Field defaults inside a present
     * {@code CnfClaim} (an empty string for {@code x5t_s256}/{@code jkt}) map to {@code null},
     * exactly as {@link CnfConfirmation#namesNoMethod()} depends on.
     */
    private static @Nullable CnfConfirmation toCnfConfirmation(boolean hasCnf, CnfClaim claim) {
        if (!hasCnf) {
            return null;
        }
        String x5t = claim.getX5TS256().isEmpty() ? null : claim.getX5TS256();
        String jkt = claim.getJkt().isEmpty() ? null : claim.getJkt();
        return new CnfConfirmation(x5t, jkt);
    }

    private static TokenValidation toTokenValidation(ValidateTokenResponse resp) {
        return new TokenValidation(
                resp.getValid(),
                resp.getSubjectId(),
                resp.getTenantId(),
                resp.getOrgId(),
                resp.getExp(),
                toCnfConfirmation(resp.hasCnf(), resp.getCnf()),
                resp.getTokenType());
    }

    private static TokenIntrospection toTokenIntrospection(IntrospectTokenResponse resp) {
        List<RptPermissionInfo> permissions = new ArrayList<>();
        for (RptPermission p : resp.getPermissionsList()) {
            permissions.add(new RptPermissionInfo(
                    p.getResourceId(), List.copyOf(p.getResourceScopesList()), p.getExp()));
        }
        return new TokenIntrospection(
                resp.getActive(),
                resp.getSub(),
                resp.getTenantId(),
                resp.getOrgId(),
                resp.getIss(),
                resp.getIat(),
                resp.getExp(),
                resp.getJti(),
                resp.getScope().isEmpty() ? null : resp.getScope(),
                resp.getClientId().isEmpty() ? null : resp.getClientId(),
                resp.getTokenType(),
                toCnfConfirmation(resp.hasCnf(), resp.getCnf()),
                List.copyOf(permissions),
                resp.getExtExchangeIss().isEmpty() ? null : resp.getExtExchangeIss());
    }

    // ------------------------------------------------------------------
    // Deadlines (D-12) — default per Task 1's constants, overridable at the
    // call site via the returned stub's own withDeadlineAfter.
    // ------------------------------------------------------------------

    private AuthorizationServiceBlockingStub deadlinedBlockingStub(java.time.Duration deadline) {
        return blockingStub.withDeadlineAfter(deadline.toMillis(), TimeUnit.MILLISECONDS);
    }

    private AuthorizationServiceFutureStub deadlinedFutureStub(java.time.Duration deadline) {
        return futureStub.withDeadlineAfter(deadline.toMillis(), TimeUnit.MILLISECONDS);
    }

    private UserInfoServiceBlockingStub deadlinedUserInfoBlockingStub(java.time.Duration deadline) {
        return userInfoBlockingStub.withDeadlineAfter(deadline.toMillis(), TimeUnit.MILLISECONDS);
    }

    private UserInfoServiceFutureStub deadlinedUserInfoFutureStub(java.time.Duration deadline) {
        return userInfoFutureStub.withDeadlineAfter(deadline.toMillis(), TimeUnit.MILLISECONDS);
    }

    // ------------------------------------------------------------------
    // Shared-guard refresh-retry (§9.3: retry exactly once, never a loop)
    // ------------------------------------------------------------------

    private <T> T callWithRefreshRetry(Supplier<T> call) {
        try {
            return call.get();
        } catch (StatusRuntimeException e) {
            // CONTRACT 1.52 N4.5 (C-12): a device credential is never refreshed,
            // on either transport — its own UNAUTHENTICATED is terminal, exactly
            // like the REST 401 AuthAuthenticator leaves alone for the same
            // credential. There is no refresh token for it (§6.1 rule 6), so
            // entering the guard would only spend a wire call on nothing.
            if (isUnauthenticated(e) && !session.hasAdoptedAccessToken()) {
                doRefresh();
                try {
                    return call.get();
                } catch (StatusRuntimeException retryException) {
                    throw mapToRuntime(retryException);
                }
            }
            throw mapToRuntime(e);
        }
    }

    private <T> CompletableFuture<T> callAsyncWithRefreshRetry(Supplier<ListenableFuture<T>> call) {
        return toCompletableFuture(call.get())
                .handle((result, error) -> {
                    if (error == null) {
                        return CompletableFuture.completedFuture(result);
                    }
                    Throwable cause = unwrap(error);
                    // N4.5 (C-12): same rule as the blocking path above.
                    if (isUnauthenticated(cause) && !session.hasAdoptedAccessToken()) {
                        return CompletableFuture.runAsync(this::doRefresh)
                                .thenCompose(unused -> toCompletableFuture(call.get()))
                                .handle((retryResult, retryError) -> {
                                    if (retryError != null) {
                                        throw mapToRuntime(unwrap(retryError));
                                    }
                                    return retryResult;
                                });
                    }
                    CompletableFuture<T> failed = new CompletableFuture<>();
                    failed.completeExceptionally(mapToRuntime(cause));
                    return failed;
                })
                .thenCompose(Function.identity());
    }

    /** Drives the SAME {@link RefreshGuard} instance REST uses (D-07/D-11) — never a second
     * guard, mirroring {@code AxiamClient.refresh()}'s exact call shape. */
    private void doRefresh() {
        String observedAccess = currentAccessToken(refreshGuard, session);
        refreshGuard.refreshIfNeeded(observedAccess == null ? "" : observedAccess, session::doHttpRefresh);
    }

    /**
     * The token this transport currently considers "current": the shared
     * {@link RefreshGuard}'s cache when populated, falling back to the
     * {@link SessionState} cookie-jar-backed token otherwise. The guard's
     * cache is empty until the FIRST refresh ever happens on this client —
     * {@code AxiamClient.login()} only sets cookies, it never seeds the
     * guard — so a gRPC call made immediately after {@code login()} (before
     * any refresh) still needs the cookie-jar fallback, exactly like the
     * REST {@code AuthInterceptor}'s token source. Non-blocking: neither
     * read acquires {@link RefreshGuard}'s lock.
     *
     * <p>CONTRACT 1.52 N4.3 (C-12): an adopted &sect;6.1 device token takes
     * priority over the guard's cache unconditionally. The guard's cache can
     * hold a PRIOR cookie-session's access token from a refresh that happened
     * before {@code authenticateDevice()} was ever called — that entry is not
     * cleared by adoption (it belongs to the guard, not the session) — so
     * falling through to it here would send the wrong credential's token on
     * every gRPC call this transport makes after adoption.
     */
    static @Nullable String currentAccessToken(RefreshGuard refreshGuard, SessionState session) {
        if (session.hasAdoptedAccessToken()) {
            return session.cachedAccessToken();
        }
        String cached = refreshGuard.cachedAccessToken();
        return cached != null ? cached : session.cachedAccessToken();
    }

    // ------------------------------------------------------------------
    // Wire mapping (proto/axiam/v1/authorization.proto)
    // ------------------------------------------------------------------

    private CheckAccessRequest toWire(@Nullable String subjectId, String action, String resourceId,
                                       @Nullable String scope) {
        SessionState.Claims claims = resolveClaims();
        String resolvedSubjectId = subjectId != null ? subjectId : requireClaim(claims.sub(), "sub");
        String resolvedTenantId = requireClaim(claims.tenantId(), "tenant_id");

        CheckAccessRequest.Builder builder = CheckAccessRequest.newBuilder()
                .setTenantId(resolvedTenantId)
                .setSubjectId(resolvedSubjectId)
                .setAction(action)
                .setResourceId(resourceId);
        if (scope != null) {
            builder.setScope(scope);
        }
        return builder.build();
    }

    private BatchCheckAccessRequest toWireBatch(List<AccessCheck> checks) {
        BatchCheckAccessRequest.Builder builder = BatchCheckAccessRequest.newBuilder();
        for (AccessCheck check : checks) {
            builder.addRequests(toWire(check.subjectId(), check.action(), check.resourceId(), check.scope()));
        }
        return builder.build();
    }

    private SessionState.Claims resolveClaims() {
        String access = currentAccessToken(refreshGuard, session);
        if (access == null) {
            throw new AuthError("no active session — call login() before checkAccess()/batchCheck()");
        }
        SessionState.Claims claims = SessionState.decodeUnverifiedClaims(access);
        if (claims == null) {
            throw new AuthError("failed to decode the current access token's claims");
        }
        return claims;
    }

    private static String requireClaim(@Nullable String value, String claimName) {
        if (value == null) {
            throw new AuthError("access token is missing the '" + claimName
                    + "' claim required for gRPC authz checks");
        }
        return value;
    }

    private static AccessResult toAccessResult(CheckAccessResponse resp) {
        // SDK-Q10 / CONTRACT.md §11.2 rule 9 (contract 1.19): read `reason`
        // (field 4), falling back to the deprecated `deny_reason` (field 2)
        // only when `reason` is absent. `reason` has explicit presence
        // precisely so a client can tell a pre-SDK-Q10 server (refuses with
        // `reason` unset and `deny_reason` populated) from an allow (nothing
        // to say) — which is why the fallback is guarded by `hasReason()`
        // rather than by an emptiness/truthiness check: an explicitly-empty
        // `reason` must NOT fall back to `deny_reason`. Both fields carry the
        // identical string on a current server; `deny_reason` is removed at
        // AXIAM 2.0, at which point this fallback arm — and the
        // `@SuppressWarnings("deprecation")` it needs — goes with it.
        // Callers see one `reason` accessor on {@link AccessResult}, never
        // two.
        @SuppressWarnings("deprecation")
        String reason = resp.hasReason() ? resp.getReason() : resp.getDenyReason();
        // An empty value becomes null rather than "" — the same rule
        // reasonCode follows below, and for the same reason: "" is a value
        // callers could accidentally branch on.
        // proto3 renders an unset `string` as "", so an older server that
        // never set field 3 is indistinguishable from one that set it empty —
        // both mean "no reason code", and both map to null rather than to "".
        String reasonCode = resp.getReasonCode();
        return new AccessResult(
                resp.getAllowed(),
                reason.isEmpty() ? null : reason,
                reasonCode.isEmpty() ? null : reasonCode);
    }

    private static List<AccessResult> toAccessResults(BatchCheckAccessResponse resp) {
        List<AccessResult> results = new ArrayList<>();
        for (CheckAccessResponse item : resp.getResultsList()) {
            results.add(toAccessResult(item));
        }
        return results;
    }

    // ------------------------------------------------------------------
    // ListenableFuture -> CompletableFuture adaptation + error mapping (D-02, §2)
    // ------------------------------------------------------------------

    private static <T> CompletableFuture<T> toCompletableFuture(ListenableFuture<T> future) {
        CompletableFuture<T> completable = new CompletableFuture<>();
        Futures.addCallback(future, new FutureCallback<T>() {
            @Override
            public void onSuccess(T result) {
                completable.complete(result);
            }

            @Override
            public void onFailure(Throwable t) {
                completable.completeExceptionally(t);
            }
        }, MoreExecutors.directExecutor());
        return completable;
    }

    private static Throwable unwrap(Throwable t) {
        return (t instanceof CompletionException && t.getCause() != null) ? t.getCause() : t;
    }

    private static boolean isUnauthenticated(Throwable t) {
        return t instanceof StatusRuntimeException sre && sre.getStatus().getCode() == Status.Code.UNAUTHENTICATED;
    }

    /** Central status&rarr;error mapping (CONTRACT.md &sect;2) via {@link ErrorMapper#fromGrpcStatus} —
     * the single choke point for turning a terminal gRPC failure into the SDK's error taxonomy. */
    private static RuntimeException mapToRuntime(Throwable t) {
        if (t instanceof StatusRuntimeException sre) {
            String description = sre.getStatus().getDescription();
            return ErrorMapper.fromGrpcStatus(sre.getStatus().getCode(),
                    description != null ? description : sre.getStatus().getCode().name());
        }
        if (t instanceof RuntimeException re) {
            return re;
        }
        return new NetworkError("gRPC call failed: " + t.getMessage(), t);
    }
}
