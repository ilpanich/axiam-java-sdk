package io.axiam.sdk.oidc;

import io.axiam.sdk.Sensitive;

import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * The nine canonical OIDC / SSO relying-party operations (CONTRACT.md
 * &sect;12.1/&sect;12.2), implemented by {@code AxiamClient} directly — not a
 * parallel client type (CONTRACT.md &sect;12 T1 reference judgment call 1).
 *
 * <p>Each method below is the <strong>canonical</strong>, full-argument
 * signature; {@code AxiamClient} additionally exposes convenience overloads
 * (fewer arguments, a bare-string alternative to a {@link Sensitive}
 * parameter, and {@code *Async} companions per CONTRACT.md &sect;12.2's Java
 * note) that all delegate to these.
 */
public interface OidcOperations {

    /**
     * {@code GET /.well-known/openid-configuration} (CONTRACT.md &sect;12.1)
     * — fetches the OIDC discovery document, cached per origin with a
     * &ge;5-minute TTL and single-flight de-duplication of concurrent calls
     * (&sect;12.3 rule 6).
     *
     * @return the discovery document
     */
    OidcConfiguration oidcDiscover();

    /**
     * Builds an {@link AuthorizationRequest} (CONTRACT.md &sect;12.1) —
     * <strong>pure local computation, no network I/O</strong>. Nothing is
     * stored: persist the returned {@code state}, {@code nonce}, and
     * {@code codeVerifier} yourself (&sect;12.3 rule 1).
     *
     * @param configuration the discovery document, as returned by {@link #oidcDiscover()}
     * @param redirectUri   the relying party's redirect URI, echoed back into {@code oidcExchange} unchanged
     * @param scope         requested scope, space-separated; {@code openid} is added automatically when absent or {@code null} (&sect;12.1 rule 4)
     * @param extraParams   extra authorization-request parameters (e.g. {@code prompt}, {@code login_hint}); MUST NOT override one of the eight SDK-owned parameters
     * @return the built authorization request
     * @throws IllegalArgumentException if {@code extraParams} tries to override an SDK-owned parameter
     */
    AuthorizationRequest oidcBegin(OidcConfiguration configuration, String redirectUri, @Nullable String scope,
            @Nullable Map<String, String> extraParams);

    /**
     * {@code POST /oauth2/token} with {@code grant_type=authorization_code}
     * (CONTRACT.md &sect;12.1) — exchanges an authorization code for a token
     * set, validating the returned ID token in full before returning
     * (&sect;12.4). On ANY &sect;12.4 failure the whole token set is
     * discarded and {@code AuthError} is raised with the matching reason code
     * (&sect;12.4 rule 7).
     *
     * @param configuration the discovery document the authorization request was built from
     * @param code          the authorization code the IdP redirected back with
     * @param codeVerifier  the verifier from the matching {@link AuthorizationRequest}
     * @param redirectUri   the same {@code redirect_uri} sent on the authorization request
     * @param nonce         the {@code nonce} from the matching {@link AuthorizationRequest}; mandatory
     * @param tenantId      tenant UUID for the token endpoint's required {@code tenant_id} query parameter; {@code null} to default to the client's configured tenant (&sect;12.3 rule 4)
     * @return the validated token set
     */
    OidcTokenSet oidcExchange(OidcConfiguration configuration, String code, Sensitive codeVerifier,
            String redirectUri, String nonce, @Nullable UUID tenantId);

    /**
     * {@code POST /oauth2/token} with {@code grant_type=refresh_token}
     * (CONTRACT.md &sect;12.1) — refreshes an {@link OidcTokenSet}, under the
     * &sect;9 single-flight refresh guard. A distinct operation from
     * {@code AxiamClient.refresh()}.
     *
     * @param refreshToken  the refresh token to redeem
     * @param scope         optional narrowed scope to request; omitted from the form body when {@code null}
     * @param tenantId      tenant UUID for the {@code tenant_id} query parameter; {@code null} to default to the client's configured tenant
     * @param configuration a pre-fetched discovery document; fetched via {@link #oidcDiscover()} when {@code null}
     * @return the refreshed token set
     */
    OidcTokenSet oidcRefresh(Sensitive refreshToken, @Nullable String scope, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration);

    /**
     * {@code POST /oauth2/token} with {@code grant_type=client_credentials}
     * (CONTRACT.md &sect;12.1) — service-account machine-to-machine login.
     * Requests no {@code openid} scope, so the response carries no
     * {@code id_token}.
     *
     * @param scope         optional scope to request
     * @param tenantId      tenant UUID for the {@code tenant_id} query parameter; {@code null} to default to the client's configured tenant
     * @param configuration a pre-fetched discovery document; fetched via {@link #oidcDiscover()} when {@code null}
     * @return the issued token set
     */
    OidcTokenSet loginClientCredentials(@Nullable String scope, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration);

    /**
     * {@code POST /oauth2/introspect} (RFC 7662, CONTRACT.md &sect;12.1) —
     * asks the server whether a token is active. Requires confidential-client
     * credentials (&sect;12.1 note 4).
     *
     * @param token         the token to introspect
     * @param tokenTypeHint optional RFC 7662 {@code token_type_hint}
     * @param tenantId      tenant UUID for the {@code tenant_id} query parameter; {@code null} to default to the client's configured tenant
     * @param configuration a pre-fetched discovery document; fetched via {@link #oidcDiscover()} when {@code null}
     * @return the introspection result
     */
    IntrospectionResult introspect(Sensitive token, @Nullable String tokenTypeHint, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration);

    /**
     * {@code POST /oauth2/revoke} (RFC 7009, CONTRACT.md &sect;12.1) —
     * revokes an access or refresh token. Idempotent: any {@code 200}
     * (including for a token the server has never seen) is success
     * (&sect;12.1 note 5); only a {@code 401} (client authentication failed)
     * is an error.
     *
     * @param token         the token to revoke
     * @param tokenTypeHint optional RFC 7009 {@code token_type_hint}
     * @param tenantId      tenant UUID for the {@code tenant_id} query parameter; {@code null} to default to the client's configured tenant
     * @param configuration a pre-fetched discovery document; fetched via {@link #oidcDiscover()} when {@code null}
     */
    void revoke(Sensitive token, @Nullable String tokenTypeHint, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration);

    /**
     * {@code POST /api/v1/auth/federation/oidc/start} (CONTRACT.md
     * &sect;12.1) — step 1 of first-time SSO against an upstream IdP. One
     * tenant form ({@code tenantId} or {@code tenantSlug}) and one org form
     * ({@code orgId} or {@code orgSlug}) must be resolvable, from the
     * arguments or from the client's construction-time context (&sect;5.1).
     *
     * @param federationConfigId UUID of the server-side federation configuration identifying the upstream IdP
     * @param redirectUri        post-login destination, stored server-side and echoed back by {@code ssoComplete}
     * @param tenantId           tenant UUID; {@code null} to default to the client's configuration
     * @param tenantSlug         tenant slug, alternative to {@code tenantId}; {@code null} to default to the client's configuration
     * @param orgId              organization UUID; {@code null} to default to the client's configuration
     * @param orgSlug            organization slug, alternative to {@code orgId}; {@code null} to default to the client's configuration
     * @return the federation start result
     * @throws io.axiam.sdk.errors.AuthError client-side, without a wire call, when tenant or organization context cannot be resolved
     */
    SsoStartResult ssoStart(String federationConfigId, String redirectUri, @Nullable UUID tenantId,
            @Nullable String tenantSlug, @Nullable UUID orgId, @Nullable String orgSlug);

    /**
     * {@code POST /api/v1/auth/federation/oidc/callback} (CONTRACT.md
     * &sect;12.1) — step 2 of upstream SSO: consumes the single-use
     * {@code state}, provisions or links the user, and establishes the
     * session via {@code Set-Cookie} (&sect;4 cookie jar). &sect;12.4 does
     * not apply here — no ID token ever reaches the SDK on the federation
     * path.
     *
     * @param state the {@code state} value the IdP redirected back with — must be the one {@code ssoStart} returned
     * @param code  the authorization code the IdP redirected back with
     * @return the federation completion result
     */
    SsoCompleteResult ssoComplete(String state, String code);

    // -----------------------------------------------------------------------
    // §14 Device Authorization Grant (RFC 8628)
    // -----------------------------------------------------------------------

    /**
     * {@code POST /oauth2/device_authorization} (CONTRACT.md &sect;14.1) —
     * starts the device grant and obtains the code pair.
     *
     * <p><strong>Unauthenticated by design.</strong> A device that cannot show
     * a browser also cannot hold a client secret, so this never sends
     * {@code client_secret} and never refuses a client built without one.
     *
     * @param scope         requested scope, space-separated; omitted when {@code null}
     * @param tenantId      tenant UUID for the mandatory {@code tenant_id} query parameter
     * @param configuration a pre-fetched discovery document, or {@code null} to fetch one
     * @return the code pair the device shows its user
     * @throws io.axiam.sdk.errors.AuthError when the discovery document advertises no {@code device_authorization_endpoint}
     */
    DeviceAuthorization deviceAuthorize(@Nullable String scope, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration);

    /**
     * {@code POST /oauth2/token} with the device-code grant (CONTRACT.md
     * &sect;14.1) — <strong>one</strong> poll attempt.
     *
     * <p>The raw single call, so an application driving its own loop (a UI
     * rendering a countdown, say) can. All five RFC 8628 &sect;3.5 answers
     * surface as {@code OAuthProtocolError} — {@code authorization_pending}
     * and {@code slow_down} included — so a hand-rolled loop sees exactly what
     * {@link #deviceLogin} sees. Most callers want {@code deviceLogin}.
     *
     * @param deviceCode    the {@code deviceCode} from {@link DeviceAuthorization}
     * @param tenantId      tenant UUID for the {@code tenant_id} query parameter
     * @param configuration a pre-fetched discovery document, or {@code null}
     * @return the issued token set
     */
    OidcTokenSet devicePoll(Sensitive deviceCode, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration);

    /**
     * The composed &sect;14.3 helper: starts the grant, hands the caller the
     * user code, polls to completion.
     *
     * <p>{@code onUserCode} is called <strong>before the first poll</strong> —
     * &sect;14.3 rule 2 requires the caller to have had the chance to display
     * the code before polling begins. The SDK never prints it: what the device
     * does with it (screen, QR code, e-ink panel) is the application's
     * decision.
     *
     * <p>Per &sect;14.3 rule 4 (contract 1.7 errata) the token set is
     * <strong>returned</strong>; this SDK does not adopt it, matching its
     * {@code loginClientCredentials} posture.
     *
     * <p>Polling follows &sect;14.2: the interval comes from the response;
     * {@code slow_down} adds 5&nbsp;s <strong>permanently</strong>;
     * {@code authorization_pending} loops; {@code access_denied} and
     * {@code expired_token} raise distinct errors; polling stops at
     * {@code expiresIn} even if the server has not yet said
     * {@code expired_token}. A 5xx or transport failure mid-poll is
     * <strong>not</strong> terminal (rule 6) — a server restart must not lose
     * a grant the user has already approved.
     *
     * @param scope         requested scope, or {@code null}
     * @param tenantId      tenant UUID for the {@code tenant_id} query parameter
     * @param configuration a pre-fetched discovery document, or {@code null}
     * @param onUserCode    invoked with the code pair before the first poll
     * @return the issued token set
     */
    OidcTokenSet deviceLogin(@Nullable String scope, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration, Consumer<DeviceAuthorization> onUserCode);

    // -----------------------------------------------------------------------
    // §15 Token Exchange (RFC 8693)
    // -----------------------------------------------------------------------

    /**
     * The {@code actor_token_type} this SDK sends, and the
     * {@code subject_token_type} it sends when the caller names none — an
     * AXIAM-issued access token (&sect;15.1).
     */
    String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    /**
     * A JWT from a trusted external issuer — the cross-domain exchange of
     * &sect;15.7.
     *
     * <p>Pass it as the {@code subjectTokenType} of
     * {@link #tokenExchange(Sensitive, String, Sensitive, java.util.List, String, String, UUID, OidcConfiguration)}
     * to exchange a partner IdP's token. AXIAM also accepts
     * {@link #ACCESS_TOKEN_TYPE} for an external issuer, and refuses refresh
     * and ID token types <strong>by name</strong>.
     */
    String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

    /**
     * {@code POST /oauth2/token} with the RFC 8693 grant (CONTRACT.md
     * &sect;15.1) — exchanges a token for a <strong>narrower</strong> one.
     *
     * <p>What this method deliberately does <em>not</em> do:
     *
     * <ul>
     *   <li><strong>No default {@code actorToken}</strong> (&sect;15.2
     *       rule 1). Passing {@code null} asks for <em>impersonation</em>; the
     *       SDK will not quietly reuse the client's own session token as the
     *       actor and turn that into a delegation.</li>
     *   <li><strong>No retry or downgrade on {@code unauthorized_client}</strong>
     *       (rule 2) — a registration fact an operator must fix.</li>
     *   <li><strong>No auto-narrowing on {@code invalid_scope}</strong>
     *       (rule 3). The server refuses instead of silently narrowing
     *       precisely so the caller finds out here.</li>
     *   <li><strong>No adoption</strong> (rule 5). The returned token is
     *       handed onward in one outbound call.</li>
     * </ul>
     *
     * <p>A cross-tenant subject token answers {@code invalid_grant},
     * identically to an expired one. The SDK does not try to tell them apart
     * (&sect;15.3): the server collapses them because distinguishing them is a
     * tenant-enumeration signal.
     *
     * @param subjectToken  the token being exchanged (&sect;15.5 secret)
     * @param actorToken    the acting party for a <em>delegation</em>, or {@code null} for impersonation
     * @param scopes        scopes to request, or {@code null} to omit
     * @param audience      the service the issued token is for, or {@code null}
     * @param resource      the RFC 8707 synonym of {@code audience}, or {@code null}
     * @param tenantId      tenant UUID for the {@code tenant_id} query parameter
     * @param configuration a pre-fetched discovery document, or {@code null}
     * @return the issued, narrower token
     * @throws io.axiam.sdk.errors.AuthError client-side, with no wire call, when no client secret is configured
     */
    default ExchangedToken tokenExchange(Sensitive subjectToken, @Nullable Sensitive actorToken,
            @Nullable List<String> scopes, @Nullable String audience, @Nullable String resource,
            @Nullable UUID tenantId, @Nullable OidcConfiguration configuration) {
        return tokenExchange(subjectToken, null, actorToken, scopes, audience, resource, tenantId,
                configuration);
    }

    /**
     * {@code POST /oauth2/token} with the RFC 8693 grant, naming what kind of
     * token {@code subjectToken} is — the <strong>external-IdP</strong>
     * exchange of CONTRACT.md &sect;15.7.
     *
     * <p>Same operation as the overload above, and every rule there still
     * applies. &sect;15.7 adds no new operation: what changes is which subject
     * tokens the server accepts and what its refusals mean. A partner runs
     * their own IdP (Entra, Okta, Keycloak), their service calls yours
     * carrying <em>their</em> token, and you present it here to get an AXIAM
     * token scoped to what the resolved AXIAM user may actually do.
     *
     * <p><strong>{@code subjectTokenType} is yours to name, never the SDK's to
     * guess.</strong> The SDK never reads {@code subjectToken} to decide it
     * (&sect;15.7): which kind of token you hold is something only you know,
     * and a wrong guess is the difference between a request that is refused
     * and one that is silently reinterpreted. AXIAM refuses refresh and ID
     * token types <em>by name</em>, and the SDK will not retry a refusal as a
     * different type.
     *
     * <p><strong>{@code actorToken} must be {@code null} here.</strong>
     * Delegation across a trust boundary is unsupported in v1 and is refused
     * with {@code invalid_request} — which this SDK surfaces rather than
     * working around by dropping the actor and re-sending.
     *
     * <p>One {@code error_description} is normative and worth matching on:
     * {@code the subject token's issuer is not configured for token exchange},
     * carried on {@code invalid_grant}. It is the <em>only</em> distinguishable
     * external failure, and it means <em>fix the AXIAM trust configuration</em>
     * rather than <em>fix your token</em>.
     *
     * @param subjectToken     the token being exchanged (&sect;15.5 secret)
     * @param subjectTokenType what kind of token {@code subjectToken} is, or
     *                         {@code null} for {@code …:access_token} — the
     *                         same-domain exchange of &sect;15.1. Pass
     *                         {@link #JWT_TOKEN_TYPE} for a partner IdP's JWT.
     * @param actorToken       the acting party for a <em>delegation</em>, or {@code null} for impersonation
     * @param scopes           scopes to request, or {@code null} to omit
     * @param audience         the service the issued token is for, or {@code null}
     * @param resource         the RFC 8707 synonym of {@code audience}, or {@code null}
     * @param tenantId         tenant UUID for the {@code tenant_id} query parameter
     * @param configuration    a pre-fetched discovery document, or {@code null}
     * @return the issued token
     * @throws io.axiam.sdk.errors.AuthError client-side, with no wire call, when no client secret is configured
     */
    ExchangedToken tokenExchange(Sensitive subjectToken, @Nullable String subjectTokenType,
            @Nullable Sensitive actorToken, @Nullable List<String> scopes,
            @Nullable String audience, @Nullable String resource, @Nullable UUID tenantId,
            @Nullable OidcConfiguration configuration);

    // -----------------------------------------------------------------------
    // §20 UMA 2.0 — Protection API and ticket grant
    // -----------------------------------------------------------------------

    /**
     * {@code POST /uma2/rreg/resource_set} — registers a resource set
     * (CONTRACT.md &sect;20.1).
     *
     * <p>The {@code pat} is an explicit parameter, not this client's session.
     * A Protection API Token must be a <strong>client-credentials</strong>
     * token, because a ticket binds to the {@code client_id} that minted it —
     * and this client's session is usually a <em>user</em> session, which
     * names no client to bind to (&sect;20.2 rule 1).
     *
     * @param pat      the Protection API Token
     * @param resource the resource set to register
     * @return the registered set, carrying the server-assigned id
     */
    ResourceSet umaRegisterResource(Sensitive pat, ResourceSet resource);

    /**
     * {@code GET /uma2/rreg/resource_set/{id}} — reads a resource set
     * (&sect;20.1).
     *
     * @param pat        the Protection API Token
     * @param resourceId the resource set id
     * @return the resource set
     */
    ResourceSet umaReadResource(Sensitive pat, UUID resourceId);

    /**
     * {@code PUT /uma2/rreg/resource_set/{id}} — replaces a resource set
     * (&sect;20.1).
     *
     * <p><strong>The scope list is replaced, not merged</strong> (&sect;20.2
     * rule 8). Whatever {@code resource.resourceScopes()} holds becomes the
     * complete declared set; omitting a scope removes it, which is how a
     * resource server drops an authority. This method performs no
     * read-before-write.
     *
     * @param pat        the Protection API Token
     * @param resourceId the resource set id
     * @param resource   the new state
     * @return the updated resource set
     */
    ResourceSet umaUpdateResource(Sensitive pat, UUID resourceId, ResourceSet resource);

    /**
     * {@code DELETE /uma2/rreg/resource_set/{id}} — deregisters (&sect;20.1).
     *
     * @param pat        the Protection API Token
     * @param resourceId the resource set id
     */
    void umaDeleteResource(Sensitive pat, UUID resourceId);

    /**
     * {@code GET /uma2/rreg/resource_set} — lists the ids <strong>this
     * client</strong> registered (&sect;20.1).
     *
     * <p>Not the tenant's whole resource tree: a protection scope does not
     * entitle a caller to enumerate it.
     *
     * @param pat the Protection API Token
     * @return the registered resource set ids
     */
    List<UUID> umaListResources(Sensitive pat);

    /**
     * {@code POST /uma2/perm} — mints a permission ticket (&sect;20.1).
     *
     * <p>Scope names are validated <strong>here</strong>, against each
     * resource's declared set. Asking for an undeclared scope is a
     * {@code 400}, not a denial — the two are different failures, and this SDK
     * surfaces the distinction the server draws rather than flattening it.
     *
     * @param pat         the Protection API Token
     * @param permissions the pairs the resource server requires
     * @return the opaque ticket
     */
    Sensitive umaRequestTicket(Sensitive pat, List<RequestedPermission> permissions);

    /**
     * {@code POST /oauth2/token} with the uma-ticket grant (&sect;20.1) —
     * exchanges a ticket for an RPT.
     *
     * <p><strong>This method never retries.</strong> It issues exactly one
     * request and is outside the &sect;16 retry policy — not on {@code 5xx},
     * not on timeout, not on any transport failure (&sect;20.2 rule 6). The
     * ticket is consumed <em>before</em> the request is evaluated, so a failed
     * exchange has already spent it: a retry cannot succeed, and under
     * concurrency it is precisely the second redemption that
     * ilpanich/axiam#302's measured residual describes. On failure, request a
     * <strong>new</strong> ticket.
     *
     * <p>What this method deliberately does not do:
     * <ul>
     *   <li><strong>No default {@code claimToken}</strong> (rule 2) — it is
     *       required. Defaulting it to the resource server's own PAT would
     *       mint an RPT for the resource server instead of for the user.</li>
     *   <li><strong>No auto-narrowing on {@code access_denied}</strong>
     *       (rule 3). A partial grant is refused whole.</li>
     *   <li><strong>No adoption</strong> (rule 4). The RPT is the
     *       <em>requesting party's</em> token.</li>
     * </ul>
     *
     * <p>The four ticket refusals — unknown, expired, already used, wrong
     * client — all answer {@code invalid_grant} with one message. This SDK
     * does not try to tell them apart (&sect;20.4): the server collapses them
     * so a caller cannot probe for live ticket handles.
     *
     * @param ticket        the permission ticket
     * @param claimToken    the requesting party's access token
     * @param tenantId      tenant UUID for the {@code tenant_id} query parameter, or {@code null}
     * @param configuration a pre-fetched discovery document, or {@code null}
     * @return the requesting party token
     * @throws io.axiam.sdk.errors.AuthError client-side, with no wire call, when no client secret is configured
     */
    RequestingPartyToken umaExchangeTicket(Sensitive ticket, Sensitive claimToken,
            @Nullable UUID tenantId, @Nullable OidcConfiguration configuration);

    // -----------------------------------------------------------------------
    // §12.7 Logout helpers
    // -----------------------------------------------------------------------

    /**
     * Builds the RP-initiated logout URL to redirect the user agent to
     * (CONTRACT.md &sect;12.7.2).
     *
     * <p>Performs <strong>no network I/O</strong> beyond the discovery fetch
     * the SDK caches anyway, and does <strong>not</strong> clear this client's
     * own session: whether the local session ends is the application's
     * decision — a backend holding a service-account session must not lose it
     * because a <em>user</em> logged out.
     *
     * <p>{@code end_session_endpoint} is read from discovery and never
     * synthesised from the issuer (rule 1). {@code postLogoutRedirectUri} is
     * passed through <strong>unvalidated against any local list</strong>
     * (rule 3): the allow-list lives in the client's server-side registration,
     * and a client-side copy would drift and reject a URI an operator had just
     * registered.
     *
     * @param idToken               a previously-issued ID token, placed in {@code id_token_hint}
     * @param postLogoutRedirectUri where the OP should send the browser afterwards, or {@code null}
     * @param state                 an opaque value echoed back on the redirect — generated and checked by the caller (rule 2), never by the SDK
     * @param configuration         a pre-fetched discovery document, or {@code null}
     * @return the absolute logout URL
     * @throws io.axiam.sdk.errors.AuthError when the discovery document advertises no {@code end_session_endpoint}
     */
    String logoutUrl(Sensitive idToken, @Nullable String postLogoutRedirectUri, @Nullable String state,
            @Nullable OidcConfiguration configuration);

    /**
     * Verifies a back-channel logout token the OP POSTed to this
     * application's {@code backchannel_logout_uri} (CONTRACT.md &sect;12.7.3).
     *
     * <p>Every check exists because skipping it has a name:
     *
     * <ol>
     *   <li><strong>Signature</strong>, through the same &sect;12.4 JWKS
     *       verifier the ID-token path uses — no second key-fetching path —
     *       with the same {@code kid}-required discipline.</li>
     *   <li><strong>{@code iss}/{@code aud}</strong>: a token minted for
     *       another RP is not accepted here.</li>
     *   <li><strong>{@code events} carries the back-channel-logout key.</strong>
     *       This is what distinguishes a logout token from an ID token;
     *       skipping it means accepting a replayed ID token as a logout
     *       instruction.</li>
     *   <li><strong>{@code nonce} is absent.</strong> Back-Channel Logout 1.0
     *       &sect;2.4 forbids it, and its presence is the documented signature
     *       of an ID token being replayed. Rejected, not ignored.</li>
     *   <li><strong>At least one of {@code sid}/{@code sub}</strong> — a token
     *       naming neither identifies nothing.</li>
     *   <li><strong>{@code exp} in the future, {@code iat} recent.</strong></li>
     * </ol>
     *
     * @param logoutToken   the compact JWS the OP posted
     * @param configuration a pre-fetched discovery document, or {@code null}
     * @return the {@code sid}/{@code sub}/{@code jti} the token names — never a bare boolean, because the RP has to know <em>which</em> session to end
     * @throws io.axiam.sdk.errors.AuthError on any failed check
     */
    VerifiedLogoutToken verifyLogoutToken(String logoutToken, @Nullable OidcConfiguration configuration);
}
