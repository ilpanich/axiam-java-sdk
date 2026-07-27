package io.axiam.sdk.oidc;

import io.axiam.sdk.Sensitive;

import org.jspecify.annotations.Nullable;

import java.util.Map;
import java.util.UUID;

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
}
