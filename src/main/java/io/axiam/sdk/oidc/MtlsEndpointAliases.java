package io.axiam.sdk.oidc;

import org.jspecify.annotations.Nullable;

/**
 * RFC 8705 &sect;5 {@code mtls_endpoint_aliases} — the seven endpoints re-based
 * on the host that performs the mutual-TLS handshake (wire schema
 * {@code MtlsEndpointAliases}, contract 1.40; the seventh,
 * {@code backchannel_authentication_endpoint}, contract 1.58, CONTRACT.md
 * &sect;21.3.1 vector A as amended for &sect;33 CIBA).
 *
 * <p>A TLS listener decides whether to request a client certificate during the
 * handshake, before it has seen any HTTP, so "ask for a certificate on
 * {@code /oauth2/token} but not on {@code /oauth2/authorize}" is not something
 * one listener can do. A deployment wanting both runs two, and this object
 * names the second.
 *
 * <p>Only these seven are ever aliased. {@code authorization_endpoint} and
 * {@code end_session_endpoint} are front-channel and {@code jwks_uri} is public
 * key material, so CONTRACT.md &sect;21.3 rule 2 forbids synthesising an alias
 * for any of them — sending a browser to an mTLS host raises a native
 * certificate-chooser dialog most users cannot answer. {@code issuer} is not an
 * endpoint and does not move either: &sect;12.4 rule 3 still compares
 * {@code iss} against it by exact string.
 *
 * <p><strong>Every component is {@code @Nullable}</strong>, though the server's
 * schema marks all seven required. AXIAM builds them from one path through a
 * shared macro and so always publishes the complete set, but RFC 8705 &sect;5
 * permits an OP to alias fewer, and the shape of this member must never be why
 * a client stops working — the same principle rule 2 point 1 states for the
 * object as a whole, one level in. A {@code null} entry falls back to the
 * top-level endpoint of the same name, exactly as an absent object does.
 *
 * @param token_endpoint                          RFC 8705 &sect;2 client authentication, and &sect;3 the mint of a certificate-bound token
 * @param userinfo_endpoint                       OIDC Core &sect;5.3, reached with an access token that may carry {@code cnf}
 * @param revocation_endpoint                     RFC 7009 &sect;2.1 — authenticates the client
 * @param introspection_endpoint                  RFC 7662 &sect;2.1 — authenticates the caller
 * @param device_authorization_endpoint           RFC 8628 &sect;3.1 — authenticates the client
 * @param pushed_authorization_request_endpoint   RFC 9126 &sect;2 — authenticates the client
 * @param backchannel_authentication_endpoint     CIBA Core &sect;7 ({@code /oauth2/bc-authorize}) — authenticates the client; a {@code tls_client_auth} CIBA client has no other way to present its certificate on a two-listener deployment (contract 1.58)
 */
public record MtlsEndpointAliases(
        @Nullable String token_endpoint,
        @Nullable String userinfo_endpoint,
        @Nullable String revocation_endpoint,
        @Nullable String introspection_endpoint,
        @Nullable String device_authorization_endpoint,
        @Nullable String pushed_authorization_request_endpoint,
        @Nullable String backchannel_authentication_endpoint) {

    /**
     * The pre-contract-1.58 arity, for source compatibility: an alias object
     * without {@code backchannel_authentication_endpoint}, which then falls back
     * to the top-level entry like any other unnamed member.
     *
     * @param token_endpoint                        the token endpoint alias
     * @param userinfo_endpoint                     the userinfo endpoint alias
     * @param revocation_endpoint                   the revocation endpoint alias
     * @param introspection_endpoint                the introspection endpoint alias
     * @param device_authorization_endpoint         the device authorization endpoint alias
     * @param pushed_authorization_request_endpoint the PAR endpoint alias
     */
    public MtlsEndpointAliases(
            @Nullable String token_endpoint,
            @Nullable String userinfo_endpoint,
            @Nullable String revocation_endpoint,
            @Nullable String introspection_endpoint,
            @Nullable String device_authorization_endpoint,
            @Nullable String pushed_authorization_request_endpoint) {
        this(token_endpoint, userinfo_endpoint, revocation_endpoint, introspection_endpoint,
                device_authorization_endpoint, pushed_authorization_request_endpoint, null);
    }
}
