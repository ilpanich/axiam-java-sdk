package io.axiam.sdk.oidc;

import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * The OIDC Discovery 1.0 metadata document served by
 * {@code GET /.well-known/openid-configuration} (wire schema
 * {@code OidcDiscoveryDocument}, CONTRACT.md &sect;12.1). Every field is
 * required by the server's schema.
 *
 * <p>Field names keep their wire (snake_case) spelling deliberately: this
 * type IS a protocol document, cross-referenced against OIDC Discovery 1.0 /
 * RFC 8414 by name (CONTRACT.md &sect;12 T1 reference judgment call 3).
 *
 * <p>{@link #issuer()} is the <strong>authoritative</strong> issuer for
 * ID-token validation (CONTRACT.md &sect;12.4 rule 3). It may legitimately
 * differ from the client's base URL when AXIAM runs behind a proxy, so this
 * SDK never rejects a document on an issuer/base-URL mismatch (&sect;12.3
 * rule 6). Likewise {@link #jwks_uri()} is read from here rather than
 * hardcoded.
 *
 * @param issuer                                   the authorization server's issuer identifier — the value an ID token's {@code iss} claim must equal exactly
 * @param authorization_endpoint                   the authorization endpoint {@code oidcBegin} builds its redirect URL from
 * @param token_endpoint                           the token endpoint used by {@code oidcExchange}, {@code oidcRefresh}, and {@code loginClientCredentials}
 * @param userinfo_endpoint                        the userinfo endpoint; advertised by the server but deliberately never called by this SDK (CONTRACT.md &sect;12.3 rule 5)
 * @param jwks_uri                                 URI of the JWKS document whose keys verify ID-token signatures (CONTRACT.md &sect;12.4 rule 2)
 * @param revocation_endpoint                      the RFC 7009 revocation endpoint used by {@code revoke}
 * @param introspection_endpoint                   the RFC 7662 introspection endpoint used by {@code introspect}
 * @param response_types_supported                 OAuth2 {@code response_type} values the server supports
 * @param subject_types_supported                  subject identifier types the server supports
 * @param id_token_signing_alg_values_supported     ID-token signing algorithms the server advertises; informational only — CONTRACT.md &sect;12.4 rule 1 pins verification to {@code EdDSA} regardless of what appears here
 * @param scopes_supported                         scopes the server supports
 * @param token_endpoint_auth_methods_supported     client-authentication methods the token endpoint supports ({@code client_secret_post}, CONTRACT.md &sect;12.1 note 3)
 * @param claims_supported                         claims the server may include in an ID token
 * @param grant_types_supported                    grant types the token endpoint supports
 * @param device_authorization_endpoint            the RFC 8628 device authorization endpoint used by {@code deviceAuthorize} (CONTRACT.md &sect;14.1); {@code null} when the server does not implement the device grant — its absence is an error at call time, never a cue to build the URL by concatenation
 * @param pushed_authorization_request_endpoint    the RFC 9126 pushed authorization request endpoint used by {@code oidcPar} (CONTRACT.md &sect;26.1); {@code null} when the server does not implement PAR — its absence is an error at call time, never a cue to build {@code <issuer>/oauth2/par} by concatenation
 * @param end_session_endpoint                     the OIDC RP-Initiated Logout 1.0 endpoint used by {@code logoutUrl} (CONTRACT.md &sect;12.7.2 rule 1); {@code null} when unsupported, and never synthesised from the issuer — code that concatenates works against AXIAM and breaks against every other OP the same application is pointed at
 * @param backchannel_logout_supported             whether the OP sends back-channel logout tokens
 * @param backchannel_logout_session_supported     whether those logout tokens carry {@code sid}; AXIAM always sends it
 */
public record OidcConfiguration(
        String issuer,
        String authorization_endpoint,
        String token_endpoint,
        String userinfo_endpoint,
        String jwks_uri,
        String revocation_endpoint,
        String introspection_endpoint,
        List<String> response_types_supported,
        List<String> subject_types_supported,
        List<String> id_token_signing_alg_values_supported,
        List<String> scopes_supported,
        List<String> token_endpoint_auth_methods_supported,
        List<String> claims_supported,
        List<String> grant_types_supported,
        @Nullable String device_authorization_endpoint,
        @Nullable String pushed_authorization_request_endpoint,
        @Nullable String end_session_endpoint,
        boolean backchannel_logout_supported,
        boolean backchannel_logout_session_supported) {

    /**
     * Defensively copies every list component so a caller cannot mutate this
     * (otherwise fully immutable) record's collections after construction.
     *
     * @param issuer the authorization server's issuer identifier
     * @param authorization_endpoint the authorization endpoint
     * @param token_endpoint the token endpoint
     * @param userinfo_endpoint the userinfo endpoint
     * @param jwks_uri the JWKS document URI
     * @param revocation_endpoint the revocation endpoint
     * @param introspection_endpoint the introspection endpoint
     * @param response_types_supported supported {@code response_type} values
     * @param subject_types_supported supported subject identifier types
     * @param id_token_signing_alg_values_supported advertised ID-token signing algorithms
     * @param scopes_supported supported scopes
     * @param token_endpoint_auth_methods_supported supported client-authentication methods
     * @param claims_supported claims the server may include in an ID token
     * @param grant_types_supported supported grant types
     * @param device_authorization_endpoint the RFC 8628 device authorization endpoint, or {@code null}
     * @param pushed_authorization_request_endpoint the RFC 9126 PAR endpoint, or {@code null}
     * @param end_session_endpoint the RP-initiated logout endpoint, or {@code null}
     * @param backchannel_logout_supported whether the OP sends logout tokens
     * @param backchannel_logout_session_supported whether those tokens carry {@code sid}
     */
    public OidcConfiguration {
        response_types_supported = List.copyOf(response_types_supported);
        subject_types_supported = List.copyOf(subject_types_supported);
        id_token_signing_alg_values_supported = List.copyOf(id_token_signing_alg_values_supported);
        scopes_supported = List.copyOf(scopes_supported);
        token_endpoint_auth_methods_supported = List.copyOf(token_endpoint_auth_methods_supported);
        claims_supported = List.copyOf(claims_supported);
        grant_types_supported = List.copyOf(grant_types_supported);
    }
}
