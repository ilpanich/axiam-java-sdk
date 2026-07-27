package io.axiam.sdk.oidc;

import io.axiam.sdk.Sensitive;

import org.jspecify.annotations.Nullable;

/**
 * A token set returned by the OAuth2 token endpoint (wire schema
 * {@code TokenResponse}), returned by {@code oidcExchange},
 * {@code oidcRefresh}, and {@code loginClientCredentials}.
 *
 * <p>{@link #accessToken()}, {@link #refreshToken()}, and {@link #idToken()}
 * are {@link Sensitive} (CONTRACT.md &sect;12.5): {@code toString()} and
 * Jackson serialization both redact them to {@code "[SENSITIVE]"}, and the
 * raw value is reachable only through {@code Sensitive}'s package-internal
 * accessor.
 *
 * <p>{@link #idClaims()} is present exactly when {@link #idToken()} is, and
 * holds the <strong>already-validated</strong> claim set (CONTRACT.md
 * &sect;12.4) — validation happens before this record is ever constructed, so
 * an {@code OidcTokenSet} in hand is never partially trusted (&sect;12.4
 * rule 7).
 *
 * @param accessToken  the OAuth2 access token (&sect;12.5 secret)
 * @param tokenType    the token type the server issued ({@code Bearer})
 * @param expiresIn    access-token lifetime in seconds from the time of the response
 * @param scope        granted scope, when the server narrowed or echoed it
 * @param refreshToken the refresh token, when the grant issued one (&sect;12.5 secret)
 * @param idToken      the raw ID token, when the grant issued one (&sect;12.5 secret)
 * @param idClaims     the validated ID-token claims — present exactly when {@link #idToken()} is
 */
public record OidcTokenSet(
        Sensitive accessToken,
        String tokenType,
        long expiresIn,
        @Nullable String scope,
        @Nullable Sensitive refreshToken,
        @Nullable Sensitive idToken,
        @Nullable IdTokenClaims idClaims) {
}
