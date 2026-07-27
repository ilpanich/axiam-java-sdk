package io.axiam.sdk.oidc;

import org.jspecify.annotations.Nullable;

/**
 * The RFC 7662 introspection result (wire schema {@code IntrospectionResponse},
 * CONTRACT.md &sect;12.1), returned by {@code introspect}. Only
 * {@link #active()} is guaranteed; the server omits the metadata fields for
 * an inactive token.
 *
 * @param active    whether the token is currently active
 * @param sub       subject the token was issued to
 * @param clientId  client the token was issued to
 * @param scope     scope granted to the token
 * @param tokenType token type ({@code Bearer})
 * @param exp       expiry time, epoch seconds
 * @param iat       issued-at time, epoch seconds
 */
public record IntrospectionResult(
        boolean active,
        @Nullable String sub,
        @Nullable String clientId,
        @Nullable String scope,
        @Nullable String tokenType,
        @Nullable Long exp,
        @Nullable Long iat) {
}
