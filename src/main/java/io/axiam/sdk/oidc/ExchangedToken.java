package io.axiam.sdk.oidc;

import io.axiam.sdk.Sensitive;

import org.jspecify.annotations.Nullable;

/**
 * The result of an RFC 8693 exchange (wire schema
 * {@code TokenExchangeResponse}, CONTRACT.md &sect;15.1).
 *
 * <p><strong>There is no {@code refreshToken} component, and that is
 * deliberate</strong> (&sect;15.2 rule 4). RFC 8693 issues none, so this type
 * cannot represent one: an application that wants a fresh exchanged token
 * re-runs the exchange. This result also never enters the &sect;9
 * single-flight refresh guard — there is nothing to refresh.
 *
 * @param accessToken     the issued token (&sect;15.5 secret)
 * @param issuedTokenType what the server actually issued; mandatory in RFC 8693 &sect;2.2.1 and surfaced rather than dropped (&sect;15.2 rule 6), so a client that asked for one type and got another can tell
 * @param tokenType       the token type ({@code Bearer})
 * @param expiresIn       lifetime in seconds — never longer than the subject token's remaining life, since the server caps it so an exchange cannot launder lifetime
 * @param scope           <strong>the granted scope, which may be narrower than requested</strong> even on success (&sect;15.2 rule 7); read it rather than assuming the request was honoured verbatim. {@code null} when the server did not state one
 */
public record ExchangedToken(
        Sensitive accessToken,
        String issuedTokenType,
        String tokenType,
        int expiresIn,
        @Nullable String scope) {
}
