package io.axiam.sdk.webauthn;

import io.axiam.sdk.Sensitive;
import java.util.UUID;

/**
 * The outcome of a completed passkey sign-in (CONTRACT.md &sect;24.1).
 *
 * <p>The client is <strong>already authenticated</strong> when this is returned
 * (&sect;24.3 rule 1) — the tokens come back as well because a caller may want
 * to hand them onward, not because adoption was optional.
 *
 * @param accessToken  the new access token
 * @param refreshToken a <strong>session</strong> refresh token, refreshed
 *                     through {@code refresh()} and not {@code oidcRefresh}
 *                     (&sect;24.3 rule 5)
 * @param sessionId    identifies the session just created
 * @param expiresIn    access-token lifetime in seconds
 */
public record WebauthnLoginResult(
        Sensitive accessToken, Sensitive refreshToken, UUID sessionId, long expiresIn) {
}
