package io.axiam.sdk.oidc;

/**
 * The result of {@code ssoComplete} (wire schema {@code SsoLoginSuccessResponse},
 * CONTRACT.md &sect;12.1) — step 2 of upstream SSO.
 *
 * <p>Carries <strong>no token material</strong> — the session arrives as
 * {@code Set-Cookie}, so the &sect;4 cookie jar is what actually captures it
 * (CONTRACT.md &sect;12.1 note 6).
 *
 * @param userId      the provisioned/linked user's UUID
 * @param sessionId   the established session's UUID
 * @param expiresIn   session/access-token lifetime in seconds
 * @param redirectUri the post-login destination that was stored during {@code ssoStart}
 */
public record SsoCompleteResult(String userId, String sessionId, long expiresIn, String redirectUri) {
}
