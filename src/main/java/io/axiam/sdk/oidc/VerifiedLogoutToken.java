package io.axiam.sdk.oidc;

import org.jspecify.annotations.Nullable;

/**
 * What a verified back-channel logout token names (CONTRACT.md &sect;12.7.3).
 *
 * <p>Deliberately <strong>not</strong> a bare {@code boolean}: the RP has to
 * know <em>which</em> session to end, and a verifier that only says "valid"
 * would force the caller to re-parse the token themselves, with none of the
 * checks this type is proof of.
 *
 * @param sid the session that ended. <strong>When non-{@code null}, end only this session</strong> — falling back to "every session for {@code sub}" is over-reach the AXIAM server itself refuses to make
 * @param sub the subject whose session ended, or {@code null}
 * @param jti replay identifier. <strong>The RP dedups on this, not the SDK.</strong> Back-channel delivery is at-least-once with retry, so a valid token legitimately arrives twice; the SDK has no durable store and an in-memory guard would silently drop a real second logout after a restart. Surfaced, never consumed
 */
public record VerifiedLogoutToken(
        @Nullable String sid,
        @Nullable String sub,
        String jti) {
}
