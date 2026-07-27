package io.axiam.sdk.errors;

import org.jspecify.annotations.Nullable;

/**
 * Authentication failure: wrong credentials, expired session, MFA failure,
 * or a 401 on refresh (CONTRACT.md &sect;2). Unchecked (D-03) — composes
 * with lambdas/streams/{@code CompletableFuture} without a forced
 * {@code throws}.
 *
 * <p>Messages are English-only, no i18n (D-29) — classification is via this
 * typed exception, not localized text.
 *
 * <p><strong>Not {@code final}</strong> (CONTRACT.md &sect;12.3 rule 3,
 * &sect;2 sub-type table): {@link OAuthProtocolError} is a language-idiomatic
 * sub-type of this class, so existing {@code catch (AuthError e)} code keeps
 * working unchanged when an OIDC/OAuth2 call fails (contract 1.4's
 * "non-breaking, additive" requirement). This is the ONLY sub-type; the
 * three top-level error types remain {@link AuthError}, {@link AuthzError},
 * and {@link NetworkError}.
 */
public class AuthError extends RuntimeException {

    /**
     * A stable, machine-readable reason code for the failure, or
     * {@code null} when none applies.
     *
     * <p>Populated by the CONTRACT.md &sect;12.4 ID-token validation
     * checklist with one of the seven &sect;12.3 rule 3 reason codes
     * ({@code invalid_alg}, {@code unknown_kid}, {@code invalid_signature},
     * {@code invalid_issuer}, {@code invalid_audience}, {@code token_expired},
     * {@code nonce_mismatch}); {@code null} for every other {@code AuthError}.
     * A code, never free text, so callers can branch on it without parsing
     * {@link #getMessage()}.
     */
    private final @Nullable String reason;

    /**
     * Creates a new {@code AuthError} with the given message and no reason code.
     *
     * @param message a human-readable, English-only description of the
     *                authentication failure (D-29)
     */
    public AuthError(String message) {
        this(message, null);
    }

    /**
     * Creates a new {@code AuthError} carrying a stable, machine-readable
     * reason code (CONTRACT.md &sect;12.3 rule 3).
     *
     * @param message a human-readable, English-only description of the
     *                authentication failure (D-29)
     * @param reason  a stable reason code (e.g. {@code "invalid_issuer"}),
     *                or {@code null} when none applies
     */
    public AuthError(String message, @Nullable String reason) {
        super(message);
        this.reason = reason;
    }

    /**
     * Returns this failure's stable, machine-readable reason code, if any.
     *
     * @return the reason code, or {@code null} if none was set
     */
    public @Nullable String reason() {
        return reason;
    }
}
