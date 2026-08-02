package io.axiam.sdk.webhook;

/**
 * Thrown by {@link AxiamWebhooks#verify} when an inbound webhook delivery
 * fails signature verification. Unchecked (matches
 * {@code io.axiam.sdk.errors}' {@code AuthError}/{@code AuthzError}/
 * {@code NetworkError} convention: composes with lambdas/streams without a
 * forced {@code throws}).
 *
 * <p>{@link #getMessage()} carries only the stable {@link Reason} code —
 * <strong>never</strong> the expected/computed signature, the received
 * signature, or the secret (CONTRACT.md &sect;13.3 rule 6). Logging or
 * displaying a {@code WebhookVerificationException} is always safe.
 */
public final class WebhookVerificationException extends RuntimeException {

    /**
     * A stable, machine-readable code identifying why verification failed.
     */
    public enum Reason {
        /**
         * The signature header failed to parse: empty, no {@code t=} pair,
         * or more than one {@code t=} pair.
         */
        MALFORMED_HEADER,
        /**
         * The header had a valid {@code t=} but no {@code v1=} pair at all
         * (CONTRACT.md &sect;13.3 rule 3: always a failure, never treated as
         * "nothing to verify").
         */
        MISSING_V1,
        /**
         * The {@code t=} value was not a base-10 integer.
         */
        INVALID_TIMESTAMP,
        /**
         * A syntactically well-formed header whose signature(s) did not
         * verify against the supplied secret and body — including the case
         * where every {@code v1=} value failed hex decoding, which fails
         * closed into a mismatch rather than falling back to any other
         * comparison.
         */
        SIGNATURE_MISMATCH,
        /**
         * The signature verified, but {@code t=} is too far in the past
         * ({@code now - t > tolerance}).
         */
        TIMESTAMP_TOO_OLD,
        /**
         * The signature verified, but {@code t=} is too far in the future
         * ({@code t - now > tolerance}) — clock-skew abuse protection
         * (CONTRACT.md &sect;13.3 rule 5).
         */
        TIMESTAMP_TOO_NEW
    }

    /** This failure's stable, machine-readable reason code. */
    private final Reason reason;

    /**
     * Creates a {@code WebhookVerificationException} carrying the given
     * stable reason code.
     *
     * @param reason the stable, machine-readable reason verification failed
     */
    public WebhookVerificationException(Reason reason) {
        super("axiam: webhook signature verification failed: " + reason);
        this.reason = reason;
    }

    /**
     * Returns this failure's stable, machine-readable reason code.
     *
     * @return the reason code
     */
    public Reason reason() {
        return reason;
    }
}
