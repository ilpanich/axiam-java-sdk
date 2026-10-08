package io.axiam.sdk.ssf;

import io.axiam.sdk.errors.AuthError;

/**
 * A SET refused by {@link SsfReceiver#verifySet(String)} (CONTRACT.md
 * &sect;32.7): an {@link AuthError} carrying the {@link SetFailureReason}.
 *
 * <p>The message names the failed step, never the SET or any claim value.
 */
public final class SetVerificationError extends AuthError {

    private static final long serialVersionUID = 1L;

    /** The step that failed. */
    private final SetFailureReason reason;

    /**
     * Creates the refusal.
     *
     * @param reason the step that failed
     * @param detail what about it failed, naming no value
     */
    public SetVerificationError(SetFailureReason reason, String detail) {
        super("SET refused (" + reason.code() + "): " + detail, reason.code());
        this.reason = reason;
    }

    /**
     * The step that failed.
     *
     * @return the reason
     */
    public SetFailureReason failureReason() {
        return reason;
    }
}
