package io.axiam.sdk.internal;

import java.util.function.IntFunction;

/**
 * The CONTRACT.md &sect;16 retry runner for a call whose retryability depends
 * on the HTTP status rather than on the error type.
 *
 * <p>&sect;2 maps a bodiless {@code 400} to a {@code NetworkError}, the same
 * type a dropped connection produces, so a predicate on the type alone would
 * retry a request the server already refused for good. Here the attempt
 * itself decides: it throws {@link Transient} around a failure worth another
 * attempt (a transport error, a {@code 5xx}, a {@code 408}, a {@code 429}) and
 * throws the failure bare otherwise. The runner unwraps before returning, so
 * a caller never sees {@link Transient}.
 *
 * <p>Internal plumbing; public only because the callers live in other packages.
 */
public final class StatusRetry {

    private StatusRetry() {
    }

    /** Marks a failure as worth another attempt. Never escapes {@link #run}. */
    public static final class Transient extends RuntimeException implements Retry.RetryAfterHint {

        private static final long serialVersionUID = 1L;

        /** The failure the caller sees if no attempt succeeds. */
        private final RuntimeException error;

        /** A server-supplied {@code Retry-After}, in milliseconds, or 0. */
        private final long retryAfterMillis;

        /**
         * Wraps a transient failure.
         *
         * @param error            the failure itself
         * @param retryAfterMillis the server's {@code Retry-After} hint in milliseconds, or 0
         */
        public Transient(RuntimeException error, long retryAfterMillis) {
            super(error.getMessage(), null, false, false);
            this.error = error;
            this.retryAfterMillis = retryAfterMillis;
        }

        @Override
        public long retryAfterMillis() {
            return retryAfterMillis;
        }
    }

    /**
     * Whether a status is worth another attempt under &sect;16: {@code 408},
     * {@code 429} and every {@code 5xx}. Every other {@code 4xx} is the
     * server's answer, not a failure to get one.
     *
     * @param status the HTTP status
     * @return whether to retry
     */
    public static boolean retryableStatus(int status) {
        return status == 408 || status == 429 || status >= 500;
    }

    /**
     * Reads a delta-seconds {@code Retry-After} header, in milliseconds.
     *
     * @param response the response
     * @return the hint in milliseconds, or 0 when absent or not delta-seconds
     */
    public static long retryAfterMillis(okhttp3.Response response) {
        String value = response.header("Retry-After");
        if (value == null) {
            return 0;
        }
        try {
            // Capped at the §16 delay ceiling: a hint is a floor on the wait,
            // never a way for a server to stall the caller indefinitely.
            return Math.min(Retry.MAX_DELAY_MILLIS, Math.max(0, Long.parseLong(value.trim())) * 1000L);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /**
     * Runs {@code attempt} under &sect;16.
     *
     * @param <T>       the result type
     * @param enabled   whether the client's retry policy is on (off: one attempt)
     * @param telemetry the &sect;19 dispatcher notified before each retry wait
     * @param operation canonical operation name for the retry event
     * @param attempt   one attempt, given its 1-based number
     * @return the first successful attempt's result
     */
    public static <T> T run(boolean enabled, TelemetryDispatcher telemetry, String operation,
                            IntFunction<T> attempt) {
        try {
            return Retry.withRetry(enabled ? Retry.DEFAULT_MAX_ATTEMPTS : 1, attempt,
                    e -> e instanceof Transient, telemetry, operation);
        } catch (Transient t) {
            throw t.error;
        }
    }
}
