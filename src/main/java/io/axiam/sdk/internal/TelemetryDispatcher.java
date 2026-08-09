package io.axiam.sdk.internal;

import io.axiam.sdk.telemetry.TelemetryEvent;
import io.axiam.sdk.telemetry.TelemetryHook;
import java.time.Duration;
import org.jspecify.annotations.Nullable;

/**
 * Internal §19 dispatcher. A null hook is the overwhelmingly common case and
 * costs one reference comparison per request.
 */
public final class TelemetryDispatcher {

    private final @Nullable TelemetryHook hook;

    /**
     * Wraps {@code hook}, or nothing at all when it is null.
     *
     * @param hook the caller's sink, or null
     */
    public TelemetryDispatcher(@Nullable TelemetryHook hook) {
        this.hook = hook;
    }

    /**
     * Whether a hook is installed.
     *
     * @return true when events will be delivered
     */
    public boolean installed() {
        return hook != null;
    }

    /**
     * Delivers {@code event}, swallowing anything the caller's hook throws.
     *
     * <p>§19.2 rule 2: telemetry is not permitted to fail an authorization
     * check. A hook that throws is the caller's bug, and letting it propagate
     * here would turn a metrics problem into an authorization failure.
     *
     * @param event the event to deliver
     */
    public void emit(TelemetryEvent event) {
        if (hook == null) {
            return;
        }
        try {
            hook.accept(event);
        } catch (RuntimeException ignored) {
            // Deliberately swallowed; see above.
        }
    }

    /**
     * Opens a §19 request pair around one <strong>attempt</strong>.
     *
     * <p>Per attempt, not per logical call: §19.2 rule 5 requires a caller to
     * be able to count real wire calls from the events, which one pair per
     * operation would hide — a retried call would look like a single slow one.
     *
     * @param operation    canonical operation name
     * @param method       HTTP method
     * @param pathTemplate the route constant, never a substituted URL
     * @param attempt      the 1-based attempt number
     * @return the span that closes this pair
     */
    public Span startRequest(String operation, String method, String pathTemplate, int attempt) {
        if (installed()) {
            emit(new TelemetryEvent.RequestStart(operation, method, pathTemplate, attempt));
        }
        return new Span(this, operation, method, pathTemplate, attempt, System.nanoTime());
    }

    /** Closes a §19 request pair opened by {@link #startRequest}. */
    public static final class Span {
        private final TelemetryDispatcher dispatcher;
        private final String operation;
        private final String method;
        private final String pathTemplate;
        private final int attempt;
        private final long startedNanos;

        private Span(TelemetryDispatcher dispatcher, String operation, String method,
                     String pathTemplate, int attempt, long startedNanos) {
            this.dispatcher = dispatcher;
            this.operation = operation;
            this.method = method;
            this.pathTemplate = pathTemplate;
            this.attempt = attempt;
            this.startedNanos = startedNanos;
        }

        /**
         * Emits the closing {@code RequestEnd}.
         *
         * @param status  HTTP status, or 0 when no response arrived
         * @param outcome success or failure
         */
        public void end(int status, TelemetryEvent.Outcome outcome) {
            if (!dispatcher.installed()) {
                return;
            }
            dispatcher.emit(new TelemetryEvent.RequestEnd(
                    operation, method, pathTemplate, attempt, status,
                    Duration.ofNanos(System.nanoTime() - startedNanos), outcome));
        }
    }
}
