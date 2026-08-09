package io.axiam.sdk.telemetry;

import java.time.Duration;

/**
 * A telemetry event (CONTRACT.md §19).
 *
 * <p>This is a <strong>sealed</strong> hierarchy: no code outside this package
 * can add a variant. That is what makes §19.2 rule 3's "no event payload may
 * carry a secret" checkable rather than aspirational — every permitted record
 * below has a fixed component list and no free-form map, so there is nowhere to
 * put a token in a payload bound for a metrics backend.
 *
 * <p>Hooks are invoked on the calling thread, so a sink must not block: §19.2
 * rule 4 makes buffering the caller's job so they can pick the policy. Every
 * mature metrics library already buffers.
 */
public sealed interface TelemetryEvent
        permits TelemetryEvent.RequestStart,
                TelemetryEvent.RequestEnd,
                TelemetryEvent.Retry,
                TelemetryEvent.Refresh {

    /** Why a request finished. */
    enum Outcome {
        /** The call returned a usable response. */
        SUCCESS,
        /** The call failed, at any layer. */
        FAILURE
    }

    /** Whether this caller performed a §9 refresh or waited on another's. */
    enum RefreshRole {
        /** This caller performed the refresh. */
        LEADER,
        /** This caller waited on another thread's refresh. */
        FOLLOWER
    }

    /**
     * Emitted before an outbound call leaves the SDK.
     *
     * @param operation    canonical operation name, e.g. {@code checkAccess}
     * @param method       HTTP method
     * @param pathTemplate the route constant — {@code /api/v1/authz/check},
     *                     never a URL with ids substituted in. A metric label
     *                     carrying a UUID is a cardinality bomb.
     * @param attempt      1 for the first try, incrementing per §16 retry
     */
    record RequestStart(String operation, String method, String pathTemplate, int attempt)
            implements TelemetryEvent {
    }

    /**
     * Emitted after a call completes, success or failure.
     *
     * @param operation    canonical operation name
     * @param method       HTTP method
     * @param pathTemplate the route constant; see {@link RequestStart}
     * @param attempt      the attempt this event closes
     * @param status       HTTP status, or 0 when the call never got a response
     * @param duration     wall-clock time this attempt took
     * @param outcome      success or failure
     */
    record RequestEnd(String operation, String method, String pathTemplate, int attempt,
                      int status, Duration duration, Outcome outcome) implements TelemetryEvent {
    }

    /**
     * Emitted before each §16 retry wait.
     *
     * <p>§16.5 requires this: a retried-then-succeeded operation is otherwise
     * invisible — the caller sees a slow success and no signal that the server
     * is failing. That silence is the standing objection to automatic retry.
     *
     * @param operation canonical operation name
     * @param attempt   the attempt that just failed
     * @param delay     the wait about to be taken, after jitter and any
     *                  {@code Retry-After}
     * @param reason    a redacted failure description; never carries a token
     */
    record Retry(String operation, int attempt, Duration delay, String reason)
            implements TelemetryEvent {
    }

    /**
     * Emitted around a §9 single-flight refresh.
     *
     * @param role     whether this caller led or followed
     * @param duration how long the refresh, or the wait for one, took
     */
    record Refresh(RefreshRole role, Duration duration) implements TelemetryEvent {
    }
}
