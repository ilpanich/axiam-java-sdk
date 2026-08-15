package io.axiam.sdk.reactor;

/**
 * A reactor's decision function: one event in, one of three answers out
 * (CONTRACT.md &sect;22.10).
 *
 * <p>Invoked only after the runtime has verified the event under &sect;8 v2, so
 * an implementation never sees an unauthenticated payload.
 *
 * <p><strong>Throwing produces no reply.</strong> The runtime will not
 * synthesize an {@code allow} on your behalf — that would override the
 * operator's {@code fail_closed} setting from inside the library. A handler that
 * throws is a reactor that did not answer, and the registration's
 * {@code failure_policy} decides what that costs.
 *
 * <p><strong>Answer inside the window.</strong> {@link ReactorEvent#timeoutMs()}
 * is how long the server will actually wait. A late reply is discarded and the
 * CPU spent producing it was spent for nothing, so a handler doing expensive
 * work should consult {@link ReactorEvent#remaining} and shed load rather than
 * push on.
 */
@FunctionalInterface
public interface ReactorHandler {

    /**
     * Decides one event.
     *
     * @param event the verified event
     * @return {@link ReactorDecision#allow()},
     *         {@link ReactorDecision#allowRequiringStepUp()},
     *         {@link ReactorDecision#deny},
     *         or {@link ReactorDecision#mutate}; never {@code null}
     */
    ReactorDecision handle(ReactorEvent event);
}
