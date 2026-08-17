package io.axiam.sdk.reactor;

/**
 * Thrown by a {@link ReactorHandlers}-composed handler for an event no handler
 * was bound for (CONTRACT.md &sect;22.14 rule 4).
 *
 * <p>Throwing is the point. {@link ReactorServer} publishes <strong>no
 * reply</strong> for a handler that threw, so the registration's
 * {@code failure_policy} resolves this exactly as &sect;22.8 resolves a timeout.
 * The alternative &mdash; answering {@code allow} &mdash; would answer on behalf
 * of code that never ran, which is how an operator's {@code fail_closed}
 * setting gets defeated from inside the library (&sect;22.10 rule 2).
 *
 * <p>An event a reactor did not register for should never arrive at all. When
 * one does, the registration and the code have drifted, and letting the
 * operator's policy resolve it is the answer that cannot silently weaken the
 * operator's configuration.
 */
public final class UnboundReactorEventException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** The wire event name no handler was bound for. */
    private final String event;

    /**
     * Creates an exception naming the unbound event.
     *
     * @param event the wire event name no handler was bound for
     */
    public UnboundReactorEventException(String event) {
        super("no reactor handler bound for " + event);
        this.event = event;
    }

    /**
     * The event name no handler was bound for.
     *
     * @return the wire event name; never {@code null}
     */
    public String event() {
        return event;
    }
}
