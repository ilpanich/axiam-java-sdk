package io.axiam.sdk.reactor;

/**
 * A fire-and-forget observer of reactor events ({@code mode: "listen"},
 * CONTRACT.md &sect;22.5).
 *
 * <p>The server never waits for a listener and never reads a reply, so a
 * listener cannot affect any outcome. That is why this interface returns
 * {@code void} rather than a {@link ReactorDecision}: an SDK listener handler
 * MUST NOT publish a reply, and a type that cannot express one is a stronger
 * guarantee than a paragraph saying so.
 *
 * <p><strong>Write it idempotently.</strong> A redelivery after a broker hiccup
 * is normal. A listener that double-counts is a listener that was assuming
 * exactly-once delivery it was never promised.
 */
@FunctionalInterface
public interface ReactorListener {

    /**
     * Observes one verified event.
     *
     * @param event the verified event
     */
    void observe(ReactorEvent event);
}
