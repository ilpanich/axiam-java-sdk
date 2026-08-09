package io.axiam.sdk.telemetry;

/**
 * A caller-supplied telemetry sink (CONTRACT.md §19).
 *
 * <p>Install one with {@code AxiamClient.Builder#telemetryHook}. It receives
 * request start/end, §16 retry and §9 refresh events, so metrics can be wired
 * without this library depending on any metrics API.
 *
 * <p>A hook that throws cannot fail the operation that fired it (§19.2 rule 2)
 * — the dispatcher swallows it. That is a backstop, not a licence: a sink that
 * throws on every event still costs the exception construction on the calling
 * thread.
 */
@FunctionalInterface
public interface TelemetryHook {
    /**
     * Receives one event.
     *
     * @param event the event; never null
     */
    void accept(TelemetryEvent event);
}
