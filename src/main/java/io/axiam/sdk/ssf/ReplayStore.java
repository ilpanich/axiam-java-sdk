package io.axiam.sdk.ssf;

import java.time.Duration;

/**
 * Remembers the {@code jti}s already accepted, for step 9 of
 * {@link SsfReceiver#verifySet(String)}.
 *
 * <p>Pluggable so a receiver running several instances can share one store
 * (CONTRACT.md &sect;32.7). {@link MemoryReplayStore} is the default.
 */
@FunctionalInterface
public interface ReplayStore {

    /**
     * Records {@code jti} for {@code window} and returns {@code true}, or returns
     * {@code false} without recording when it is already held. Must be atomic:
     * two concurrent calls with one {@code jti} must not both see {@code true}.
     *
     * @param jti    the SET's unique id
     * @param window how long to remember it
     * @return {@code true} the first time, {@code false} for a replay
     */
    boolean checkAndRecord(String jti, Duration window);
}
