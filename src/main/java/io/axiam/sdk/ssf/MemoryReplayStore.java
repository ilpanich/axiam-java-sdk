package io.axiam.sdk.ssf;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * The in-memory {@link ReplayStore}: one process, lost on restart. Entries
 * expire after their window and are purged as new ones are recorded.
 */
public final class MemoryReplayStore implements ReplayStore {

    /** {@code jti} &rarr; the {@link System#nanoTime()} it expires at. */
    private final Map<String, Long> seen = new HashMap<>();

    /** Creates an empty store. */
    public MemoryReplayStore() {
    }

    @Override
    public synchronized boolean checkAndRecord(String jti, Duration window) {
        long now = System.nanoTime();
        seen.values().removeIf(expires -> expires - now <= 0);
        if (seen.containsKey(jti)) {
            return false;
        }
        long nanos;
        try {
            nanos = window.toNanos();
        } catch (ArithmeticException e) {
            nanos = Long.MAX_VALUE / 2;
        }
        seen.put(jti, now + Math.min(nanos, Long.MAX_VALUE / 2));
        return true;
    }
}
