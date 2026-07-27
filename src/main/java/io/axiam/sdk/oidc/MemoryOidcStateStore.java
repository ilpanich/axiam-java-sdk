package io.axiam.sdk.oidc;

import org.jspecify.annotations.Nullable;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory reference implementation of {@link OidcStateStore}
 * (CONTRACT.md &sect;12.3 rule 1).
 *
 * <p>Per-instance (never process-global), single-use, 10-minute TTL. Expired
 * entries are dropped lazily on {@link #consume} and swept opportunistically
 * on {@link #save} — no background thread/timer is held, since a library must
 * not keep the host process alive.
 *
 * <p>Suitable for a single-process app and for tests. A multi-instance
 * deployment needs a shared store (Redis, a database) — implement
 * {@link OidcStateStore} yourself for that; nothing in the SDK assumes this
 * class.
 *
 * <p>Thread-safe: backed by a {@link ConcurrentHashMap}, so concurrent
 * {@link #save}/{@link #consume} calls never corrupt the underlying map, and
 * {@link ConcurrentHashMap#remove(Object)}'s atomic get-and-delete makes
 * {@link #consume} single-use even under concurrent callers racing the same
 * {@code state}.
 */
public final class MemoryOidcStateStore implements OidcStateStore {

    /**
     * The contract-mandated TTL for stored login state: 10 minutes, matching
     * the server's {@code federation_login_state} row lifetime (CONTRACT.md
     * &sect;12.3 rule 1).
     */
    public static final long OIDC_STATE_TTL_MILLIS = 600_000L;

    private final long ttlMillis;
    private final Map<String, Held> entries = new ConcurrentHashMap<>();

    /**
     * Builds a store with the default 10-minute TTL.
     */
    public MemoryOidcStateStore() {
        this(OIDC_STATE_TTL_MILLIS);
    }

    /**
     * Builds a store with a custom TTL.
     *
     * @param ttlMillis entry lifetime in milliseconds. <strong>Clamped</strong>
     *                  to {@link #OIDC_STATE_TTL_MILLIS}: a shorter TTL is
     *                  honored (useful in tests), a longer one is reduced,
     *                  because CONTRACT.md &sect;12.3 rule 1 fixes 10 minutes
     *                  as the maximum.
     */
    public MemoryOidcStateStore(long ttlMillis) {
        this.ttlMillis = Math.min(ttlMillis, OIDC_STATE_TTL_MILLIS);
    }

    /**
     * Returns the number of unexpired entries currently held. Intended for
     * tests and metrics.
     *
     * @return the number of unexpired entries currently held
     */
    public int size() {
        sweep();
        return entries.size();
    }

    @Override
    public void save(OidcStateEntry entry) {
        sweep();
        entries.put(entry.state(), new Held(entry, System.currentTimeMillis() + ttlMillis));
    }

    @Override
    public @Nullable OidcStateEntry consume(String state) {
        Held held = entries.remove(state);
        if (held == null || held.expiresAtEpochMs <= System.currentTimeMillis()) {
            return null;
        }
        return held.entry;
    }

    /** Drops every expired entry. Lazy housekeeping — no background timer. */
    private void sweep() {
        long now = System.currentTimeMillis();
        entries.entrySet().removeIf(e -> e.getValue().expiresAtEpochMs <= now);
    }

    private record Held(OidcStateEntry entry, long expiresAtEpochMs) {
    }
}
