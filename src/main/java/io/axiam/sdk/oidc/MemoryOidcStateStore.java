package io.axiam.sdk.oidc;

import org.jspecify.annotations.Nullable;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

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
 * <p>Thread-safe: backed by a synchronized insertion-ordered map, so concurrent
 * {@link #save}/{@link #consume} calls never corrupt it, and the atomic
 * get-and-delete in {@link #consume} makes it single-use even under concurrent
 * callers racing the same {@code state}.
 */
public final class MemoryOidcStateStore implements OidcStateStore {

    /**
     * The contract-mandated TTL for stored login state: 10 minutes, matching
     * the server's {@code federation_login_state} row lifetime (CONTRACT.md
     * &sect;12.3 rule 1).
     */
    public static final long OIDC_STATE_TTL_MILLIS = 600_000L;

    /**
     * Upper bound on held entries (N1). Every login start saves one entry that lives ten minutes, so
     * an unauthenticated caller of the login route could otherwise grow the map without limit; when
     * the bound is reached the entry closest to expiry is evicted to make room.
     */
    public static final int DEFAULT_MAX_ENTRIES = 10_000;

    private final long ttlMillis;
    private final int maxEntries;
    /**
     * Insertion-ordered. Every entry has the same TTL, so insertion order is expiry order: expired
     * entries are all at the head and the entry closest to expiry is the eldest, which keeps both
     * the sweep and the eviction at the bound cheap. Guarded by {@code this}.
     */
    private final Map<String, Held> entries = new LinkedHashMap<>();

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
        this(ttlMillis, DEFAULT_MAX_ENTRIES);
    }

    /**
     * Builds a store with a custom TTL and entry bound.
     *
     * @param ttlMillis  entry lifetime in milliseconds, clamped as in {@link #MemoryOidcStateStore(long)}
     * @param maxEntries the most entries held at once; at least 1. The entry closest to expiry is evicted to make room
     */
    public MemoryOidcStateStore(long ttlMillis, int maxEntries) {
        if (maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries must be at least 1");
        }
        this.ttlMillis = Math.min(ttlMillis, OIDC_STATE_TTL_MILLIS);
        this.maxEntries = maxEntries;
    }

    /**
     * Returns the number of unexpired entries currently held. Intended for
     * tests and metrics.
     *
     * @return the number of unexpired entries currently held
     */
    public synchronized int size() {
        sweep();
        return entries.size();
    }

    @Override
    public synchronized void save(OidcStateEntry entry) {
        sweep();
        // Re-saving a state moves it to the tail, as a new entry.
        entries.remove(entry.state());
        while (entries.size() >= maxEntries) {
            Iterator<String> eldest = entries.keySet().iterator();
            eldest.next();
            eldest.remove();
        }
        entries.put(entry.state(), new Held(entry, System.currentTimeMillis() + ttlMillis));
    }

    @Override
    public synchronized @Nullable OidcStateEntry consume(String state) {
        Held held = entries.remove(state);
        if (held == null || held.expiresAtEpochMs <= System.currentTimeMillis()) {
            return null;
        }
        return held.entry;
    }

    /** Drops every expired entry: they are contiguous at the head. No background timer. */
    private void sweep() {
        long now = System.currentTimeMillis();
        Iterator<Held> it = entries.values().iterator();
        while (it.hasNext() && it.next().expiresAtEpochMs <= now) {
            it.remove();
        }
    }

    private record Held(OidcStateEntry entry, long expiresAtEpochMs) {
    }
}
