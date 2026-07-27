package io.axiam.sdk.internal;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * Origin-keyed cache with single-flight fetching, used for the CONTRACT.md
 * &sect;12.3 rule 6 OIDC discovery-document cache.
 *
 * <p>The key is normally the normalized <strong>scheme + host + port</strong>
 * of the base URL a document was fetched from, so a document fetched from one
 * origin can never be served for another (cross-issuer cache poisoning) — this
 * class does not compute the key itself, callers supply it. Per-{@code
 * AxiamClient}-instance (never process-global) and not keyed on tenant.
 *
 * <p>Single-flight is a single {@link ReentrantLock} held across the entire
 * fetch (double-checked-locking): any concurrent caller blocks until the
 * in-progress fetch completes, then reads the now-populated cache instead of
 * re-fetching. Generic so the same mechanism backs any per-origin/per-key
 * value, not just an OIDC discovery document.
 *
 * @param <T> the cached value type
 */
public final class DiscoveryCache<T> {

    private final long ttlMillis;
    private final Map<String, CachedValue<T>> values = new ConcurrentHashMap<>();
    private final ReentrantLock lock = new ReentrantLock();

    /**
     * Creates a cache with the given TTL floored at {@code minTtlMillis}.
     *
     * @param ttlMillis    the requested TTL, in milliseconds
     * @param minTtlMillis the minimum TTL this cache enforces; a smaller
     *                     {@code ttlMillis} is raised to it
     */
    public DiscoveryCache(long ttlMillis, long minTtlMillis) {
        this.ttlMillis = Math.max(ttlMillis, minTtlMillis);
    }

    /**
     * Returns the cached value for {@code key} if still fresh, else invokes
     * {@code fetcher} exactly once (even under concurrent callers for the
     * same key) and caches its result.
     *
     * @param key     the cache key (e.g. a normalized origin)
     * @param fetcher performs the actual fetch; invoked at most once per
     *                cache miss/expiry, never while another thread's fetch
     *                for the SAME OR a DIFFERENT key is already resolved from
     *                cache, but may block behind another key's concurrent
     *                fetch since this cache uses one lock for all keys
     * @return the fresh or freshly-fetched value
     * @throws RuntimeException whatever {@code fetcher} throws, propagated as-is
     */
    public T get(String key, Supplier<T> fetcher) {
        CachedValue<T> cached = values.get(key);
        if (cached != null && cached.expiresAtEpochMs > System.currentTimeMillis()) {
            return cached.value;
        }
        lock.lock();
        try {
            cached = values.get(key);
            if (cached != null && cached.expiresAtEpochMs > System.currentTimeMillis()) {
                return cached.value;
            }
            T fetched = fetcher.get();
            values.put(key, new CachedValue<>(fetched, System.currentTimeMillis() + ttlMillis));
            return fetched;
        } finally {
            lock.unlock();
        }
    }

    private record CachedValue<V>(V value, long expiresAtEpochMs) {
    }
}
