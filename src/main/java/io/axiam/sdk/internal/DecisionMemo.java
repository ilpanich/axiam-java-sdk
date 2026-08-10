package io.axiam.sdk.internal;

import io.axiam.sdk.telemetry.TelemetryEvent;
import java.time.Duration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.LongSupplier;
import org.jspecify.annotations.Nullable;

/**
 * Client-side decision memo (CONTRACT.md §17).
 *
 * <p><strong>Disabled by default.</strong> §11.2 rule 6's ban on caching
 * allow/deny decisions is still the default behaviour; this is the single
 * opt-in exception that section carves out, and a caller has to switch it on
 * having read the cost.
 *
 * <h2>What it costs</h2>
 *
 * <p>The staleness bound is the TTL, <strong>in both directions</strong>. A
 * grant revoked on the server can still read as allowed for up to the TTL, and
 * a grant just added can still read as denied for up to the TTL. That second
 * direction is the one that surprises people: <strong>reads-your-own-writes is
 * not guaranteed.</strong> An admin UI that grants a role and immediately
 * re-checks is the case that breaks, and it breaks silently.
 *
 * <p>This mirrors the server's own bound rather than inventing a second
 * staleness story — {@code AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS} (default 5s)
 * makes the same trade server-side. One deliberate difference: the server's
 * setting is an unclamped integer, so an operator can configure a multi-hour
 * staleness window. {@link #MAX_TTL} clamps this one at 5s, because the client
 * has no reason to repeat that.
 *
 * <p>Thread-safe by synchronization: a Java client is routinely shared across a
 * request-handling thread pool, and a cache that corrupted under concurrency
 * would be a worse bug than the one it is optimising away.
 *
 * <p>Generic in the decision type so this package stays free of any dependency
 * on the public client surface — the same shape as {@link DiscoveryCache}.
 *
 * @param <T> the memoized decision type
 */
public final class DecisionMemo<T> {

    /**
     * The §17.1 rule 2 ceiling. A configured TTL above this is clamped, not
     * rejected: a caller who asked for a minute wants caching, and silently
     * giving them the maximum safe value beats failing construction.
     */
    public static final Duration MAX_TTL = Duration.ofSeconds(5);

    /**
     * Entry cap before eviction (§17.1 rule 8). The memo is a latency
     * optimisation, so dropping an entry is always correct — but it must drop
     * rather than grow without bound.
     */
    static final int MAX_ENTRIES = 1024;

    /**
     * Joins the key components. The unit separator (U+001F) cannot appear in an
     * action, a UUID or a scope, so no combination of caller-supplied values
     * can forge a collision.
     */
    private static final String SEP = "\u001F";

    /**
     * Marks an absent optional (U+0000), which is why an absent scope can never
     * collide with a present one — a memo that let them collide would answer a
     * narrower question with a broader answer.
     */
    private static final String ABSENT = "\u0000";

    private final long ttlMillis;
    private final LongSupplier clock;
    private final Map<String, Entry<T>> entries;

    /**
     * Builds a memo.
     *
     * @param ttl   requested TTL; null or non-positive disables the memo, and
     *              anything above {@link #MAX_TTL} is clamped to it
     * @param clock injected millisecond clock, so the TTL can be tested without
     *              waiting
     */
    public DecisionMemo(@Nullable Duration ttl, LongSupplier clock) {
        long requested = (ttl == null || ttl.isNegative()) ? 0L : ttl.toMillis();
        this.ttlMillis = Math.min(requested, MAX_TTL.toMillis());
        this.clock = clock;
        // Insertion order (accessOrder=false) makes the eviction below FIFO
        // rather than LRU: entries expire on age, so the oldest is the one that
        // was going to expire first anyway.
        this.entries = new LinkedHashMap<>(64, 0.75f, false);
    }

    /**
     * Builds a memo on the system clock.
     *
     * @param ttl requested TTL; see {@link #DecisionMemo(Duration, LongSupplier)}
     */
    public DecisionMemo(@Nullable Duration ttl) {
        this(ttl, System::currentTimeMillis);
    }

    /**
     * Whether this memo does anything.
     *
     * @return false for the default configuration
     */
    public boolean enabled() {
        return ttlMillis > 0;
    }

    /**
     * The TTL after clamping.
     *
     * @return the effective TTL in milliseconds
     */
    public long effectiveTtlMillis() {
        return ttlMillis;
    }

    /**
     * Builds the §17.1 rule 3 key: all four components, absent distinguished
     * from present.
     *
     * @param subjectId  the subject, or null for this client's own session
     * @param resourceId the resource
     * @param action     the action
     * @param scope      the sub-resource scope, or null
     * @return the memo key
     */
    public static String key(@Nullable String subjectId, String resourceId, String action,
                             @Nullable String scope) {
        return (subjectId == null ? ABSENT : subjectId) + SEP
                + resourceId + SEP
                + action + SEP
                + (scope == null ? ABSENT : scope);
    }

    /**
     * A live decision for {@code key}, if one is memoized and unexpired.
     *
     * @param key the memo key
     * @return the decision, or null on a miss
     */
    public synchronized @Nullable T get(String key) {
        if (!enabled()) {
            return null;
        }
        Entry<T> entry = entries.get(key);
        if (entry == null) {
            return null;
        }
        if (clock.getAsLong() - entry.storedAt() >= ttlMillis) {
            entries.remove(key);
            return null;
        }
        // Returned whole, including the reason code: §17.1 rule 5 forbids
        // returning `allowed` while dropping the code, which would make the
        // field intermittently absent — worse than never having had it.
        return entry.result();
    }

    /**
     * Memoizes a decision the server actually returned.
     *
     * <p>Callers must only reach here on success. §17.1 rule 7 forbids
     * negative-caching a failure: memoizing a transport error as a deny would
     * turn a blip into a TTL-long outage, and memoizing it as an allow is
     * unthinkable.
     *
     * @param key    the memo key
     * @param result the decision to store
     */
    public synchronized void put(String key, T result) {
        if (!enabled()) {
            return;
        }
        entries.remove(key);
        entries.put(key, new Entry<>(result, clock.getAsLong()));
        while (entries.size() > MAX_ENTRIES) {
            Iterator<String> it = entries.keySet().iterator();
            it.next();
            it.remove();
        }
    }

    /**
     * Drops every entry (§17.1 rule 9).
     *
     * <p>Called on login, verifyMfa, refresh and logout. Entries are keyed by
     * subject, not by session, so a re-authentication as a <em>different</em>
     * principal would otherwise read the previous principal's decisions.
     */
    public synchronized void clear() {
        entries.clear();
    }

    /**
     * Emits a {@link TelemetryEvent.ConfigClamped} if the requested TTL was
     * clamped (CONTRACT.md &#167;19.2 rule 6).
     *
     * <p>This is the clamp that matters most to get right: an operator who set a
     * 60-second TTL believes their staleness bound is 60 seconds. It is five, and
     * without this event nothing anywhere says so.
     *
     * <p>Nothing is emitted when the requested value was already inside the
     * limit, or when the memo is disabled — an event that fires when nothing
     * happened trains its reader to ignore it.
     *
     * @param requested the TTL the caller asked for, or null
     * @param telemetry the §19 dispatcher
     */
    public void reportClamp(@Nullable Duration requested, TelemetryDispatcher telemetry) {
        if (requested == null || requested.isNegative() || requested.isZero()) {
            return;
        }
        if (requested.toMillis() == ttlMillis) {
            return;
        }
        telemetry.emit(new TelemetryEvent.ConfigClamped(
                "decisionMemoTtl",
                requested.toString(),
                Duration.ofMillis(ttlMillis).toString(),
                "§17.1 rule 2"));
    }

    /**
     * Entry count, for tests.
     *
     * @return the number of entries currently held
     */
    public synchronized int size() {
        return entries.size();
    }

    private record Entry<T>(T result, long storedAt) {
    }
}
