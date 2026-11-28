package io.axiam.sdk.internal;

import org.jspecify.annotations.Nullable;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * The §9 single-flight refresh guard (D-07, CONTRACT.md &sect;9): exactly
 * one in-flight {@code POST /api/v1/auth/refresh} call across any number of
 * concurrent callers observing the same stale/expired access token.
 *
 * <p>One instance is constructed per {@code AxiamClient} and shared by the
 * REST interceptor/authenticator AND the gRPC client (D-07's "one guard"
 * requirement) — never a second instance per transport.
 *
 * <p>Uses a {@link ReentrantLock} (NOT {@code synchronized}) so the lock is
 * never held across the actual HTTP call — {@code synchronized} around I/O
 * would serialize every concurrent caller behind the network round-trip and
 * is not virtual-thread-friendly (D-10). The lock is released before
 * blocking on {@link CompletableFuture#join()} so a waiter's block never
 * holds the mutex it would otherwise need for its own double-check.
 *
 * <p><strong>No retry loop (§9.3):</strong> a failing {@code doRefresh}
 * propagates its exception, as-is, to every waiter exactly once. The caller
 * must re-authenticate from scratch; this class never re-attempts a failed
 * refresh automatically.
 *
 * <p><strong>The {@link #inFlight} slot is a result-sharing channel, not a
 * busy flag.</strong> {@link #inFlight} holds the {@link CompletableFuture} that publishes the
 * single refresh's outcome to every waiter (§9 rule 2). It therefore has to
 * stay populated <em>until after</em> that outcome has been published: a
 * late-arriving caller that finds the slot occupied joins the shared future
 * and receives the one wire call's result, whereas a caller that found the
 * slot already emptied would start a <em>second</em> refresh — fatal against
 * AXIAM's single-use, rotating refresh tokens. Publication therefore always
 * happens <em>before</em> the slot is cleared, which means there is a short
 * window in which the slot references an <strong>already-settled</strong>
 * future whose network call has long returned.
 *
 * <p>The {@code oidc_refresh} single-flight is not this guard: it is keyed per refresh token and tenant
 * and never holds this guard's lock across its wire call (CONTRACT.md &sect;9 rule 7).
 */
public final class RefreshGuard {

    private final ReentrantLock lock = new ReentrantLock();

    // Holds the shared result future of the one refresh that is currently
    // being coalesced. Populated for the duration of the wire call AND for
    // the brief bookkeeping window after the outcome has been published (see
    // the class Javadoc) — so a non-null value does NOT by itself mean a
    // refresh is still on the wire.
    private final AtomicReference<CompletableFuture<TokenPair>> inFlight = new AtomicReference<>();

    private volatile @Nullable TokenPair current;

    /** Creates a new, empty refresh guard (no cached token yet). */
    public RefreshGuard() {
    }

    /**
     * Ensures exactly one call to {@code doRefresh} is in flight at a time,
     * regardless of how many threads call this concurrently with the same
     * (now-stale) {@code observedAccessToken}.
     *
     * <p>Double-check-after-lock: if another thread already completed a
     * refresh while this caller waited for the lock (i.e. the cached
     * token no longer matches what this caller observed as stale), the
     * cached token is returned immediately — no new refresh is performed.
     *
     * <p><strong>Completion ordering.</strong> On the success path
     * {@link #current} is published <em>before</em> the shared future
     * completes, and the {@link #inFlight} slot is only vacated <em>after</em>
     * it; on the failure path the exception is likewise published before the
     * slot is vacated. Both orderings exist so that a caller arriving at any
     * instant either (a) finds the slot occupied and joins the shared future,
     * or (b) finds the slot empty and the fresh token already cached — never
     * "slot empty and nothing cached", which is the only state that would let
     * it issue a redundant second refresh wire call (§9 rule 2's observable
     * requirement). The cost of that ordering is the settled-but-uncleared
     * window documented in the class Javadoc.
     *
     * @param observedAccessToken the access token this caller observed as
     *                             stale/expired/rejected
     * @param doRefresh            performs the actual
     *                             {@code POST /api/v1/auth/refresh} call;
     *                             invoked OUTSIDE the lock, at most once per
     *                             call to this method
     * @return the resolved (current or freshly refreshed) token pair
     * @throws RuntimeException whatever {@code doRefresh} throws, propagated
     *                          as-is to every waiter (§9.3 — no retry)
     */
    public TokenPair refreshIfNeeded(String observedAccessToken, Supplier<TokenPair> doRefresh) {
        lock.lock();
        try {
            TokenPair snapshot = current;
            if (snapshot != null && !snapshot.access().equals(observedAccessToken)) {
                // Another thread already refreshed while we waited for the
                // lock — no new refresh needed.
                return snapshot;
            }

            CompletableFuture<TokenPair> existing = inFlight.get();
            if (existing != null) {
                lock.unlock(); // release before blocking on join()
                try {
                    return existing.join();
                } catch (CompletionException e) {
                    // §9.3: hand the single refresh's failure to this waiter
                    // as-is, never a wrapper and never a retry.
                    Throwable cause = e.getCause();
                    if (cause instanceof RuntimeException re) {
                        throw re;
                    }
                    if (cause instanceof Error err) {
                        throw err;
                    }
                    throw e;
                } finally {
                    lock.lock(); // re-acquire so the outer finally's unlock() is balanced
                }
            }

            CompletableFuture<TokenPair> future = new CompletableFuture<>();
            inFlight.set(future);
            lock.unlock(); // perform the actual HTTP call OUTSIDE the lock
            try {
                TokenPair result = doRefresh.get(); // POST /api/v1/auth/refresh
                current = result; // cached BEFORE the slot is vacated (see above)
                future.complete(result);
                return result;
            } catch (Throwable t) {
                // Publish to every waiter first, THEN vacate the slot, so no
                // late arrival can miss this outcome and retry the refresh.
                // Catches Throwable (not just RuntimeException) purely so an
                // Error can never leave the shared future uncompleted and its
                // waiters blocked forever in join(); §9.3 is unchanged — the
                // original throwable is rethrown as-is, never retried.
                future.completeExceptionally(t);
                throw t;
            } finally {
                // Reached with the outcome published and the slot still
                // occupied, on both the success and the failure path.
                inFlight.compareAndSet(future, null);
                lock.lock(); // re-acquire so the outer finally's unlock() is balanced
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Non-blocking read of the most recently cached token pair, for hot-path
     * callers (the REST {@code Interceptor}, the gRPC client interceptor)
     * that must never synchronously acquire this guard's lock. A plain
     * volatile field read — never {@code lock.lock()}.
     *
     * @return the cached token pair, or {@link Optional#empty()} if no refresh
     *         has completed yet
     */
    public Optional<TokenPair> cached() {
        return Optional.ofNullable(current);
    }

    /**
     * Non-blocking read of the currently cached access token, or
     * {@code null} if none has been cached yet. See {@link #cached()}.
     *
     * @return the cached access token, or {@code null} if no refresh has
     *         completed yet
     */
    public @Nullable String cachedAccessToken() {
        TokenPair snapshot = current;
        return snapshot == null ? null : snapshot.access();
    }
}
