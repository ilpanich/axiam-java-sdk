package io.axiam.sdk.internal;

import io.axiam.sdk.errors.AuthError;

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
 * <p>Consequently the slot's occupancy alone does <strong>not</strong> mean
 * "a refresh is on the wire". Anything that needs to know whether a refresh
 * is genuinely live — i.e. {@link #runExclusive} — must ask
 * {@link CompletableFuture#isDone()} as well; see
 * {@link #isRefreshLive(CompletableFuture)}. Treating a settled-but-uncleared
 * future as "busy" is what previously let {@link #runExclusive} burn its whole
 * bounded attempt budget in a few microseconds on a guard that was in fact
 * free, and fail a perfectly valid {@code oidcRefresh} with a spurious
 * "guard busy" {@link AuthError}.
 */
public final class RefreshGuard {

    private final ReentrantLock lock = new ReentrantLock();

    // Holds the shared result future of the one refresh that is currently
    // being coalesced. Populated for the duration of the wire call AND for
    // the brief bookkeeping window after the outcome has been published (see
    // the class Javadoc) — so a non-null value does NOT by itself mean a
    // refresh is still on the wire; use isRefreshLive(..) for that.
    private final AtomicReference<CompletableFuture<TokenPair>> inFlight = new AtomicReference<>();

    private volatile @Nullable TokenPair current;

    /** Effective {@link #runExclusive} attempt budget; see {@link #RUN_EXCLUSIVE_MAX_ATTEMPTS}. */
    private final int runExclusiveMaxAttempts;

    /**
     * Visible-for-testing seam: run on the refreshing thread immediately after
     * {@link #refreshIfNeeded} has published its outcome to waiters and while
     * that thread holds no lock — i.e. exactly inside the "settled future
     * still occupying the slot" window described in the class Javadoc. Lets a
     * test pin that window open deterministically instead of racing for it.
     * Never set in production (always {@code null}).
     */
    @Nullable volatile Runnable afterPublishHook;

    /** Creates a new, empty refresh guard (no cached token yet). */
    public RefreshGuard() {
        this(RUN_EXCLUSIVE_MAX_ATTEMPTS);
    }

    /**
     * Visible-for-testing constructor that overrides the {@link #runExclusive}
     * attempt budget. {@code 0} means "never wait out even one live refresh",
     * which is how the bounded-failure branch is reached deterministically in
     * tests; production code always uses the {@link #RefreshGuard()} default of
     * {@value #RUN_EXCLUSIVE_MAX_ATTEMPTS}.
     *
     * @param runExclusiveMaxAttempts attempt budget for {@link #runExclusive}
     */
    RefreshGuard(int runExclusiveMaxAttempts) {
        this.runExclusiveMaxAttempts = runExclusiveMaxAttempts;
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
                afterPublish();
                inFlight.compareAndSet(future, null);
                lock.lock(); // re-acquire so the outer finally's unlock() is balanced
            }
        } finally {
            lock.unlock();
        }
    }

    /** Bounded retry count for {@link #runExclusive} waiting out a busy guard
     * (port-brief-addendum item 14: "retry the guard (bounded — TS uses 3 attempts)"). */
    private static final int RUN_EXCLUSIVE_MAX_ATTEMPTS = 3;

    /**
     * Runs an arbitrary refresh-shaped operation mutually exclusive with
     * {@link #refreshIfNeeded} and with any other concurrent
     * {@code runExclusive} call — the CONTRACT.md &sect;12 requirement that
     * {@code oidcRefresh} "runs the wire call inside the existing &sect;9
     * guard" so a cookie-session refresh and an {@code oidcRefresh} can never
     * interleave.
     *
     * <p>Because {@link #refreshIfNeeded} deliberately releases {@link #lock}
     * for the duration of its own HTTP call (see this class's header
     * Javadoc), a plain {@code lock.lock()} around {@code op} would only
     * exclude the brief bookkeeping windows around that call, not the call
     * itself. So this method first waits out any <em>live</em> refresh, then
     * takes {@link #lock} and re-checks under it before running {@code op};
     * holding {@link #lock} across {@code op} in turn blocks any NEW
     * {@link #refreshIfNeeded} call from starting until {@code op} completes,
     * since that method takes the lock first thing.
     *
     * <p><strong>"Live" means not yet settled.</strong> A refresh counts as
     * live only while its shared future is incomplete — see
     * {@link #isRefreshLive(CompletableFuture)} and the class Javadoc on why
     * the {@link #inFlight} slot outlives the wire call. Once that future has
     * settled, {@code doRefresh} has already returned, so running {@code op}
     * cannot overlap it and there is nothing left to wait for; the residual
     * bookkeeping is finished by the refreshing thread, which will simply
     * block on {@link #lock} behind {@code op}.
     *
     * <p><strong>Termination and the bounded budget.</strong> Every loop
     * iteration does exactly one of three things: run {@code op} and return,
     * exhaust the budget and throw, or spend one attempt <em>blocking</em> on
     * a genuinely live refresh (either found before taking the lock, or found
     * under the lock as a lost race against a refresh that started in
     * between). Nothing else consumes an attempt and nothing spins, so the
     * loop performs at most {@value #RUN_EXCLUSIVE_MAX_ATTEMPTS}+1 iterations
     * and burns no CPU while waiting — CONTRACT.md §9 rule 5's "bounded
     * (never unbounded) wait ... exhausting that bound MUST raise
     * {@code AuthError}". Because attempts are only ever spent on live
     * refreshes, the {@link AuthError} below is reachable only under real
     * sustained contention: {@value #RUN_EXCLUSIVE_MAX_ATTEMPTS} distinct
     * cookie-session refresh wire calls monopolising the guard back-to-back.
     *
     * <p>Unlike {@link #refreshIfNeeded}, this does not compare against an
     * observed access token or cache a {@link TokenPair} — it purely
     * provides mutual exclusion.
     *
     * @param op  the operation to run exclusively; invoked at most once
     * @param <T> the operation's result type
     * @return {@code op}'s result
     * @throws AuthError        if a live cookie-session refresh still holds the
     *                          guard after
     *                          {@value #RUN_EXCLUSIVE_MAX_ATTEMPTS} attempts
     * @throws RuntimeException whatever {@code op} throws, propagated as-is
     */
    public <T> T runExclusive(Supplier<T> op) {
        int attemptsSpent = 0;
        while (true) {
            CompletableFuture<TokenPair> busy = inFlight.get();
            if (isRefreshLive(busy)) {
                if (attemptsSpent++ >= runExclusiveMaxAttempts) {
                    throw guardBusy();
                }
                // A cookie-session refresh is actively mid-flight (lock
                // released for that duration by design) — block until it
                // settles, ignoring its outcome, then re-check from the top.
                awaitSettled(busy);
                continue;
            }
            // The slot is either empty or holds a settled future whose wire
            // call has already returned; neither can overlap op.
            lock.lock();
            try {
                CompletableFuture<TokenPair> raced = inFlight.get();
                if (isRefreshLive(raced)) {
                    // Lost the race: a refreshIfNeeded call started between
                    // our check above and acquiring the lock. Release the lock
                    // (via the finally below) and wait it out on the next
                    // iteration — real contention, so it costs an attempt.
                    if (attemptsSpent++ >= runExclusiveMaxAttempts) {
                        throw guardBusy();
                    }
                    continue;
                }
                return op.get();
            } finally {
                lock.unlock();
            }
        }
    }

    /**
     * Whether {@code future} represents a refresh that is still on the wire.
     * A {@code null} slot means no refresh at all; a settled future means the
     * refresh's {@code doRefresh} call has already returned and only the
     * slot-vacating bookkeeping is outstanding (class Javadoc).
     *
     * @param future the current {@link #inFlight} slot value, possibly {@code null}
     * @return {@code true} only while a refresh wire call is genuinely outstanding
     */
    private static boolean isRefreshLive(@Nullable CompletableFuture<TokenPair> future) {
        return future != null && !future.isDone();
    }

    /** Blocks until {@code future} settles, discarding its outcome. */
    private static void awaitSettled(CompletableFuture<TokenPair> future) {
        try {
            future.join();
        } catch (Throwable ignored) {
            // Outcome is irrelevant here — only that it settled.
        }
    }

    private static AuthError guardBusy() {
        return new AuthError(
                "oidcRefresh could not acquire the single-flight refresh guard (CONTRACT.md §9); "
                        + "another refresh kept it busy.");
    }

    /** Invokes {@link #afterPublishHook} if a test installed one. */
    private void afterPublish() {
        Runnable hook = afterPublishHook;
        if (hook != null) {
            hook.run();
        }
    }

    /**
     * Visible-for-testing: whether the {@link #inFlight} result-sharing slot is
     * currently populated, regardless of whether its future has settled. Used
     * by the regression test to assert that the settled-but-uncleared window
     * described in the class Javadoc really is open at the moment
     * {@link #runExclusive} is exercised.
     *
     * @return {@code true} if the slot holds a future (live or settled)
     */
    boolean inFlightSlotOccupied() {
        return inFlight.get() != null;
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
