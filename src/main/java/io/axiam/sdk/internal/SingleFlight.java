package io.axiam.sdk.internal;

import org.jspecify.annotations.Nullable;

import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/**
 * Collapses concurrent callers of an operation, per key, into exactly one real invocation, all
 * sharing its result or exception.
 *
 * <p>Used by {@code AxiamClient.oidcRefresh} and {@code oidcRefreshAsync} (CONTRACT.md &sect;9,
 * &sect;12): callers presenting the same refresh token and tenant (the key, a digest) share one wire
 * call; callers of different keys run independently and concurrently.
 *
 * <p><strong>Each flight owns its outcome.</strong> A flight is a holder created when its first
 * caller claims the key; every later caller of that key captures the same holder and reads the
 * outcome from it, never from state shared with the key's next flight. So a caller who joined flight
 * 1 receives flight 1's outcome even if flight 2 of the same key has started and finished meanwhile.
 *
 * <p><strong>Publish before vacate.</strong> The leader completes the holder first and only then
 * removes it from the key, identity-checked. A caller arriving between the two joins the published
 * flight and receives its outcome without a second invocation (&sect;9 rule 6a); a caller arriving
 * after the removal starts a fresh flight. No lock is held while the operation runs, and nothing here
 * parks a thread: synchronous joiners wait on their own thread, asynchronous ones get a future.
 *
 * @param <T> the operation's result type
 */
public final class SingleFlight<T> {

    /** The key of {@link #run(Supplier)}, the unkeyed form. */
    private static final String UNKEYED = "";

    private final ConcurrentHashMap<String, Flight<T>> flights = new ConcurrentHashMap<>();

    private volatile @Nullable Runnable afterPublishHook;
    private volatile @Nullable Runnable afterVacateHook;

    /** One flight's outcome holder plus the number of callers that claimed it. */
    private static final class Flight<T> {
        final CompletableFuture<T> outcome = new CompletableFuture<>();
        final AtomicInteger callers = new AtomicInteger();
    }

    /** A caller's claim on a flight: the flight, and whether this caller must run the operation. */
    private record Claim<T>(Flight<T> flight, boolean leader) {
    }

    /** Creates an idle single-flight coalescer with no call in progress. */
    public SingleFlight() {
    }

    /**
     * {@link #run(String, Supplier)} under one fixed key: every concurrent caller shares one flight.
     *
     * @param op the operation to coalesce
     * @return {@code op}'s result (shared across all concurrent callers)
     * @throws RuntimeException whatever {@code op} threw, re-raised to every caller of the flight
     */
    public T run(Supplier<T> op) {
        return run(UNKEYED, op);
    }

    /**
     * Runs {@code op} on the calling thread if no flight of {@code key} is live, otherwise waits on
     * the calling thread for the live flight and returns its outcome.
     *
     * @param key the flight's key; never a secret in the clear
     * @param op  the operation to coalesce
     * @return the flight's result
     * @throws RuntimeException whatever {@code op} threw, the same instance to every caller
     * @throws Error            whatever {@code op} threw, the same instance to every caller
     */
    public T run(String key, Supplier<T> op) {
        Claim<T> claim = claim(key);
        if (!claim.leader()) {
            return await(claim.flight().outcome);
        }
        T value;
        try {
            value = op.get();
        } catch (Throwable t) {
            settle(key, claim.flight(), null, t);
            throw t;
        }
        settle(key, claim.flight(), value, null);
        return value;
    }

    /**
     * Joins the live flight of {@code key}, or starts one whose {@code op} runs on {@code executor},
     * without blocking the calling thread.
     *
     * <p>The returned future is the caller's own copy of the flight's outcome: completing or
     * cancelling it does not affect the flight or any other caller. If {@code executor} refuses the
     * task, the flight fails with that refusal, so no caller is left waiting.
     *
     * @param key      the flight's key; never a secret in the clear
     * @param op       the operation to coalesce
     * @param executor runs {@code op} when this caller starts the flight
     * @return a future of the flight's outcome
     */
    public CompletableFuture<T> submit(String key, Supplier<T> op, Executor executor) {
        Claim<T> claim = claim(key);
        if (claim.leader()) {
            Flight<T> flight = claim.flight();
            try {
                executor.execute(() -> {
                    T value;
                    try {
                        value = op.get();
                    } catch (Throwable t) {
                        settle(key, flight, null, t);
                        if (t instanceof Error e) {
                            throw e;
                        }
                        return;
                    }
                    settle(key, flight, value, null);
                });
            } catch (Throwable t) {
                settle(key, flight, null, t);
            }
        }
        return claim.flight().outcome.copy();
    }

    private Claim<T> claim(String key) {
        boolean[] leader = {false};
        Flight<T> flight = flights.compute(key, (k, existing) -> {
            Flight<T> f = existing;
            if (f == null) {
                f = new Flight<>();
                leader[0] = true;
            }
            f.callers.incrementAndGet();
            return f;
        });
        return new Claim<>(flight, leader[0]);
    }

    /** Publishes the outcome to the flight's own holder, then vacates the key if it is still this flight. */
    private void settle(String key, Flight<T> flight, @Nullable T value, @Nullable Throwable error) {
        try {
            if (error != null) {
                flight.outcome.completeExceptionally(error);
            } else {
                flight.outcome.complete(value);
            }
            runHook(afterPublishHook);
        } finally {
            flights.remove(key, flight);
        }
        runHook(afterVacateHook);
    }

    private static <T> T await(CompletableFuture<T> outcome) {
        try {
            return outcome.join();
        } catch (CompletionException e) {
            // The flight's own failure, as-is: never a wrapper and never a retry.
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException re) {
                throw re;
            }
            if (cause instanceof Error err) {
                throw err;
            }
            throw e;
        }
    }

    private static void runHook(@Nullable Runnable hook) {
        if (hook != null) {
            hook.run();
        }
    }

    /**
     * Test seam: hooks run on the settling thread right after a flight's outcome is published (the
     * flight still holds its key) and right after it vacated its key. Never set in production.
     *
     * @param afterPublish run after publish, before vacate, or {@code null}
     * @param afterVacate  run after vacate, or {@code null}
     */
    public void setTestHooks(@Nullable Runnable afterPublish, @Nullable Runnable afterVacate) {
        this.afterPublishHook = afterPublish;
        this.afterVacateHook = afterVacate;
    }

    /**
     * Test seam: callers that have claimed a flight still holding its key (leaders and joiners).
     *
     * @return the number of such callers
     */
    public int callers() {
        return flights.values().stream().mapToInt(f -> f.callers.get()).sum();
    }

    /**
     * Test seam: the number of keys with a flight.
     *
     * @return the number of live flights
     */
    public int size() {
        return flights.size();
    }

    /**
     * Test seam: the keys with a flight.
     *
     * @return a snapshot of the keys
     */
    public Set<String> keys() {
        return Set.copyOf(flights.keySet());
    }
}
