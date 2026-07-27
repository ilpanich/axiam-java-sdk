package io.axiam.sdk.internal;

import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * Collapses N concurrent callers of an operation into exactly one real
 * invocation, all sharing its result or exception.
 *
 * <p>Used by {@code AxiamClient.oidcRefresh} (CONTRACT.md &sect;12,
 * port-brief-addendum item 14): concurrent {@code oidcRefresh} callers must
 * collapse into one wire call, whose result all callers share, distinct from
 * (but composed with) the &sect;9 {@link RefreshGuard} mutual-exclusion
 * requirement.
 *
 * @param <T> the operation's result type
 */
public final class SingleFlight<T> {

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition settled = lock.newCondition();
    private boolean inFlight;
    private T result;
    private RuntimeException error;

    /** Creates an idle single-flight coalescer with no call in progress. */
    public SingleFlight() {
    }

    /**
     * Runs {@code op} exactly once across any number of concurrent callers;
     * every other concurrent caller blocks and then receives the same result
     * or re-raises the same exception.
     *
     * @param op the operation to coalesce
     * @return {@code op}'s result (shared across all concurrent callers)
     * @throws RuntimeException whatever {@code op} threw, re-raised to every waiter
     */
    public T run(Supplier<T> op) {
        lock.lock();
        try {
            if (inFlight) {
                // Someone else is already running op(): wait for it to settle
                // and share its outcome — do NOT run op() again ourselves.
                while (inFlight) {
                    settled.awaitUninterruptibly();
                }
                if (error != null) {
                    throw error;
                }
                return result;
            }
            inFlight = true;
        } finally {
            lock.unlock();
        }

        try {
            T value = op.get();
            lock.lock();
            try {
                result = value;
                error = null;
                inFlight = false;
                settled.signalAll();
            } finally {
                lock.unlock();
            }
            return value;
        } catch (RuntimeException e) {
            lock.lock();
            try {
                error = e;
                inFlight = false;
                settled.signalAll();
            } finally {
                lock.unlock();
            }
            throw e;
        }
    }
}
