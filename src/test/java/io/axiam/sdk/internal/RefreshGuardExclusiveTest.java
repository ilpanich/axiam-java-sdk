package io.axiam.sdk.internal;

import io.axiam.sdk.errors.AuthError;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12 {@code oidcRefresh}: {@link RefreshGuard#runExclusive}
 * shares the SAME lock as {@link RefreshGuard#refreshIfNeeded}, so an
 * {@code oidcRefresh}-shaped operation can never interleave with a
 * cookie-session refresh.
 */
class RefreshGuardExclusiveTest {

    @Test
    void runExclusiveReturnsTheOperationResult() {
        RefreshGuard guard = new RefreshGuard();

        String result = guard.runExclusive(() -> "oidc-token-set");

        assertEquals("oidc-token-set", result);
    }

    @Test
    void runExclusivePropagatesTheOperationsException() {
        RefreshGuard guard = new RefreshGuard();
        RuntimeException failure = new RuntimeException("token endpoint 400");

        RuntimeException thrown = org.junit.jupiter.api.Assertions.assertThrows(RuntimeException.class,
                () -> guard.runExclusive(() -> {
                    throw failure;
                }));

        assertEquals(failure, thrown);
    }

    @Test
    void runExclusiveNeverOverlapsWithARefreshIfNeededInFlightRefresh() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        AtomicBoolean cookieRefreshInFlight = new AtomicBoolean(false);
        AtomicBoolean overlapDetected = new AtomicBoolean(false);
        AtomicInteger oidcRunCount = new AtomicInteger(0);

        CountDownLatch cookieRefreshStarted = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            var cookieRefreshFuture = pool.submit(() -> guard.refreshIfNeeded("stale-token", () -> {
                cookieRefreshInFlight.set(true);
                cookieRefreshStarted.countDown();
                sleepQuietly(150);
                cookieRefreshInFlight.set(false);
                return new TokenPair("new-access", "new-refresh", System.currentTimeMillis() + 900_000);
            }));

            assertTrue(cookieRefreshStarted.await(2, TimeUnit.SECONDS));

            String oidcResult = guard.runExclusive(() -> {
                oidcRunCount.incrementAndGet();
                if (cookieRefreshInFlight.get()) {
                    overlapDetected.set(true);
                }
                return "oidc-token-set";
            });

            cookieRefreshFuture.get(5, TimeUnit.SECONDS);

            assertEquals("oidc-token-set", oidcResult);
            assertEquals(1, oidcRunCount.get());
            assertFalse(overlapDetected.get(), "runExclusive must never run while a cookie-session refresh is in flight");
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    /**
     * Regression test for the wake-before-clear race: a {@code refreshIfNeeded}
     * publishes its outcome to waiters BEFORE it vacates the guard's in-flight
     * slot (so no late arrival can miss the shared result and issue a second
     * refresh wire call), which leaves a window in which the slot references an
     * already-settled future whose network call has long returned.
     *
     * <p>{@link RefreshGuard#runExclusive} used to treat that settled future as
     * "guard busy": it woke on the future's completion, {@code join()}ed it
     * (returning instantly), and burned its whole bounded attempt budget within
     * microseconds — failing a perfectly valid {@code oidcRefresh} with a
     * spurious {@link AuthError}. The window is pinned open deterministically
     * here via the package-private {@code afterPublishHook} seam instead of
     * being raced for, so the regression cannot silently return.
     */
    @Test
    void runExclusiveProceedsWhileASettledRefreshStillOccupiesTheGuardSlot() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        CountDownLatch wireCallEntered = new CountDownLatch(1);
        CountDownLatch publishWindowOpen = new CountDownLatch(1);
        CountDownLatch releaseRefresher = new CountDownLatch(1);
        AtomicInteger oidcRunCount = new AtomicInteger(0);

        // Pin the refreshing thread inside the "published, not yet vacated"
        // window. It holds no lock there, exactly as in production.
        guard.afterPublishHook = () -> {
            publishWindowOpen.countDown();
            awaitQuietly(releaseRefresher);
        };

        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<TokenPair> cookieRefresh = pool.submit(() -> guard.refreshIfNeeded("stale-token", () -> {
                wireCallEntered.countDown();
                return new TokenPair("new-access", "new-refresh", System.currentTimeMillis() + 900_000);
            }));

            assertTrue(wireCallEntered.await(2, TimeUnit.SECONDS));
            assertTrue(publishWindowOpen.await(2, TimeUnit.SECONDS));
            assertTrue(guard.inFlightSlotOccupied(),
                    "the settled-but-not-yet-vacated window must actually be open, "
                            + "otherwise this test asserts nothing");

            String oidcResult = guard.runExclusive(() -> {
                oidcRunCount.incrementAndGet();
                return "oidc-token-set";
            });

            assertEquals("oidc-token-set", oidcResult);
            assertEquals(1, oidcRunCount.get());

            releaseRefresher.countDown();
            assertEquals("new-access", cookieRefresh.get(5, TimeUnit.SECONDS).access(),
                    "the pinned refresh must still return its own result unchanged");
        } finally {
            releaseRefresher.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    /**
     * The bounded-failure path (CONTRACT.md &sect;9 rule 5: a bounded wait whose
     * exhaustion MUST raise {@code AuthError} rather than return a stale token
     * set) is reachable only while a refresh is genuinely LIVE — on the wire,
     * not merely settled-and-uncleared. Driven deterministically with the
     * package-private zero-attempt budget so no real contention is needed.
     */
    @Test
    void runExclusiveRaisesAuthErrorWhenALiveRefreshExhaustsTheAttemptBudget() throws Exception {
        RefreshGuard guard = new RefreshGuard(0); // never wait out even one live refresh
        CountDownLatch wireCallEntered = new CountDownLatch(1);
        CountDownLatch releaseWireCall = new CountDownLatch(1);
        AtomicInteger oidcRunCount = new AtomicInteger(0);

        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<TokenPair> cookieRefresh = pool.submit(() -> guard.refreshIfNeeded("stale-token", () -> {
                wireCallEntered.countDown();
                awaitQuietly(releaseWireCall); // hold the refresh genuinely in flight
                return new TokenPair("new-access", "new-refresh", System.currentTimeMillis() + 900_000);
            }));

            assertTrue(wireCallEntered.await(2, TimeUnit.SECONDS));

            AuthError thrown = assertThrows(AuthError.class, () -> guard.runExclusive(() -> {
                oidcRunCount.incrementAndGet();
                return "oidc-token-set";
            }));
            assertTrue(thrown.getMessage().contains("single-flight refresh guard"), thrown.getMessage());
            assertEquals(0, oidcRunCount.get(),
                    "op must not run at all when the guard could not be acquired");

            releaseWireCall.countDown();
            assertEquals("new-access", cookieRefresh.get(5, TimeUnit.SECONDS).access());
        } finally {
            releaseWireCall.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    /**
     * A settled-but-uncleared future must not consume any attempt at all: with a
     * zero-attempt budget (which raises {@link AuthError} on the first LIVE
     * refresh it meets, see above) {@code runExclusive} must still succeed while
     * the slot merely awaits cleanup.
     */
    @Test
    void aSettledRefreshConsumesNoAttemptBudget() throws Exception {
        RefreshGuard guard = new RefreshGuard(0);
        CountDownLatch publishWindowOpen = new CountDownLatch(1);
        CountDownLatch releaseRefresher = new CountDownLatch(1);

        guard.afterPublishHook = () -> {
            publishWindowOpen.countDown();
            awaitQuietly(releaseRefresher);
        };

        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<TokenPair> cookieRefresh = pool.submit(() -> guard.refreshIfNeeded("stale-token",
                    () -> new TokenPair("new-access", "new-refresh", System.currentTimeMillis() + 900_000)));

            assertTrue(publishWindowOpen.await(2, TimeUnit.SECONDS));
            assertTrue(guard.inFlightSlotOccupied());

            assertEquals("oidc-token-set", guard.runExclusive(() -> "oidc-token-set"));

            releaseRefresher.countDown();
            cookieRefresh.get(5, TimeUnit.SECONDS);
        } finally {
            releaseRefresher.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    /**
     * A refresh that fails must still hand its failure to a {@code join()}ing
     * waiter as-is (&sect;9.3), and must leave the guard acquirable afterwards —
     * the failure path publishes before vacating the slot too.
     */
    @Test
    void runExclusiveIsAcquirableAfterAFailedRefreshAndOpStillRunsOnce() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        RuntimeException failure = new RuntimeException("refresh failed: 401 on /api/v1/auth/refresh");
        CountDownLatch publishWindowOpen = new CountDownLatch(1);
        CountDownLatch releaseRefresher = new CountDownLatch(1);
        AtomicInteger oidcRunCount = new AtomicInteger(0);

        guard.afterPublishHook = () -> {
            publishWindowOpen.countDown();
            awaitQuietly(releaseRefresher);
        };

        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<TokenPair> cookieRefresh = pool.submit(() -> guard.refreshIfNeeded("stale-token", () -> {
                throw failure;
            }));

            assertTrue(publishWindowOpen.await(2, TimeUnit.SECONDS));
            assertTrue(guard.inFlightSlotOccupied());

            assertEquals("oidc-token-set", guard.runExclusive(() -> {
                oidcRunCount.incrementAndGet();
                return "oidc-token-set";
            }));
            assertEquals(1, oidcRunCount.get());

            releaseRefresher.countDown();
            java.util.concurrent.ExecutionException wrapped = assertThrows(
                    java.util.concurrent.ExecutionException.class, () -> cookieRefresh.get(5, TimeUnit.SECONDS));
            assertEquals(failure, wrapped.getCause(), "§9.3: the original exception, as-is");
        } finally {
            releaseRefresher.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            assertTrue(latch.await(5, TimeUnit.SECONDS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
