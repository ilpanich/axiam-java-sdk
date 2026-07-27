package io.axiam.sdk.internal;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
