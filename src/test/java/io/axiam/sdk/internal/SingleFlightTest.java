package io.axiam.sdk.internal;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12, port-brief-addendum item 14: {@code oidcRefresh}'s
 * own single-flight de-duplication layer collapses N concurrent callers into
 * exactly one invocation, sharing the result or exception.
 */
class SingleFlightTest {

    @Test
    void concurrentCallersCollapseIntoExactlyOneInvocation() throws Exception {
        SingleFlight<String> flight = new SingleFlight<>();
        AtomicInteger invocations = new AtomicInteger(0);

        int threadCount = 6;
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startBarrier = new CountDownLatch(1);
        try {
            List<Callable<String>> tasks = new java.util.ArrayList<>();
            for (int i = 0; i < threadCount; i++) {
                tasks.add(() -> {
                    startBarrier.await();
                    return flight.run(() -> {
                        invocations.incrementAndGet();
                        sleepQuietly(50);
                        return "result";
                    });
                });
            }
            List<Future<String>> futures = new java.util.ArrayList<>();
            for (Callable<String> task : tasks) {
                futures.add(pool.submit(task));
            }
            startBarrier.countDown();
            for (Future<String> future : futures) {
                assertEquals("result", future.get(5, TimeUnit.SECONDS));
            }
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }

        assertEquals(1, invocations.get());
    }

    @Test
    void aSubsequentCallAfterSettlingRunsAgain() {
        SingleFlight<String> flight = new SingleFlight<>();
        AtomicInteger invocations = new AtomicInteger(0);

        String first = flight.run(() -> "v" + invocations.incrementAndGet());
        String second = flight.run(() -> "v" + invocations.incrementAndGet());

        assertEquals("v1", first);
        assertEquals("v2", second);
        assertEquals(2, invocations.get());
    }

    @Test
    void failureIsSharedByEveryWaiter() throws Exception {
        SingleFlight<String> flight = new SingleFlight<>();
        AtomicInteger invocations = new AtomicInteger(0);
        RuntimeException failure = new RuntimeException("boom");

        int threadCount = 5;
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startBarrier = new CountDownLatch(1);
        try {
            List<Callable<String>> tasks = new java.util.ArrayList<>();
            for (int i = 0; i < threadCount; i++) {
                tasks.add(() -> {
                    startBarrier.await();
                    return flight.run(() -> {
                        invocations.incrementAndGet();
                        sleepQuietly(50);
                        throw failure;
                    });
                });
            }
            List<Future<String>> futures = new java.util.ArrayList<>();
            for (Callable<String> task : tasks) {
                futures.add(pool.submit(task));
            }
            startBarrier.countDown();
            for (Future<String> future : futures) {
                RuntimeException thrown = assertThrows(RuntimeException.class, () -> {
                    try {
                        future.get(5, TimeUnit.SECONDS);
                    } catch (java.util.concurrent.ExecutionException e) {
                        throw (RuntimeException) e.getCause();
                    }
                });
                assertSame(failure, thrown, "every waiter must observe the SAME exception instance");
            }
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }

        assertEquals(1, invocations.get());
    }

    /**
     * Each flight owns its outcome: joiners parked on flight 1 return flight 1's outcome even when a
     * same-key caller arrives right after flight 1 vacated and runs flight 2 to completion before
     * those joiners read anything. The arrival is made from the after-vacate hook, on the leader's
     * own thread, so it happens at the earliest reachable instant and before any joiner can resume.
     */
    @Test
    void joinersOfFlightOneNeverReceiveTheOutcomeOfFlightTwo() throws Exception {
        SingleFlight<String> flight = new SingleFlight<>();
        AtomicInteger invocations = new AtomicInteger();
        CountDownLatch release = new CountDownLatch(1);
        java.util.concurrent.atomic.AtomicReference<String> secondFlight = new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicBoolean fired = new java.util.concurrent.atomic.AtomicBoolean();
        flight.setTestHooks(null, () -> {
            if (fired.compareAndSet(false, true)) {
                secondFlight.set(flight.run(() -> "flight-2:" + invocations.incrementAndGet()));
            }
        });

        int joiners = 8;
        ExecutorService pool = Executors.newFixedThreadPool(joiners + 1);
        try {
            Future<String> leader = pool.submit(() -> flight.run(() -> {
                invocations.incrementAndGet();
                awaitQuietly(release);
                return "flight-1";
            }));
            awaitCallers(flight, 1);
            List<Future<String>> parked = new java.util.ArrayList<>();
            for (int i = 0; i < joiners; i++) {
                parked.add(pool.submit(() -> flight.run(() -> "a joiner must never run op: " + invocations.incrementAndGet())));
            }
            awaitCallers(flight, joiners + 1);
            release.countDown();

            assertEquals("flight-1", leader.get(5, TimeUnit.SECONDS));
            for (Future<String> f : parked) {
                assertEquals("flight-1", f.get(5, TimeUnit.SECONDS), "a flight-1 joiner got another flight's outcome");
            }
            assertEquals("flight-2:2", secondFlight.get(), "the caller after vacate started its own flight");
            assertEquals(2, invocations.get());
        } finally {
            pool.shutdownNow();
        }
    }

    /** An Error from op reaches the leader and every joiner, and does not wedge the slot. */
    @Test
    void anErrorIsPublishedToEveryJoinerAndTheSlotIsVacated() throws Exception {
        SingleFlight<String> flight = new SingleFlight<>();
        CountDownLatch release = new CountDownLatch(1);
        Error failure = new StackOverflowError("simulated");

        int joiners = 4;
        ExecutorService pool = Executors.newFixedThreadPool(joiners + 1);
        try {
            Future<String> leader = pool.submit(() -> flight.run(() -> {
                awaitQuietly(release);
                throw failure;
            }));
            awaitCallers(flight, 1);
            List<Future<String>> parked = new java.util.ArrayList<>();
            for (int i = 0; i < joiners; i++) {
                parked.add(pool.submit(() -> flight.run(() -> "a joiner must never run op")));
            }
            awaitCallers(flight, joiners + 1);
            release.countDown();

            java.util.concurrent.ExecutionException leaderFailure = assertThrows(
                    java.util.concurrent.ExecutionException.class, () -> leader.get(5, TimeUnit.SECONDS));
            assertSame(failure, leaderFailure.getCause(), "the leader gets the Error itself");
            for (Future<String> f : parked) {
                java.util.concurrent.ExecutionException e = assertThrows(
                        java.util.concurrent.ExecutionException.class, () -> f.get(5, TimeUnit.SECONDS),
                        "a joiner must not hang after an Error");
                assertSame(failure, e.getCause(), "joiners get the same Error, as RefreshGuard does");
            }
            Future<String> after = pool.submit(() -> flight.run(() -> "next"));
            assertEquals("next", after.get(5, TimeUnit.SECONDS), "the slot was vacated");
        } finally {
            pool.shutdownNow();
        }
    }

    /** submit: a refusing executor fails the flight with the refusal, and an async Error reaches the future. */
    @Test
    void submitPublishesARefusedExecutorAndAnAsyncErrorAndVacates() throws Exception {
        SingleFlight<String> flight = new SingleFlight<>();
        RuntimeException refused = new java.util.concurrent.RejectedExecutionException("closed");
        CompletableFuture<String> rejected = flight.submit("k", () -> "never", r -> {
            throw refused;
        });
        java.util.concurrent.ExecutionException e1 = assertThrows(java.util.concurrent.ExecutionException.class,
                () -> rejected.get(5, TimeUnit.SECONDS));
        assertSame(refused, e1.getCause());
        assertEquals(0, flight.size(), "a refused flight vacates its key");

        Error failure = new StackOverflowError("simulated");
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            CompletableFuture<String> failed = flight.submit("k", () -> {
                throw failure;
            }, pool);
            java.util.concurrent.ExecutionException e2 = assertThrows(java.util.concurrent.ExecutionException.class,
                    () -> failed.get(5, TimeUnit.SECONDS));
            assertSame(failure, e2.getCause());
            assertEquals("ok", flight.submit("k", () -> "ok", pool).get(5, TimeUnit.SECONDS), "vacated after the Error");
        } finally {
            pool.shutdownNow();
        }
    }

    private static void awaitCallers(SingleFlight<?> flight, int n) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (flight.callers() < n) {
            assertTrue(System.nanoTime() < deadline, "callers never joined the flight");
            Thread.sleep(2);
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
