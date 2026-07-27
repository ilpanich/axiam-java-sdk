package io.axiam.sdk.internal;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.Callable;
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

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
