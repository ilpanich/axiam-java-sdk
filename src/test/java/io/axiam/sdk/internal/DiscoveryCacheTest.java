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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12.3 rule 6: the OIDC discovery cache is TTL-floored,
 * per-key isolated, and single-flight under concurrent callers for the SAME
 * key.
 */
class DiscoveryCacheTest {

    @Test
    void cachesAValueUntilTtlExpires() throws InterruptedException {
        DiscoveryCache<String> cache = new DiscoveryCache<>(50, 0);
        AtomicInteger fetches = new AtomicInteger(0);

        String first = cache.get("origin-a", () -> {
            fetches.incrementAndGet();
            return "doc-v" + fetches.get();
        });
        String second = cache.get("origin-a", () -> {
            fetches.incrementAndGet();
            return "doc-v" + fetches.get();
        });

        assertEquals("doc-v1", first);
        assertEquals("doc-v1", second, "a fresh cache entry must not re-fetch");
        assertEquals(1, fetches.get());

        Thread.sleep(120);

        String third = cache.get("origin-a", () -> {
            fetches.incrementAndGet();
            return "doc-v" + fetches.get();
        });
        assertEquals("doc-v2", third, "an expired entry must be re-fetched");
    }

    @Test
    void ttlIsFlooredAtTheConfiguredMinimum() throws InterruptedException {
        DiscoveryCache<String> cache = new DiscoveryCache<>(1, 200);
        AtomicInteger fetches = new AtomicInteger(0);

        cache.get("origin-a", () -> {
            fetches.incrementAndGet();
            return "doc";
        });
        Thread.sleep(50);
        cache.get("origin-a", () -> {
            fetches.incrementAndGet();
            return "doc";
        });

        assertEquals(1, fetches.get(), "a TTL below the floor must be raised to it");
    }

    @Test
    void differentKeysAreCachedIndependently() {
        DiscoveryCache<String> cache = new DiscoveryCache<>(60_000, 0);

        String a = cache.get("origin-a", () -> "doc-a");
        String b = cache.get("origin-b", () -> "doc-b");

        assertEquals("doc-a", a);
        assertEquals("doc-b", b);
    }

    @Test
    void concurrentCallersForTheSameKeyTriggerExactlyOneFetch() throws Exception {
        DiscoveryCache<String> cache = new DiscoveryCache<>(60_000, 0);
        AtomicInteger fetches = new AtomicInteger(0);

        int threadCount = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startBarrier = new CountDownLatch(1);
        try {
            List<Callable<String>> tasks = new java.util.ArrayList<>();
            for (int i = 0; i < threadCount; i++) {
                tasks.add(() -> {
                    startBarrier.await();
                    return cache.get("origin-a", () -> {
                        fetches.incrementAndGet();
                        sleepQuietly(50);
                        return "doc";
                    });
                });
            }
            List<Future<String>> futures = new java.util.ArrayList<>();
            for (Callable<String> task : tasks) {
                futures.add(pool.submit(task));
            }
            startBarrier.countDown();
            for (Future<String> future : futures) {
                assertEquals("doc", future.get(5, TimeUnit.SECONDS));
            }
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }

        assertEquals(1, fetches.get(), "expected exactly one fetch for a concurrent burst on the same key");
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
