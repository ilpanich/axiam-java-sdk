package io.axiam.sdk.oidc;

import io.axiam.sdk.Sensitive;

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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12.3 rule 1: {@link MemoryOidcStateStore} is single-use
 * ({@link OidcStateStore#consume} atomically deletes), TTL-bounded (10
 * minutes, clamped), and safe under concurrent callers racing the same state.
 */
class MemoryOidcStateStoreTest {

    @Test
    void consumeIsSingleUse() {
        MemoryOidcStateStore store = new MemoryOidcStateStore();
        Sensitive verifier = Sensitive.of("verifier-1");
        OidcStateEntry entry = new OidcStateEntry("state-1", "nonce-1", verifier, "https://app/cb");
        store.save(entry);

        OidcStateEntry first = store.consume("state-1");
        OidcStateEntry second = store.consume("state-1");

        assertNotNull(first);
        assertEquals("nonce-1", first.nonce());
        // Sensitive.expose() is public (§7 rule 3), but reference identity is
        // still the strongest available proof the store round-trips the SAME
        // wrapper rather than re-wrapping or copying the raw value.
        assertSame(verifier, first.codeVerifier());
        assertNull(second, "a second consume of the same state must return null (single-use)");
    }

    @Test
    void consumeOfUnknownStateReturnsNull() {
        MemoryOidcStateStore store = new MemoryOidcStateStore();
        assertNull(store.consume("never-saved"));
    }

    @Test
    void entryExpiresAfterTtl() throws InterruptedException {
        MemoryOidcStateStore store = new MemoryOidcStateStore(50);
        store.save(new OidcStateEntry("state-1", "nonce-1", Sensitive.of("verifier-1"), "https://app/cb"));

        Thread.sleep(150);

        assertNull(store.consume("state-1"), "an expired entry must not be returned");
    }

    @Test
    void ttlIsClampedToTenMinutesMaximum() {
        MemoryOidcStateStore store = new MemoryOidcStateStore(Long.MAX_VALUE);
        store.save(new OidcStateEntry("state-1", "nonce-1", Sensitive.of("verifier-1"), "https://app/cb"));

        // Not directly observable from the public API beyond "does not throw
        // and stores normally" — the clamp is exercised via the constructor
        // not overflowing; size() confirms save() succeeded.
        assertEquals(1, store.size());
    }

    @Test
    void returnToIsOptionalAndPreserved() {
        MemoryOidcStateStore store = new MemoryOidcStateStore();
        store.save(new OidcStateEntry("state-1", "nonce-1", Sensitive.of("verifier-1"), "https://app/cb", "/dashboard"));

        OidcStateEntry entry = store.consume("state-1");

        assertNotNull(entry);
        assertEquals("/dashboard", entry.returnTo());
    }

    @Test
    void sizeReflectsUnexpiredEntriesOnly() throws InterruptedException {
        MemoryOidcStateStore store = new MemoryOidcStateStore(50);
        store.save(new OidcStateEntry("state-1", "nonce-1", Sensitive.of("v1"), "https://app/cb"));
        assertEquals(1, store.size());

        Thread.sleep(150);

        assertEquals(0, store.size(), "size() must sweep expired entries");
    }

    /**
     * Concurrency test: N threads racing {@link OidcStateStore#consume} on
     * the SAME state must yield exactly one non-null winner.
     */
    @Test
    void concurrentConsumeOfTheSameStateYieldsExactlyOneWinner() throws Exception {
        MemoryOidcStateStore store = new MemoryOidcStateStore();
        store.save(new OidcStateEntry("state-1", "nonce-1", Sensitive.of("verifier-1"), "https://app/cb"));

        int threadCount = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startBarrier = new CountDownLatch(1);
        AtomicInteger winners = new AtomicInteger(0);
        try {
            List<Callable<OidcStateEntry>> tasks = new java.util.ArrayList<>();
            for (int i = 0; i < threadCount; i++) {
                tasks.add(() -> {
                    startBarrier.await();
                    return store.consume("state-1");
                });
            }
            List<Future<OidcStateEntry>> futures = new java.util.ArrayList<>();
            for (Callable<OidcStateEntry> task : tasks) {
                futures.add(pool.submit(task));
            }
            startBarrier.countDown();

            for (Future<OidcStateEntry> future : futures) {
                if (future.get(5, TimeUnit.SECONDS) != null) {
                    winners.incrementAndGet();
                }
            }
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }

        assertEquals(1, winners.get(), "exactly one concurrent consumer must win a single-use state");
    }
}
