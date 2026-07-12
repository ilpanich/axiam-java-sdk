package io.axiam.sdk.amqp;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit coverage for {@link NonceStore}'s constructor validation, freshness /
 * replay semantics, TTL expiry, and the bounded/opportunistic pruning path
 * (NEW-4). No broker or clock dependency — an explicit {@link Instant} "now"
 * is supplied to {@link NonceStore#observe} on every call.
 */
class NonceStoreTest {

    private static final Instant NOW = Instant.parse("2026-07-10T12:00:00Z");

    @Test
    void rejectsNonPositiveTtl() {
        assertThrows(IllegalArgumentException.class, () -> new NonceStore(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new NonceStore(Duration.ofSeconds(-1)));
    }

    @Test
    void rejectsNonPositiveMaxTrackedNonces() {
        assertThrows(IllegalArgumentException.class, () -> new NonceStore(Duration.ofSeconds(60), 0));
        assertThrows(IllegalArgumentException.class, () -> new NonceStore(Duration.ofSeconds(60), -5));
    }

    @Test
    void firstSightingIsFreshAndRepeatIsReplay() {
        NonceStore store = new NonceStore(Duration.ofSeconds(600));

        assertTrue(store.observe("nonce-a", NOW), "first sighting must be reported fresh");
        assertFalse(store.observe("nonce-a", NOW), "an unexpired second sighting must be reported as a replay");
        assertEquals(1, store.size(), "a single distinct nonce should occupy exactly one slot");
    }

    @Test
    void distinctNoncesAreEachFresh() {
        NonceStore store = new NonceStore(Duration.ofSeconds(600));

        assertTrue(store.observe("nonce-a", NOW));
        assertTrue(store.observe("nonce-b", NOW));
        assertEquals(2, store.size());
    }

    @Test
    void anExpiredNonceMayBeObservedAgainAsFresh() {
        NonceStore store = new NonceStore(Duration.ofSeconds(60));

        assertTrue(store.observe("nonce-a", NOW), "first sighting fresh");
        // Well past the 60s TTL: the prior entry has expired, so the same
        // nonce is fresh again (and the prune has room to reclaim it).
        Instant later = NOW.plus(Duration.ofSeconds(3_600));
        assertTrue(store.observe("nonce-a", later), "after TTL elapses the same nonce is fresh again");
    }

    @Test
    void overCapacityTriggersPruneOfExpiredEntries() {
        // Cap of 1 forces the opportunistic prune on the very next observe once
        // an entry is present; supplying a "now" past the first entry's TTL
        // makes that entry eligible for removal (exercising the removeIf path).
        NonceStore store = new NonceStore(Duration.ofSeconds(60), 1);

        assertTrue(store.observe("nonce-old", NOW));
        assertEquals(1, store.size());

        Instant later = NOW.plus(Duration.ofSeconds(3_600));
        assertTrue(store.observe("nonce-new", later), "a brand-new nonce is fresh");
        // The expired "nonce-old" should have been pruned, keeping the store bounded.
        assertEquals(1, store.size(), "over-capacity prune should evict the expired entry");
    }
}
