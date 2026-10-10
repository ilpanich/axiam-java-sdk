package io.axiam.sdk.ssf;

import java.time.Duration;

/**
 * Remembers the {@code jti}s already accepted, for step 9 of
 * {@link SsfReceiver#verifySet(String)}.
 *
 * <p>Pluggable so a receiver running several instances can share one store
 * (CONTRACT.md &sect;32.7). {@link MemoryReplayStore} is the default.
 */
@FunctionalInterface
public interface ReplayStore {

    /**
     * Records {@code jti} for {@code window} and returns {@code true}, or returns
     * {@code false} without recording when it is already held. Must be atomic:
     * two concurrent calls with one {@code jti} must not both see {@code true}.
     *
     * <p><strong>There is a third answer: "cannot answer".</strong> A store that cannot say
     * whether it has seen {@code jti} (its backing service is down, a timeout, a lost
     * connection) <em>throws</em>, and must never return {@code false} to be safe: {@code false}
     * means {@code replayed}, which {@link SsfReceiver#poll(String, SsfPollOptions)} tells the
     * caller to acknowledge, so an event that was never processed would be lost (CONTRACT.md
     * &sect;34.2 P4, contract 1.60). Any {@link RuntimeException} is read as "cannot answer":
     * the SET gets no verdict, is not recorded, is neither refused nor acknowledged, and the
     * receiver raises {@link io.axiam.sdk.errors.NetworkError} (a poll stops at that SET and
     * lists the rest in {@link SsfPollResult#unjudged()} if it had already judged one).
     * Nothing is ever accepted on a store failure.
     *
     * @param jti    the SET's unique id
     * @param window how long to remember it
     * @return {@code true} the first time, {@code false} for a replay
     * @throws RuntimeException when the store cannot answer
     */
    boolean checkAndRecord(String jti, Duration window);
}
