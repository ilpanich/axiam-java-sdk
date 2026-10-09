package io.axiam.sdk.ssf;

import java.util.List;

/**
 * What {@link SsfReceiver#poll(String, SsfPollOptions)} returns.
 *
 * @param events        the SETs that verified, in the order the transmitter listed them
 * @param moreAvailable whether the transmitter holds more
 * @param refused       the SETs that did not verify
 * @param unjudged      the keys of the SETs the helper could not judge because the replay
 *                      store could not answer part-way through the batch (CONTRACT.md
 *                      &sect;34.2 P1, P3): their {@code jti}s are <strong>not</strong>
 *                      recorded, so neither acknowledge nor refuse them &mdash; the
 *                      transmitter offers them again. Empty on every other poll.
 */
public record SsfPollResult(List<SecurityEvent> events, boolean moreAvailable, List<RefusedSet> refused,
                            List<String> unjudged) {

    /**
     * Copies every list.
     *
     * @param events        the verified SETs
     * @param moreAvailable whether the transmitter holds more
     * @param refused       the refused SETs
     * @param unjudged      the keys of the SETs left unjudged and unrecorded
     */
    public SsfPollResult {
        events = List.copyOf(events);
        refused = List.copyOf(refused);
        unjudged = List.copyOf(unjudged);
    }

    /**
     * A result with nothing left unjudged &mdash; the shape of every poll before
     * contract 1.59.
     *
     * @param events        the verified SETs
     * @param moreAvailable whether the transmitter holds more
     * @param refused       the refused SETs
     */
    public SsfPollResult(List<SecurityEvent> events, boolean moreAvailable, List<RefusedSet> refused) {
        this(events, moreAvailable, refused, List.of());
    }
}
