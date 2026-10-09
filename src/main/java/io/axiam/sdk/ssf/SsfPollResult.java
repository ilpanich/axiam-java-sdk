package io.axiam.sdk.ssf;

import java.util.List;

/**
 * What {@link SsfReceiver#poll(String, SsfPollOptions)} returns.
 *
 * @param events        the SETs that verified, in the order the transmitter listed them
 * @param moreAvailable whether the transmitter holds more
 * @param refused       the SETs that did not verify
 */
public record SsfPollResult(List<SecurityEvent> events, boolean moreAvailable, List<RefusedSet> refused) {

    /**
     * Copies both lists.
     *
     * @param events        the verified SETs
     * @param moreAvailable whether the transmitter holds more
     * @param refused       the refused SETs
     */
    public SsfPollResult {
        events = List.copyOf(events);
        refused = List.copyOf(refused);
    }
}
