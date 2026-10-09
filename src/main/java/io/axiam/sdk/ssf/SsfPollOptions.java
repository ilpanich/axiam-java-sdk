package io.axiam.sdk.ssf;

import org.jspecify.annotations.Nullable;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Arguments to {@link SsfReceiver#poll(String, SsfPollOptions)}. Every member is
 * passed through exactly as given; an unset one is not sent.
 *
 * @param maxEvents         {@code maxEvents} &mdash; the server clamps it to 100; {@code 0} acknowledges and returns nothing
 * @param returnImmediately {@code returnImmediately} &mdash; without it the server long-polls up to 30 s
 * @param ack               {@code ack} &mdash; the {@code jti}s you <strong>processed</strong> since the last poll
 * @param setErrs           {@code setErrs} &mdash; the {@code jti}s you refuse, each with its code
 */
public record SsfPollOptions(
        @Nullable Integer maxEvents,
        @Nullable Boolean returnImmediately,
        @Nullable List<String> ack,
        @Nullable Map<String, SetErr> setErrs) {

    /**
     * Copies the collections, keeping {@code setErrs}' order.
     *
     * @param maxEvents         {@code maxEvents}
     * @param returnImmediately {@code returnImmediately}
     * @param ack               {@code ack}
     * @param setErrs           {@code setErrs}
     */
    public SsfPollOptions {
        ack = ack == null ? null : List.copyOf(ack);
        setErrs = setErrs == null ? null : java.util.Collections.unmodifiableMap(new LinkedHashMap<>(setErrs));
    }

    /**
     * A poll with nothing set: the body is {@code {}}, and nothing is acknowledged.
     *
     * @return the empty options
     */
    public static SsfPollOptions none() {
        return new SsfPollOptions(null, null, null, null);
    }
}
