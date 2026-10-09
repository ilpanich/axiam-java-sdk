package io.axiam.sdk.ssf;

import com.fasterxml.jackson.databind.JsonNode;

import org.jspecify.annotations.Nullable;

/**
 * A verified Security Event Token (CONTRACT.md &sect;32.7's result).
 *
 * @param jti       the SET's unique id
 * @param iat       when it was issued, seconds since the epoch
 * @param iss       the issuer, equal to the configured one
 * @param aud       the audience as sent: one string, or an array containing yours
 * @param txn       the transaction id shared by every SET one operation produced, or {@code null}
 * @param eventType the single {@code events} key &mdash; an event-type URI, see {@link SsfEventTypes}
 * @param event     that event's object, opaque to the helper
 * @param subId     the RFC 9493 subject identifier, opaque to the helper
 */
public record SecurityEvent(
        String jti,
        long iat,
        String iss,
        JsonNode aud,
        @Nullable String txn,
        String eventType,
        JsonNode event,
        JsonNode subId) {
}
