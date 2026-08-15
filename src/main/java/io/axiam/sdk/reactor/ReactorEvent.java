package io.axiam.sdk.reactor;

import com.fasterxml.jackson.databind.JsonNode;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * One hook firing, delivered to a reactor (CONTRACT.md &sect;22.3).
 *
 * <p>An instance only ever reaches a handler <em>after</em>
 * {@link ReactorServer} has rejected {@code key_version < 2}, verified the MAC,
 * checked freshness and checked the nonce, in that order. A runtime that hands
 * an unverified payload to user code has already lost, so this type is not
 * constructible from an unverified body outside this package.
 *
 * <p>The {@link #payload()} never carries a credential, a token or a signing
 * key: a reactor is told what is being decided, not handed the means to act on
 * it elsewhere. It is not sensitive in the &sect;7 sense and must remain readable
 * — a handler that cannot inspect the event cannot decide anything — but it is
 * tenant business data, so this SDK never logs it, and neither should you at
 * {@code info} level.
 */
public final class ReactorEvent {

    /**
     * Payload key under which the server inserts the accumulated patch from
     * earlier reactors in the chain (&sect;22.3).
     */
    public static final String REACTOR_PATCH_KEY = "_reactor_patch";

    private final UUID tenantId;
    private final String event;
    private final UUID correlationId;
    private final JsonNode payload;
    private final int timeoutMs;
    private final int keyVersion;
    private final UUID nonce;
    private final Instant issuedAt;
    private final Instant deadline;

    ReactorEvent(UUID tenantId, String event, UUID correlationId, JsonNode payload,
                 int timeoutMs, int keyVersion, UUID nonce, Instant issuedAt, Instant deadline) {
        this.tenantId = Objects.requireNonNull(tenantId, "tenantId");
        this.event = Objects.requireNonNull(event, "event");
        this.correlationId = Objects.requireNonNull(correlationId, "correlationId");
        this.payload = Objects.requireNonNull(payload, "payload");
        this.timeoutMs = timeoutMs;
        this.keyVersion = keyVersion;
        this.nonce = Objects.requireNonNull(nonce, "nonce");
        this.issuedAt = Objects.requireNonNull(issuedAt, "issuedAt");
        this.deadline = Objects.requireNonNull(deadline, "deadline");
    }

    /**
     * The tenant this event belongs to.
     *
     * @return the tenant id; always the tenant this runtime was configured for
     */
    public UUID tenantId() {
        return tenantId;
    }

    /**
     * The registry event name, e.g. {@code token.pre_issue}.
     *
     * @return the event name; also the second half of the routing key
     */
    public String event() {
        return event;
    }

    /**
     * The single-use handle for this dispatch.
     *
     * @return the correlation id, copied into the reply body by the runtime.
     *         Copying it only into the AMQP property produces a reply the server
     *         discards.
     */
    public UUID correlationId() {
        return correlationId;
    }

    /**
     * The event-specific body.
     *
     * @return the payload as an immutable-by-convention Jackson tree; never
     *         carries a credential, a token or a signing key
     */
    public JsonNode payload() {
        return payload;
    }

    /**
     * How long the server will actually wait for <em>this</em> dispatch.
     *
     * @return the window in milliseconds. It is inside the signed body, so it
     *         cannot be widened in transit.
     */
    public int timeoutMs() {
        return timeoutMs;
    }

    /**
     * The &sect;8 envelope version this event was signed under.
     *
     * @return the key version; always at least 2, because a lower one is refused
     *         before anything else about the message is considered
     */
    public int keyVersion() {
        return keyVersion;
    }

    /**
     * The per-message nonce, inside the signed bytes.
     *
     * @return the nonce; not a secret, and safe to log for correlation
     */
    public UUID nonce() {
        return nonce;
    }

    /**
     * When the server signed this event.
     *
     * @return the signing time, already checked to lie within the freshness window
     */
    public Instant issuedAt() {
        return issuedAt;
    }

    /**
     * When this dispatch's window closes.
     *
     * <p>Measured from the moment the delivery arrived plus {@link #timeoutMs()},
     * <em>not</em> from {@link #issuedAt()}: broker latency and clock skew both
     * sit between the two, and a deadline derived from a remote clock would read
     * as already-expired on a reactor whose clock runs slightly fast.
     *
     * @return the local instant after which a reply would be discarded anyway
     */
    public Instant deadline() {
        return deadline;
    }

    /**
     * How much of the window is left.
     *
     * @param now the current instant
     * @return the remaining time, or {@link Duration#ZERO} when the window has
     *         already closed. A handler doing expensive work SHOULD consult this
     *         and shed load rather than answer into a closed window.
     */
    public Duration remaining(Instant now) {
        Duration left = Duration.between(now, deadline);
        return left.isNegative() ? Duration.ZERO : left;
    }

    /**
     * The accumulated patch from earlier reactors in the chain (&sect;22.3).
     *
     * <p>When an earlier reactor returned a mutation, the server inserts the
     * merged patch into the payload under {@value #REACTOR_PATCH_KEY} before
     * dispatching here, so this reactor decides against the state that will
     * actually be committed.
     *
     * <p><strong>Read-only context.</strong> Echoing these keys back inside your
     * own patch is not how a field is preserved — the server merges, with later
     * priority winning a contested key.
     *
     * @return the prior patch, or an empty map when this is the first reactor in
     *         the chain (or the only one). Never {@code null}.
     */
    public Map<String, String> priorPatch() {
        JsonNode node = payload.get(REACTOR_PATCH_KEY);
        if (node == null || !node.isObject()) {
            return Map.of();
        }
        Map<String, String> merged = new LinkedHashMap<>();
        node.fields().forEachRemaining(entry -> {
            JsonNode value = entry.getValue();
            if (value != null && value.isTextual()) {
                merged.put(entry.getKey(), value.textValue());
            }
        });
        return Collections.unmodifiableMap(merged);
    }

    /**
     * The registry spec for {@link #event()}.
     *
     * @return the spec, or {@code null} for an event this SDK's registry does not
     *         know — which cannot happen for a server-dispatched event, since an
     *         unregistered event dispatches to nothing
     */
    public @Nullable ReactorEventSpec spec() {
        return ReactorEvents.spec(event);
    }

    /**
     * A short, secret-free description for logs.
     *
     * <p>Deliberately omits {@link #payload()}: the nonce and correlation id are
     * not secrets and may be logged for correlation, but the payload is tenant
     * business data.
     *
     * @return a one-line summary carrying no payload and no key material
     */
    @Override
    public String toString() {
        return "ReactorEvent[event=" + event + ", tenant=" + tenantId
                + ", correlation=" + correlationId + ", nonce=" + nonce
                + ", timeoutMs=" + timeoutMs + "]";
    }
}
