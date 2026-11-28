package io.axiam.sdk.amqp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.rabbitmq.client.CancelCallback;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import com.rabbitmq.client.Delivery;
import org.slf4j.Logger;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * AMQP event consumer: verify-before-handler HMAC gate plus the CONTRACT.md
 * &sect;8 ack/nack matrix, built on the RabbitMQ Java client's built-in
 * automatic recovery (D-13).
 *
 * <p>A consumer is configured with the <strong>one</strong> {@link EventType} it consumes and the tenant whose
 * subkey it verifies with (CONTRACT.md &sect;8 step 2c, contract 1.69; D-9). A body with another signed type's
 * layout is refused as {@code malformed} before the HMAC and never reaches the application; an application that
 * consumes both types runs two consumers. Every discard logs exactly one warning-level event carrying
 * {@code timestamp}, {@code exchange}, {@code routing_key}, the consumer's own {@code tenant_id} and a
 * {@code reason} from the closed vocabulary {@code malformed}, {@code unsigned}, {@code signature},
 * {@code key_version}, {@code stale}, {@code replay} (D-8, rule 4), and never a signature, nonce, key or body.
 *
 * <p>{@link #consume} NEVER hands an unverified delivery to the caller's
 * {@code handler} &mdash; {@link Hmac} verifies first, and the handler call
 * site is structurally unreachable until it has. The handler receives the
 * <em>verified canonical bytes</em> (the exact bytes the HMAC covered: compact
 * JSON in wire order with {@code hmac_signature} removed), never the received
 * body (C2); a body with a repeated key or trailing content is refused. The remaining outcomes follow the exact &sect;8 decision
 * matrix:
 *
 * <ul>
 *   <li>HMAC verification fails &rarr; {@code basicNack(tag, false, false)}
 *       (no requeue) + a security-event log entry that never contains the
 *       received or expected HMAC value; {@code handler} is never invoked.</li>
 *   <li>{@code handler} returns normally &rarr; {@code basicAck(tag, false)}.</li>
 *   <li>{@code handler} throws {@link ErrDrop} (poison message, 20-02) &rarr;
 *       {@code basicNack(tag, false, false)} (no requeue).</li>
 *   <li>{@code handler} throws any other exception (transient/retryable)
 *       &rarr; {@code basicNack(tag, false, true)} (requeue).</li>
 * </ul>
 *
 * <p>The RabbitMQ Java client's {@link ConnectionFactory} has automatic
 * connection + topology recovery ON by default since client 4.x &mdash; this
 * class does NOT hand-roll a reconnect loop (unlike {@code sdks/go}'s
 * {@code NotifyClose}-driven approach, which Java does not need). See
 * {@link #configureAutomaticRecovery(ConnectionFactory, Duration)} for the
 * documented, overridable recovery-interval helper (CF-03).
 */
public final class AmqpConsumer {

    /** Default QoS prefetch count (CF-03; matches {@code sdks/go}'s {@code defaultPrefetch=10}). */
    public static final int DEFAULT_PREFETCH = 10;

    /** Default network-recovery-interval applied by {@link #configureAutomaticRecovery(ConnectionFactory)}. */
    public static final Duration DEFAULT_NETWORK_RECOVERY_INTERVAL = Duration.ofSeconds(5);

    /**
     * Default NEW-4 issued-at clock-skew tolerance: a v2 message's
     * {@code issued_at} must fall within &plusmn; this duration of "now" or
     * it is rejected as stale. Overridable via
     * {@link #consume(Channel, String, EventType, String, byte[], Consumer, Logger, Duration)}.
     */
    public static final Duration DEFAULT_ALLOWED_CLOCK_SKEW = Duration.ofSeconds(300);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AmqpConsumer() {
    }

    /**
     * Registers a manual-ack {@link DeliverCallback} on {@code channel} for {@code queue}: every delivery is checked
     * against {@code type}'s layout and its HMAC-SHA256 signature verified (&sect;8) BEFORE {@code handler} is
     * invoked, then the &sect;8 ack/nack matrix (see class Javadoc) is applied. Sets
     * {@code basicQos(DEFAULT_PREFETCH)} (CF-03).
     *
     * <p>This method does not itself configure automatic recovery on the underlying connection &mdash; call
     * {@link #configureAutomaticRecovery(ConnectionFactory, Duration)} on the {@link ConnectionFactory} used to
     * create {@code channel}'s connection before opening it.
     *
     * @param channel    the AMQP channel to consume on; the caller owns its lifecycle (creation/closing)
     * @param queue      the queue name to consume from
     * @param type       the ONE signed event type this consumer consumes (contract 1.69, D-9)
     * @param tenantId   the consumer's own tenant, the one whose subkey {@code signingKey} is; it is what every
     *                   discard event reports as {@code tenant_id} (never a value read from a body)
     * @param signingKey the per-tenant AMQP HMAC signing secret (&sect;8.1 &mdash; obtain from the AXIAM
     *                   management API; never hardcode)
     * @param handler    invoked ONLY after the layout check, the HMAC verification AND the NEW-4 checks
     *                   (key_version, issued_at freshness, nonce uniqueness) succeed
     * @param logger     receives the one &sect;8 rule 4 discard event per discarded delivery
     * @throws IOException if {@code basicQos}/{@code basicConsume} fails
     */
    public static void consume(Channel channel, String queue, EventType type, String tenantId, byte[] signingKey,
                                Consumer<byte[]> handler, Logger logger) throws IOException {
        consume(channel, queue, type, tenantId, signingKey, handler, logger, DEFAULT_ALLOWED_CLOCK_SKEW);
    }

    /**
     * Overload of {@link #consume(Channel, String, EventType, String, byte[], Consumer, Logger)} with a
     * caller-supplied NEW-4 issued-at clock-skew tolerance in place of {@link #DEFAULT_ALLOWED_CLOCK_SKEW}. A
     * single {@link NonceStore} (TTL = {@code 2 * allowedClockSkew}) is created for this registration and shared
     * across every delivery it handles, so nonce replay is detected across the lifetime of the consumer.
     *
     * @param channel          the AMQP channel to consume on
     * @param queue            the queue name to consume from
     * @param type             the ONE signed event type this consumer consumes
     * @param tenantId         the consumer's own tenant, reported in every discard event
     * @param signingKey       the per-tenant AMQP HMAC signing secret
     * @param handler          invoked only after every check passes
     * @param logger           receives the discard events
     * @param allowedClockSkew the &plusmn; tolerance applied to a message's {@code issued_at} versus wall-clock
     *                         now; must be positive
     * @throws IOException if {@code basicQos}/{@code basicConsume} fails
     */
    public static void consume(Channel channel, String queue, EventType type, String tenantId, byte[] signingKey,
                                Consumer<byte[]> handler, Logger logger,
                                Duration allowedClockSkew) throws IOException {
        channel.basicQos(DEFAULT_PREFETCH);
        NonceStore nonceStore = new NonceStore(allowedClockSkew.multipliedBy(2));
        DeliverCallback deliverCallback = deliverCallback(
                channel, type, tenantId, signingKey, handler, logger, allowedClockSkew, Clock.systemUTC(),
                nonceStore, queue);
        CancelCallback cancelCallback = consumerTag -> {
            // No cancellation-specific handling required; the caller manages
            // channel/connection lifecycle.
        };
        channel.basicConsume(queue, false /* manual ack (D-13) */, deliverCallback, cancelCallback);
    }

    /**
     * Builds the &sect;8 verify-before-handler / ack-nack-matrix {@link DeliverCallback} bound to
     * {@code channel}, using {@link #DEFAULT_ALLOWED_CLOCK_SKEW}, the system clock, and a freshly-created
     * {@link NonceStore}. Package-private so tests can drive it with synthesized {@link Delivery} instances and a
     * fake {@link Channel}, without a live broker.
     */
    static DeliverCallback deliverCallback(Channel channel, EventType type, String tenantId, byte[] signingKey,
                                            Consumer<byte[]> handler, Logger logger) {
        return deliverCallback(channel, type, tenantId, signingKey, handler, logger, DEFAULT_ALLOWED_CLOCK_SKEW,
                Clock.systemUTC(), new NonceStore(DEFAULT_ALLOWED_CLOCK_SKEW.multipliedBy(2)));
    }

    /** As the full form, with the routing key exactly as the broker reported it. */
    static DeliverCallback deliverCallback(Channel channel, EventType type, String tenantId, byte[] signingKey,
                                            Consumer<byte[]> handler, Logger logger,
                                            Duration allowedClockSkew, Clock clock, NonceStore nonceStore) {
        return deliverCallback(channel, type, tenantId, signingKey, handler, logger, allowedClockSkew, clock,
                nonceStore, null);
    }

    /**
     * Full-control form: the NEW-4 clock-skew tolerance, {@link Clock} (deterministic freshness tests) and
     * {@link NonceStore} (shared across deliveries so replay is detected for the consumer's lifetime).
     * {@code queue}, when non-null, stands in for a routing key the broker did not report.
     *
     * <p>Per delivery, the reason of a discard is the first that applies (CONTRACT.md &sect;8 rule 4):
     * (1) not one JSON object, a byte-order mark included &rarr; {@code malformed}; (2) no top-level
     * {@code hmac_signature} &rarr; {@code unsigned}; (3) a repeated member, a signature that is not the trailing
     * 64-hex member, or a layout that is not {@code type}'s &rarr; {@code malformed}, before the HMAC;
     * (4) the HMAC fails &rarr; {@code signature}; (5) the verified bytes do not decode as {@code type}
     * &rarr; {@code malformed}; (6) {@code key_version < 2} &rarr; {@code key_version}; (7) {@code issued_at}
     * outside &plusmn;{@code allowedClockSkew} &rarr; {@code stale}; (8) a nonce already seen &rarr;
     * {@code replay}. The nonce is recorded only once every gate has passed. A discard is a nack without
     * requeue and one warning event; the handler is never invoked. No body, however malformed, can make the
     * callback throw.
     */
    static DeliverCallback deliverCallback(Channel channel, EventType type, String tenantId, byte[] signingKey,
                                            Consumer<byte[]> handler, Logger logger,
                                            Duration allowedClockSkew, Clock clock, NonceStore nonceStore,
                                            String queue) {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(tenantId, "tenantId");
        return (consumerTag, delivery) -> {
            long deliveryTag = delivery.getEnvelope().getDeliveryTag();
            // C2: `verified` is the exact byte sequence the HMAC covered. Everything past this
            // point reads it and never the received body.
            Hmac.Reason reason;
            byte[] verified = null;
            try {
                Hmac.Inspection inspection = Hmac.inspect(signingKey, delivery.getBody(), type);
                reason = inspection.reason();
                verified = inspection.canonical();
                if (reason == null) {
                    reason = gates(verified, type, allowedClockSkew, clock, nonceStore);
                }
            } catch (RuntimeException unforeseen) {
                reason = Hmac.Reason.MALFORMED; // default-deny; nothing escapes the delivery loop
            }

            if (reason != null) {
                String routingKey = delivery.getEnvelope().getRoutingKey();
                if (routingKey == null && queue != null) { // "" is a valid routing key: never replaced
                    routingKey = queue;
                }
                // §8 rule 4 event: exactly these five members, tenant_id the consumer's own. Never a
                // signature, a nonce, a key or any part of the body.
                logger.warn(
                        "axiam_sdk_security: AMQP event discarded; nacking without requeue "
                                + "(timestamp={}, exchange={}, routing_key={}, tenant_id={}, reason={})",
                        clock.instant(), delivery.getEnvelope().getExchange(), routingKey, tenantId,
                        reason.wire());
                channel.basicNack(deliveryTag, false, false); // multiple=false, requeue=false
                return; // handler is structurally unreachable for a discarded message
            }

            try {
                handler.accept(verified); // handler NEVER sees an unverified/replayed message
                channel.basicAck(deliveryTag, false);
            } catch (ErrDrop drop) {
                channel.basicNack(deliveryTag, false, false); // poison message, no requeue
            } catch (Exception transientFailure) {
                channel.basicNack(deliveryTag, false, true); // retryable, requeue
            }
        };
    }

    private static final Pattern UUID_FORM = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    /**
     * Rule 4 positions (5) to (8) over the verified canonical bytes: decode into {@code type}, then the v2 gates.
     * Returns {@code null} when the message passes (and its nonce is now recorded), else the reason. Never throws.
     */
    private static Hmac.Reason gates(byte[] canonical, EventType type, Duration allowedClockSkew, Clock clock,
                                      NonceStore nonceStore) {
        try {
            JsonNode root = MAPPER.readTree(canonical);
            if (!(root instanceof ObjectNode node)) {
                return Hmac.Reason.MALFORMED;
            }
            // (5) Decode: every member present has its declared JSON type.
            for (EventType.Member member : type.members()) {
                JsonNode value = node.get(member.name());
                if (value == null) {
                    continue; // absent: the layout check already required it where it is required
                }
                if (value.isNull() && member.optional()) {
                    continue;
                }
                boolean ok = switch (member.kind()) {
                    case UUID -> value.isTextual() && UUID_FORM.matcher(value.asText()).matches();
                    case STRING -> value.isTextual();
                    case INT -> value.isIntegralNumber() && value.canConvertToInt();
                    case OBJECT -> value.isObject();
                    case TIMESTAMP -> {
                        try {
                            yield value.isTextual() && OffsetDateTime.parse(value.asText()) != null;
                        } catch (DateTimeParseException e) {
                            yield false;
                        }
                    }
                };
                if (!ok) {
                    return Hmac.Reason.MALFORMED;
                }
            }
            // (6) key_version below 2.
            if (node.get("key_version").asInt() < 2) {
                return Hmac.Reason.KEY_VERSION;
            }
            // (7) issued_at outside the freshness window.
            Instant issuedAt = OffsetDateTime.parse(node.get("issued_at").asText()).toInstant();
            Instant now = clock.instant();
            if (Duration.between(issuedAt, now).abs().compareTo(allowedClockSkew) > 0) {
                return Hmac.Reason.STALE;
            }
            // (8) the nonce was already seen; recorded only here, after the decode and every gate passed.
            if (!nonceStore.observe(node.get("nonce").asText(), now)) {
                return Hmac.Reason.REPLAY;
            }
            return null;
        } catch (Exception e) {
            return Hmac.Reason.MALFORMED;
        }
    }

    /**
     * Applies the SDK's documented automatic-recovery defaults to
     * {@code factory}: {@code setAutomaticRecoveryEnabled(true)} (left ON
     * &mdash; the client default since 4.x) and
     * {@code setNetworkRecoveryInterval(recoveryInterval)} (overridable per
     * CF-03's "sane defaults, overridable"). This SDK MUST NOT disable
     * automatic recovery (D-13).
     *
     * @param factory          the {@link ConnectionFactory} to configure,
     *                         before {@link ConnectionFactory#newConnection()}
     *                         is called
     * @param recoveryInterval the reconnect backoff interval; must be positive
     */
    public static void configureAutomaticRecovery(ConnectionFactory factory, Duration recoveryInterval) {
        factory.setAutomaticRecoveryEnabled(true);
        factory.setNetworkRecoveryInterval(recoveryInterval.toMillis());
    }

    /**
     * Convenience overload applying {@link #DEFAULT_NETWORK_RECOVERY_INTERVAL}
     * (~5s, CF-03).
     *
     * @param factory the {@link ConnectionFactory} to configure
     */
    public static void configureAutomaticRecovery(ConnectionFactory factory) {
        configureAutomaticRecovery(factory, DEFAULT_NETWORK_RECOVERY_INTERVAL);
    }
}
