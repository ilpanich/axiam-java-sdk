package io.axiam.sdk.reactor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.CancelCallback;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DeliverCallback;
import com.rabbitmq.client.Delivery;
import io.axiam.sdk.amqp.NonceStore;
import io.axiam.sdk.telemetry.TelemetryEvent;
import io.axiam.sdk.telemetry.TelemetryHook;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The &sect;22 reactor runtime: consume the server-declared queue, verify, decide,
 * sign, reply.
 *
 * <p>Start one with {@link #reactorServe(ReactorServeOptions)}. Per delivery it:
 *
 * <ol>
 *   <li>rejects {@code key_version < 2} — before the signature is even
 *       computed;</li>
 *   <li>verifies the HMAC over the canonical bytes (&sect;22.2:
 *       {@code hmac_signature} present and {@code null});</li>
 *   <li>checks {@code issued_at} against the freshness window, in both
 *       directions;</li>
 *   <li>checks {@code nonce} against a seen-set;</li>
 *   <li><em>then</em> decodes the payload and calls the handler;</li>
 *   <li>signs the reply with the same tenant subkey and publishes it to the
 *       delivery's {@code reply_to} queue, echoing {@code correlation_id} both as
 *       an AMQP property and — the one the server authenticates — inside the
 *       signed body.</li>
 * </ol>
 *
 * <p>A runtime that hands an unverified payload to user code has already lost:
 * the handler will act on it, and "we checked afterwards" is not a check. The
 * handler call site here is structurally unreachable until every gate above has
 * passed.
 *
 * <h2>Four rules this class holds to</h2>
 *
 * <ol>
 *   <li><strong>It declares no topology.</strong> No {@code exchangeDeclare}, no
 *       {@code queueDeclare}, no {@code queueBind}, anywhere — asserted by a test
 *       against the AMQP client's own declare calls. Actors consume; the server
 *       declares.</li>
 *   <li><strong>It fails closed on its own errors.</strong> A handler that
 *       throws, or a body it cannot decode, produces <em>no reply</em> — never a
 *       synthesized {@code allow}. Answering {@code allow} on behalf of a handler
 *       that crashed would override the operator's {@code fail_closed} setting
 *       from inside the library.</li>
 *   <li><strong>It does not filter a patch.</strong> A handler's patch goes on
 *       the wire exactly as returned, forbidden keys included.</li>
 *   <li><strong>It honours {@code timeout_ms}.</strong> When the handler returns
 *       after the window closed, the reply is abandoned rather than published
 *       late — the server has already stopped listening.</li>
 * </ol>
 *
 * <h2>Interaction with &sect;16, &sect;18 and &sect;19</h2>
 *
 * <p><strong>&sect;16 does not apply to a reply.</strong> A correlation is
 * single-use and a late reply is discarded, so re-sending one could only add load
 * to a server that has already moved on. The recovery mechanism for an
 * unanswered dispatch is the registration's {@code failure_policy}, on the
 * server, not a retry here. Connection recovery is the RabbitMQ client's, left on
 * exactly as {@code AmqpConsumer} leaves it.
 *
 * <p><strong>&sect;18:</strong> {@link #close()} is idempotent, cancels the
 * consumer so no new delivery starts, drains what is in flight up to the
 * configured grace period, and makes every later call throw rather than silently
 * reconnect.
 *
 * <p><strong>&sect;19:</strong> one {@code RequestStart}/{@code RequestEnd} pair
 * per dispatched event, with the event name as the path template — a closed set
 * of five values, so it cannot become a cardinality bomb.
 */
public final class ReactorServer implements AutoCloseable {

    /** The &sect;19 operation name every reactor telemetry event carries. */
    public static final String TELEMETRY_OPERATION = "reactorServe";

    /** The &sect;19 "method" label for an AMQP dispatch. */
    public static final String TELEMETRY_METHOD = "AMQP";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final ReactorServeOptions options;
    private final byte[] signingKey;
    private final NonceStore nonceStore;
    private final AtomicInteger inFlight = new AtomicInteger();
    private final Object drainLock = new Object();

    private volatile boolean closed;
    private volatile @Nullable String consumerTag;

    private ReactorServer(ReactorServeOptions options) {
        this.options = options;
        this.signingKey = options.signingKey();
        this.nonceStore = new NonceStore(options.freshnessSkew().multipliedBy(2));
    }

    /**
     * Starts serving reactor events (CONTRACT.md &sect;22.10).
     *
     * <p>Applies the configured QoS prefetch and registers a manual-ack consumer
     * on the <strong>server-declared</strong> queue. Nothing is declared and
     * nothing is bound.
     *
     * @param options the configuration; see
     *                {@link ReactorServeOptions#builder(Channel, UUID, io.axiam.sdk.Sensitive)}
     * @return a running server; close it to stop, ideally with try-with-resources
     * @throws IOException when {@code basicQos} or {@code basicConsume} fails
     */
    public static ReactorServer reactorServe(ReactorServeOptions options) throws IOException {
        ReactorServer server = new ReactorServer(options);
        Channel channel = options.channel();
        channel.basicQos(options.prefetch());
        DeliverCallback deliver = server.deliverCallback();
        CancelCallback cancel = tag -> {
            // The broker cancelled us (queue deleted, or the registration was
            // removed). Nothing to do: the caller owns the channel, and a
            // runtime that re-declared the queue here would be doing exactly
            // what §22.1 forbids.
        };
        server.consumerTag = channel.basicConsume(options.queue(), false, deliver, cancel);
        return server;
    }

    /**
     * The queue this runtime consumes.
     *
     * @return the server-declared queue name
     */
    public String queue() {
        return options.queue();
    }

    /**
     * How many events are being handled right now.
     *
     * @return the in-flight count; drains to zero during {@link #close()}
     */
    public int inFlight() {
        return inFlight.get();
    }

    /**
     * Whether {@link #close()} has run.
     *
     * @return {@code true} once this server has been closed
     */
    public boolean isClosed() {
        return closed;
    }

    /**
     * Stops serving, deterministically (&sect;18).
     *
     * <p>Cancels the consumer first so no new delivery can start, then waits for
     * in-flight handlers up to {@link ReactorServeOptions#shutdownGrace()}.
     * Idempotent: a concurrent double-close does the work once. It does not close
     * the channel or the connection — the caller owns those, exactly as
     * {@code AmqpConsumer} leaves them.
     */
    @Override
    public void close() {
        synchronized (drainLock) {
            if (closed) {
                return;
            }
            closed = true;
        }

        String tag = consumerTag;
        if (tag != null) {
            try {
                options.channel().basicCancel(tag);
            } catch (IOException | RuntimeException e) {
                // A channel already torn down by the broker cannot be cancelled,
                // and failing close() over that would turn a clean shutdown into
                // an exception on the way out.
                options.logger().debug("axiam_sdk_reactor: consumer cancel failed during close ({})",
                        e.getClass().getSimpleName());
            }
        }

        // Wall-clock via nanoTime, deliberately not the configured Clock: a test
        // pinning the clock to a fixed instant must not turn the drain into an
        // unbounded wait.
        long deadlineNanos = System.nanoTime() + options.shutdownGrace().toNanos();
        synchronized (drainLock) {
            while (inFlight.get() > 0 && System.nanoTime() < deadlineNanos) {
                try {
                    drainLock.wait(20);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }

    /**
     * The &sect;22 delivery pipeline, bound to this server.
     *
     * <p>Package-private so tests can invoke it against synthesized deliveries
     * and a fake {@link Channel} — every branch below is provable without a live
     * broker.
     *
     * @return the callback registered with {@code basicConsume}
     */
    DeliverCallback deliverCallback() {
        return (tag, delivery) -> {
            inFlight.incrementAndGet();
            try {
                handleDelivery(delivery);
            } finally {
                inFlight.decrementAndGet();
                synchronized (drainLock) {
                    drainLock.notifyAll();
                }
            }
        };
    }

    private void handleDelivery(Delivery delivery) throws IOException {
        Channel channel = options.channel();
        long deliveryTag = delivery.getEnvelope().getDeliveryTag();
        byte[] body = delivery.getBody();
        Instant received = options.clock().instant();

        if (closed) {
            // Cancelled but the broker had already pushed this one. Requeue it:
            // the next runtime to attach is entitled to it, and answering after
            // shutdown began would be a reply nobody is waiting on.
            channel.basicNack(deliveryTag, false, true);
            return;
        }

        ReactorEvent event = verifyAndDecode(body, received, delivery);
        if (event == null) {
            // Every rejection path has already logged. Nack without requeue: a
            // body that failed §8 v2 will fail it again on redelivery, and its
            // window is closing either way.
            channel.basicNack(deliveryTag, false, false);
            return;
        }

        TelemetryHook hook = options.telemetryHook();
        emit(hook, new TelemetryEvent.RequestStart(
                TELEMETRY_OPERATION, TELEMETRY_METHOD, event.event(), 1));
        Instant started = options.clock().instant();

        ReactorDecision decision;
        try {
            if (options.listener() != null) {
                // §22.5: a listener never publishes a reply, and the server never
                // reads one. Observe and ack.
                options.listener().observe(event);
                emitEnd(hook, event, started, TelemetryEvent.Outcome.SUCCESS);
                channel.basicAck(deliveryTag, false);
                return;
            }
            ReactorHandler handler = options.handler();
            decision = handler == null ? null : handler.handle(event);
        } catch (RuntimeException | Error handlerFailure) {
            // §22.10 rule 2: no reply. The operator's failure_policy decides what
            // a crashed handler costs — an SDK that answers `allow` here has
            // overridden a fail_closed setting from inside the library.
            options.logger().warn(
                    "axiam_sdk_reactor: handler threw for event={} correlation={}; "
                            + "publishing NO reply, the registration's failure_policy applies ({})",
                    event.event(), event.correlationId(), handlerFailure.getClass().getSimpleName());
            emitEnd(hook, event, started, TelemetryEvent.Outcome.FAILURE);
            channel.basicNack(deliveryTag, false, false);
            return;
        }

        if (decision == null) {
            options.logger().warn(
                    "axiam_sdk_reactor: handler returned null for event={} correlation={}; "
                            + "publishing NO reply",
                    event.event(), event.correlationId());
            emitEnd(hook, event, started, TelemetryEvent.Outcome.FAILURE);
            channel.basicNack(deliveryTag, false, false);
            return;
        }

        // §22.3 / §22.10 rule 4: a late reply is discarded, and the CPU spent
        // producing it was spent for nothing. Abandon rather than answer into a
        // closed window.
        if (!options.clock().instant().isBefore(event.deadline())) {
            options.logger().warn(
                    "axiam_sdk_reactor: handler finished after the {} ms window closed for event={} "
                            + "correlation={}; abandoning the reply",
                    event.timeoutMs(), event.event(), event.correlationId());
            emitEnd(hook, event, started, TelemetryEvent.Outcome.FAILURE);
            channel.basicAck(deliveryTag, false);
            return;
        }

        String replyTo = delivery.getProperties() == null ? null : delivery.getProperties().getReplyTo();
        if (replyTo == null || replyTo.isBlank()) {
            options.logger().warn(
                    "axiam_sdk_reactor: delivery for event={} correlation={} carried no reply_to; "
                            + "publishing NO reply",
                    event.event(), event.correlationId());
            emitEnd(hook, event, started, TelemetryEvent.Outcome.FAILURE);
            channel.basicAck(deliveryTag, false);
            return;
        }

        byte[] reply = ReactorProtocol.signedReply(
                signingKey,
                event.correlationId(),
                event.tenantId(),
                event.event(),
                decision,
                UUID.randomUUID(),
                options.clock().instant());

        AMQP.BasicProperties replyProperties = new AMQP.BasicProperties.Builder()
                .contentType("application/json")
                .correlationId(event.correlationId().toString())
                .build();

        // Default exchange, routing key = the reply queue: standard AMQP RPC.
        // Publishing to "" is not declaring topology — every AMQP broker routes
        // the default exchange to the same-named queue without any declaration.
        channel.basicPublish("", replyTo, replyProperties, reply);
        emitEnd(hook, event, started, TelemetryEvent.Outcome.SUCCESS);
        channel.basicAck(deliveryTag, false);
    }

    /**
     * The &sect;22.3 gate, in order: key version, MAC, freshness, nonce, then
     * decode. Returns {@code null} — never a partially-trusted event — when any
     * gate refuses.
     */
    private @Nullable ReactorEvent verifyAndDecode(byte[] body, Instant now, Delivery delivery) {
        String routingKey = delivery.getEnvelope().getRoutingKey();
        JsonNode root;
        try {
            root = MAPPER.readTree(body);
        } catch (IOException e) {
            return reject(routingKey, "body is not valid JSON");
        }
        if (root == null || !root.isObject()) {
            return reject(routingKey, "body is not a JSON object");
        }

        JsonNode keyVersionNode = root.get("key_version");
        if (keyVersionNode == null || !keyVersionNode.canConvertToInt()
                || keyVersionNode.asInt() < ReactorProtocol.MIN_ACCEPTED_KEY_VERSION) {
            return reject(routingKey, "key_version below the accepted floor");
        }

        if (!ReactorProtocol.verifyEvent(signingKey, body)) {
            // §8.4: the fact of failure and the routing context, never the
            // received or expected MAC and never the key.
            return reject(routingKey, "signature missing or invalid");
        }

        JsonNode issuedAtNode = root.get("issued_at");
        if (issuedAtNode == null || !issuedAtNode.isTextual()) {
            return reject(routingKey, "issued_at missing");
        }
        Instant issuedAt;
        try {
            issuedAt = OffsetDateTime.parse(issuedAtNode.textValue()).toInstant();
        } catch (DateTimeParseException e) {
            return reject(routingKey, "issued_at unparseable");
        }
        if (!ReactorProtocol.isFresh(issuedAt, now, options.freshnessSkew())) {
            return reject(routingKey, "issued_at outside the freshness window");
        }

        UUID nonce = ReactorProtocol.parseUuid(text(root, "nonce"));
        if (nonce == null) {
            return reject(routingKey, "nonce missing or malformed");
        }
        if (!nonceStore.observe(nonce.toString(), now)) {
            return reject(routingKey, "nonce replay");
        }

        UUID tenantId = ReactorProtocol.parseUuid(text(root, "tenant_id"));
        if (tenantId == null) {
            return reject(routingKey, "tenant_id missing or malformed");
        }
        if (!tenantId.equals(options.tenantId())) {
            // Cannot happen through a correctly declared queue, and is exactly
            // the thing worth refusing anyway if it ever does.
            return reject(routingKey, "event names a different tenant");
        }

        UUID correlationId = ReactorProtocol.parseUuid(text(root, "correlation_id"));
        if (correlationId == null) {
            return reject(routingKey, "correlation_id missing or malformed");
        }

        String event = text(root, "event");
        if (event == null || event.isBlank()) {
            return reject(routingKey, "event missing");
        }

        JsonNode payload = root.get("payload");
        if (payload == null || !payload.isObject()) {
            return reject(routingKey, "payload missing or not an object");
        }

        JsonNode timeoutNode = root.get("timeout_ms");
        if (timeoutNode == null || !timeoutNode.canConvertToInt() || timeoutNode.asInt() <= 0) {
            return reject(routingKey, "timeout_ms missing or out of range");
        }
        int timeoutMs = Math.min(timeoutNode.asInt(), ReactorProtocol.CHAIN_CEILING_MS);

        return new ReactorEvent(tenantId, event, correlationId, payload, timeoutMs,
                keyVersionNode.asInt(), nonce, issuedAt, now.plusMillis(timeoutMs));
    }

    private @Nullable ReactorEvent reject(String routingKey, String reason) {
        options.logger().warn(
                "axiam_sdk_security: reactor event rejected ({}); no reply will be sent "
                        + "(exchange={}, routingKey={})",
                reason, ReactorProtocol.EXCHANGE, routingKey);
        return null;
    }

    private static @Nullable String text(JsonNode root, String field) {
        JsonNode node = root.get(field);
        return node == null || !node.isTextual() ? null : node.textValue();
    }

    private void emitEnd(@Nullable TelemetryHook hook, ReactorEvent event, Instant started,
                         TelemetryEvent.Outcome outcome) {
        Duration took = Duration.between(started, options.clock().instant());
        emit(hook, new TelemetryEvent.RequestEnd(
                TELEMETRY_OPERATION, TELEMETRY_METHOD, event.event(), 1, 0, took, outcome));
    }

    private void emit(@Nullable TelemetryHook hook, TelemetryEvent event) {
        if (hook == null) {
            return;
        }
        try {
            hook.accept(event);
        } catch (RuntimeException e) {
            // §19.2 rule 2: telemetry is not permitted to fail the dispatch that
            // fired it.
            options.logger().debug("axiam_sdk_reactor: telemetry hook threw ({})",
                    e.getClass().getSimpleName());
        }
    }

}
