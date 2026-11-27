package io.axiam.sdk.amqp;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;

import io.axiam.sdk.errors.NetworkError;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

/**
 * The AMQP authorization requester (CONTRACT.md &sect;8, "Signed authorization responses",
 * contract 1.68; N2, D-9): publishes an {@code AuthzRequest} on {@code axiam.authz.request} with a
 * private reply queue, and accepts an answer only when it verifies as the server's signed response
 * to <em>that</em> request.
 *
 * <p><strong>Routing.</strong> The request names, in {@code reply_to}, an <em>exclusive</em>,
 * auto-delete, broker-named queue only this requester consumes (an {@code amq.gen-…} queue) and
 * never reads its answers from the shared {@code axiam.authz.response}. A reply queue whose name is
 * empty or begins {@code axiam.} is refused: the server does not honour such a {@code reply_to}
 * (&sect;8 rule 5) and would answer on the shared queue instead. {@code correlation_id} and
 * {@code nonce} are fresh, independent, unpredictable UUIDs per request.
 *
 * <p><strong>Verification.</strong> The one rule that decides the design is the one C2 broke:
 * <em>verify the received bytes and decode from the same bytes</em>. The signature is checked over
 * the delivery body with its trailing {@code ,"hmac_signature":"…"} member cut out &mdash; never
 * over a re-serialization &mdash; and the decision handed to the caller is decoded from those very
 * canonical bytes. A response is a decision only when:
 * <ol>
 *   <li>it parses strictly: a JSON object with no repeated key at any depth and no two top-level
 *       keys that differ only by case, no content after the object, a JSON-boolean {@code allowed},
 *       and {@code tenant_id}, {@code nonce} and {@code hmac_signature} present, the signature the
 *       trailing member;</li>
 *   <li>{@code HMAC-SHA256(subkey, canonical)} equals {@code hmac_signature}, compared in constant
 *       time, with the subkey of the requester's <em>own</em> tenant and the {@code key_version} it
 *       sent (never a value the response supplies);</li>
 *   <li>{@code tenant_id} is the requester's own, and {@code correlation_id} and {@code nonce} both
 *       match one request still outstanding, which is then retired.</li>
 * </ol>
 * Anything else is nacked without requeue, logged as a security event that never carries a
 * signature value, and is <em>never</em> an allow and never completes the request with a deny: the
 * requester keeps waiting for the genuine answer or times out.
 *
 * <p><strong>Trust boundary.</strong> The key is the tenant's own subkey, which every producer of
 * the tenant holds, so a valid signature proves only that the response came from a holder of it. It
 * does not close injection by another service of the same tenant; see the contract's "What the
 * signature proves" clause and this SDK's README.
 *
 * <p><strong>Server version.</strong> The AMQP authorization requester requires an AXIAM server of
 * 1.68 or later (contract 1.68). Such a server signs every authorization response with the tenant's
 * AMQP subkey and answers on the requester's private {@code reply_to} queue. A server older than
 * 1.68 ignores {@code reply_to} and answers, unsigned, only on the shared
 * {@code axiam.authz.response} queue, which this requester never reads: against it every check times
 * out. There is no option to accept unsigned responses (CONTRACT 1.69 &sect;8): no AXIAM server sends
 * one to a reply queue, so an unsigned response can only have been published by someone else, and it
 * is discarded and logged. During a rolling upgrade from a pre-1.68 server, use REST or gRPC
 * authorization until every replica runs 1.68 or later.
 *
 * <p><strong>Discard event.</strong> Every discarded response logs one warning (CONTRACT 1.69 &sect;8
 * consumer obligation 4) carrying {@code timestamp}, {@code exchange}, {@code routing_key} (the reply
 * queue), {@code tenant_id} (this requester's own tenant) and {@code reason}
 * ({@code malformed}, {@code unsigned}, {@code signature}, {@code tenant} or
 * {@code unknown_request}); never a signature, a nonce, the key, the body or any value read from it.
 *
 * <p><strong>Threading.</strong> Responses are verified on the RabbitMQ consumer thread, but the
 * futures returned by {@link #checkAsync} are completed on an executor, never on that thread, so a
 * continuation may block (for instance by calling {@link #check} again) without stalling the reply
 * queue. The executor is {@link Options#executor()} when the caller supplies one, else a small
 * daemon-thread pool owned by the requester and shut down by {@link #close()}.
 *
 * <p>Thread-safe: many {@link #check} calls may be outstanding at once.
 */
public final class AuthzRequester implements AutoCloseable {

    /** The queue the server consumes {@code AuthzRequest} from. */
    public static final String AUTHZ_REQUEST_QUEUE = "axiam.authz.request";

    /** The {@code key_version} this requester sends; the caller supplies the subkey for it. */
    public static final int KEY_VERSION = 2;

    /** Bound on one {@link #check} when {@link Options#timeout()} is not set. */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);

    private static final String SERVER_QUEUE_PREFIX = "axiam.";
    private static final String SIGNATURE_MEMBER = ",\"hmac_signature\":\"";
    private static final int SIGNATURE_HEX_LENGTH = 64;
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final Pattern UUID_SHAPE =
            Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    /**
     * Strict reader for a response: a repeated key at any depth, or content after the object, fails
     * the parse (C2).
     */
    private static final ObjectMapper STRICT = JsonMapper.builder()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();

    // ---- public surface -------------------------------------------------------------------

    /**
     * A verified answer to one {@code AuthzRequest}.
     *
     * @param allowed    the decision; {@code true} only for a response that verified under the tenant subkey
     * @param reason     the server's human-readable reason, or {@code null} when absent
     * @param reasonCode the machine-readable code ({@code allowed}, {@code no_grant}, {@code denied_by_rule},
     *                   {@code tenant_suspended}, ...), or {@code null} when absent; a code this SDK does not know is
     *                   surfaced verbatim
     */
    public record Decision(boolean allowed, @Nullable String reason, @Nullable String reasonCode) {
    }

    /**
     * Options for an {@link AuthzRequester}.
     *
     * @param logger   receives the security event for every discarded response; never given a signature value.
     *                 {@code null} for the default
     * @param timeout  bounds each check; {@code null} for {@link #DEFAULT_TIMEOUT}
     * @param clock    stamps {@code issued_at} and the discard event; {@code null} for the system clock
     * @param executor completes the futures {@link #checkAsync} returns, so a continuation never runs on the
     *                 RabbitMQ consumer thread. {@code null} for a small daemon-thread pool the requester owns;
     *                 a caller-supplied executor is never shut down by the requester
     */
    public record Options(@Nullable Logger logger, @Nullable Duration timeout, @Nullable Clock clock,
            @Nullable Executor executor) {

        /**
         * The defaults: {@link #DEFAULT_TIMEOUT}, the system clock, a requester-owned executor.
         *
         * @return the default options
         */
        public static Options defaults() {
            return new Options(null, null, null, null);
        }

        /**
         * Copy with a security logger.
         *
         * @param value the logger
         * @return the new options
         */
        public Options withLogger(Logger value) {
            return new Options(value, timeout, clock, executor);
        }

        /**
         * Copy with a per-check timeout.
         *
         * @param value a positive duration
         * @return the new options
         */
        public Options withTimeout(Duration value) {
            return new Options(logger, value, clock, executor);
        }

        /**
         * Copy with a clock for {@code issued_at} and the discard event.
         *
         * @param value the clock
         * @return the new options
         */
        public Options withClock(Clock value) {
            return new Options(logger, timeout, value, executor);
        }

        /**
         * Copy with the executor that completes {@link #checkAsync} futures (see the class documentation).
         *
         * @param value the executor; the requester does not shut it down
         * @return the new options
         */
        public Options withExecutor(Executor value) {
            return new Options(logger, timeout, clock, value);
        }
    }

    /** One delivery from the private reply queue. */
    public interface ResponseDelivery {

        /**
         * The delivery body, exactly as the broker delivered it.
         *
         * @return the body bytes
         */
        byte[] body();

        /**
         * The exchange the broker reported for this delivery; {@code ""} for the default exchange, where
         * the server publishes every answer. A transport that cannot report it keeps this default.
         *
         * @return the exchange name
         */
        default String exchange() {
            return "";
        }

        /**
         * The delivery's routing key (the reply queue name for the default exchange), or {@code null}
         * when the transport cannot report it, in which case the requester uses its own reply queue.
         *
         * @return the routing key, or {@code null}
         */
        default @Nullable String routingKey() {
            return null;
        }

        /** Acknowledges the delivery (an accepted response). */
        void ack();

        /** Rejects the delivery WITHOUT requeue (a response that is discarded). */
        void nackWithoutRequeue();
    }

    /** Receives the private reply queue's deliveries. */
    public interface ResponseSink {

        /**
         * A delivery arrived on the reply queue.
         *
         * @param delivery the delivery
         */
        void accept(ResponseDelivery delivery);

        /** The reply queue or its consumer went away; the requester closes. */
        void closed();
    }

    /**
     * The seam between the requester and a broker: it declares the private reply queue and publishes
     * requests. {@link #forChannel(Channel)} is the RabbitMQ implementation; a test supplies a fake.
     */
    public interface Transport {

        /**
         * Declares an EXCLUSIVE, auto-delete, broker-named queue only this requester consumes, and
         * starts consuming it with manual acknowledgement, delivering to {@code sink}.
         *
         * @param sink where the queue's deliveries go
         * @return the broker-assigned queue name
         * @throws IOException if the broker refuses
         */
        String declareReplyQueue(ResponseSink sink) throws IOException;

        /**
         * Publishes {@code body} on the default exchange with routing key {@code queue}, AMQP
         * {@code reply_to = replyTo} and {@code correlation_id = correlationId}.
         *
         * @param queue         the routing key (the request queue)
         * @param replyTo       the private reply queue
         * @param correlationId the request's correlation id
         * @param body          the signed request
         * @throws IOException if the publish fails
         */
        void publishRequest(String queue, String replyTo, String correlationId, byte[] body) throws IOException;

        /** Stops consuming the reply queue; the broker then deletes it (auto-delete). */
        default void close() {
        }
    }

    /**
     * The RabbitMQ {@link Transport} over {@code channel}: a private exclusive auto-delete
     * broker-named reply queue, consumed exclusively with manual acknowledgement.
     *
     * @param channel the channel to declare, consume and publish on; the caller owns its lifecycle
     * @return the transport
     */
    public static Transport forChannel(Channel channel) {
        return new RabbitTransport(channel);
    }

    /**
     * Opens a private reply queue on {@code channel} and returns a requester for {@code tenantId}.
     *
     * @param channel    the AMQP channel; the caller owns its lifecycle
     * @param tenantId   the requester's OWN tenant, the only tenant a response is accepted for
     * @param signingKey the tenant's AMQP subkey for {@link #KEY_VERSION} (&sect;8.1 &mdash; from the AXIAM
     *                   management API, never hardcoded)
     * @return the requester
     * @throws IOException if the reply queue cannot be declared
     */
    public static AuthzRequester create(Channel channel, String tenantId, byte[] signingKey) throws IOException {
        return create(forChannel(channel), tenantId, signingKey, Options.defaults());
    }

    /**
     * As {@link #create(Channel, String, byte[])} with options and an explicit {@link Transport}.
     *
     * @param transport  the broker seam, e.g. {@link #forChannel(Channel)}
     * @param tenantId   the requester's OWN tenant
     * @param signingKey the tenant's AMQP subkey for {@link #KEY_VERSION}
     * @param options    the options
     * @return the requester
     * @throws IOException if the reply queue cannot be declared
     */
    public static AuthzRequester create(Transport transport, String tenantId, byte[] signingKey, Options options)
            throws IOException {
        return new AuthzRequester(transport, tenantId, signingKey, options);
    }

    // ---- state ----------------------------------------------------------------------------

    private final Transport transport;
    private final String tenantId;
    private final byte[] signingKey;
    private final Logger logger;
    private final Executor executor;
    private final @Nullable ExecutorService ownedExecutor;
    private final Duration timeout;
    private final Clock clock;
    private final String replyTo;
    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private volatile boolean closed;

    /** One outstanding request, keyed by its correlation_id. */
    private record Pending(String nonce, CompletableFuture<Decision> future) {
    }

    private AuthzRequester(Transport transport, String tenantId, byte[] signingKey, Options options)
            throws IOException {
        this.tenantId = canonicalUuid(tenantId, "tenant_id");
        if (signingKey.length == 0) {
            throw new IllegalArgumentException("the authz requester needs the tenant signing key");
        }
        this.transport = transport;
        this.signingKey = signingKey.clone();
        this.logger = options.logger() != null ? options.logger() : LoggerFactory.getLogger(AuthzRequester.class);
        Duration t = options.timeout() != null ? options.timeout() : DEFAULT_TIMEOUT;
        if (t.isZero() || t.isNegative()) {
            throw new IllegalArgumentException("timeout must be positive");
        }
        this.timeout = t;
        this.clock = options.clock() != null ? options.clock() : Clock.systemUTC();
        if (options.executor() != null) {
            this.executor = options.executor();
            this.ownedExecutor = null;
        } else {
            this.ownedExecutor = Executors.newCachedThreadPool(new ThreadFactory() {
                private final AtomicInteger n = new AtomicInteger();

                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "axiam-authz-requester-" + n.incrementAndGet());
                    t.setDaemon(true);
                    return t;
                }
            });
            this.executor = ownedExecutor;
        }

        String queue = transport.declareReplyQueue(new ResponseSink() {
            @Override
            public void accept(ResponseDelivery delivery) {
                handle(delivery);
            }

            @Override
            public void closed() {
                close();
            }
        });
        if (queue == null || queue.isEmpty() || queue.startsWith(SERVER_QUEUE_PREFIX)) {
            // The server answers a reply_to naming one of its own queues on the shared
            // axiam.authz.response instead (§8 rule 5), which would put this requester back on the
            // shared queue the contract forbids.
            transport.close();
            if (ownedExecutor != null) {
                ownedExecutor.shutdown();
            }
            throw new IllegalArgumentException("the authz reply queue \"" + queue + "\" is not a private queue");
        }
        this.replyTo = queue;
    }

    /**
     * The private reply queue requests name in their {@code reply_to}.
     *
     * @return the queue name
     */
    public String replyTo() {
        return replyTo;
    }

    /**
     * Stops accepting answers; outstanding and later checks fail with a {@link NetworkError}. The
     * reply queue is exclusive and auto-delete, so the broker removes it with the consumer.
     */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        transport.close();
        NetworkError error = new NetworkError("the authz requester is closed");
        for (Pending p : pending.values()) {
            p.future().completeExceptionally(error);
        }
        pending.clear();
        if (ownedExecutor != null) {
            // Completions already handed to it still run; later ones fall back to the caller's thread.
            ownedExecutor.shutdown();
        }
    }

    /** Completes {@code action} off the caller's thread; on a refused hand-off (closed) it runs inline. */
    private void completeOffThread(Runnable action) {
        try {
            executor.execute(action);
        } catch (RejectedExecutionException e) {
            action.run();
        }
    }

    // ---- requests -------------------------------------------------------------------------

    /**
     * Asks the server whether {@code subjectId} may perform {@code action} on {@code resourceId}
     * (optionally narrowed by one {@code scope}) and waits for the verified answer. A response that
     * fails verification or binding is discarded and this keeps waiting for the genuine one until
     * the timeout ends. Must not be called from a thread the caller's own {@link Options#executor()}
     * needs in order to complete a check (it would wait on itself).
     *
     * @param subjectId  the subject UUID
     * @param action     the action
     * @param resourceId the resource UUID
     * @param scope      an optional scope, or {@code null}
     * @return the verified decision
     * @throws IllegalArgumentException if an id is not a UUID or a string is not valid UTF-16
     * @throws NetworkError             on a publish failure, a timeout or a closed requester
     */
    public Decision check(String subjectId, String action, String resourceId, @Nullable String scope) {
        try {
            return checkAsync(subjectId, action, resourceId, scope).join();
        } catch (CompletionException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw new NetworkError("the authz check failed", e.getCause());
        }
    }

    /**
     * Asynchronous form of {@link #check}: the future completes with the verified decision, or
     * exceptionally with a {@link NetworkError} on a timeout, a publish failure or a close. The future
     * is completed on the requester's executor, <strong>not</strong> on the RabbitMQ consumer thread,
     * so a dependent stage may block (including by calling {@link #check}) without stalling the reply
     * queue.
     *
     * @param subjectId  the subject UUID
     * @param action     the action
     * @param resourceId the resource UUID
     * @param scope      an optional scope, or {@code null}
     * @return the future decision
     * @throws IllegalArgumentException if an id is not a UUID or a string is not valid UTF-16
     */
    public CompletableFuture<Decision> checkAsync(
            String subjectId, String action, String resourceId, @Nullable String scope) {
        String correlationId = UUID.randomUUID().toString(); // SecureRandom-backed, unpredictable
        String nonce = UUID.randomUUID().toString();
        byte[] body = buildRequest(correlationId, subjectId, action, resourceId, scope, nonce);

        if (closed) {
            return CompletableFuture.failedFuture(new NetworkError("the authz requester is closed"));
        }
        Pending p = new Pending(nonce, new CompletableFuture<>());
        pending.put(correlationId, p);
        CompletableFuture<Decision> out = new CompletableFuture<>();
        p.future().orTimeout(timeout.toMillis(), TimeUnit.MILLISECONDS).whenComplete((decision, error) -> {
            pending.remove(correlationId, p);
            // JAV-R1-6: never complete `out` on the thread that got here (the RabbitMQ consumer
            // thread for an answer): its dependants run on the completing thread, and a blocking
            // one would stall every later delivery and the ack behind it.
            if (error == null) {
                completeOffThread(() -> out.complete(decision));
            } else if (error instanceof TimeoutException) {
                completeOffThread(() -> out.completeExceptionally(
                        new NetworkError("timed out waiting for the authz response")));
            } else {
                completeOffThread(() -> out.completeExceptionally(error));
            }
        });
        try {
            transport.publishRequest(AUTHZ_REQUEST_QUEUE, replyTo, correlationId, body);
        } catch (IOException | RuntimeException e) {
            p.future().completeExceptionally(new NetworkError("failed to publish the authz request", e));
        }
        return out;
    }

    /**
     * Serializes and signs an {@code AuthzRequest} in the server's field order, compact, with the
     * signature as the trailing member. The signed bytes are the bytes serde_json would write for the
     * same struct: {@code "} and {@code \} escaped, the short escapes for the five control characters
     * that have one, a backslash-u-00 escape with lower-case hex for the rest below U+0020, and everything else,
     * {@code < > &} and all non-ASCII included, as raw UTF-8.
     */
    byte[] buildRequest(String correlationId, String subjectId, String action, String resourceId,
            @Nullable String scope, String nonce) {
        String subject = canonicalUuid(subjectId, "subject_id");
        String resource = canonicalUuid(resourceId, "resource_id");
        StringBuilder sb = new StringBuilder(256);
        sb.append("{\"correlation_id\":");
        appendString(sb, correlationId);
        sb.append(",\"tenant_id\":");
        appendString(sb, tenantId);
        sb.append(",\"subject_id\":");
        appendString(sb, subject);
        sb.append(",\"action\":");
        appendString(sb, action);
        sb.append(",\"resource_id\":");
        appendString(sb, resource);
        if (scope != null) {
            sb.append(",\"scope\":");
            appendString(sb, scope);
        }
        sb.append(",\"key_version\":").append(KEY_VERSION);
        sb.append(",\"nonce\":");
        appendString(sb, nonce);
        sb.append(",\"issued_at\":");
        appendString(sb, clock.instant().truncatedTo(ChronoUnit.SECONDS).toString());
        sb.append('}');
        byte[] canonical = sb.toString().getBytes(StandardCharsets.UTF_8);

        String signature = HexFormat.of().formatHex(hmac(canonical));
        String wire = new String(canonical, StandardCharsets.UTF_8);
        wire = wire.substring(0, wire.length() - 1) + SIGNATURE_MEMBER + signature + "\"}";
        return wire.getBytes(StandardCharsets.UTF_8);
    }

    private static String canonicalUuid(String value, String field) {
        if (value == null || !UUID_SHAPE.matcher(value).matches()) {
            throw new IllegalArgumentException(field + " is not a UUID");
        }
        return value.toLowerCase(Locale.ROOT);
    }

    private static void appendString(StringBuilder sb, String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(i + 1))) {
                    throw new IllegalArgumentException("a request string is not valid UTF-16");
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                throw new IllegalArgumentException("a request string is not valid UTF-16");
            }
        }
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append("\\u00").append(Character.forDigit(c >> 4, 16)).append(Character.forDigit(c & 0xf, 16));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    private byte[] hmac(byte[] bytes) {
        try {
            Mac mac = Mac.getInstance(MAC_ALGORITHM);
            mac.init(new SecretKeySpec(signingKey, MAC_ALGORITHM));
            return mac.doFinal(bytes);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is unavailable", e);
        }
    }

    // ---- responses ------------------------------------------------------------------------

    /** Test seam: registers an outstanding request with a fixed correlation_id and nonce, as a published one would. */
    CompletableFuture<Decision> registerOutstanding(String correlationId, String nonce) {
        Pending p = new Pending(nonce, new CompletableFuture<>());
        pending.put(correlationId, p);
        return p.future();
    }

    /** Test seam: the number of outstanding requests. */
    int outstanding() {
        return pending.size();
    }

    /** Verifies one delivery and completes the matching request, or discards it. */
    void handle(ResponseDelivery delivery) {
        if (closed) {
            // After Close an answer is not decoded or dispatched and raises no event (CONTRACT 1.69 §8,
            // consumer obligation 4): the requester no longer holds the requests it would match.
            delivery.nackWithoutRequeue();
            return;
        }
        Verified verified;
        try {
            verified = verifyResponse(delivery.body());
        } catch (Discard d) {
            discard(delivery, d.reason());
            return;
        }
        // Retire on acceptance: a second response for the same request finds nothing to complete.
        if (!pending.remove(verified.correlationId(), verified.pending())) {
            discard(delivery, Reason.UNKNOWN_REQUEST);
            return;
        }
        verified.pending().future().complete(verified.decision());
        delivery.ack();
    }

    /** Why a response was discarded: the {@code reason} member of the security event (A.2). */
    private enum Reason {
        MALFORMED("malformed"), UNSIGNED("unsigned"), SIGNATURE("signature"), TENANT("tenant"),
        UNKNOWN_REQUEST("unknown_request");

        private final String code;

        Reason(String code) {
            this.code = code;
        }
    }

    /**
     * Nacks without requeue and logs the one security event of CONTRACT 1.69 &sect;8 consumer
     * obligation 4: timestamp, exchange, routing key, the requester's OWN tenant and the reason.
     * Nothing read from the body, no signature (received or computed), no nonce, no key.
     */
    private void discard(ResponseDelivery delivery, Reason reason) {
        String routingKey = delivery.routingKey();
        if (routingKey == null || routingKey.isEmpty()) {
            routingKey = replyTo;
        }
        String exchange = delivery.exchange() == null ? "" : delivery.exchange();
        logger.warn("axiam_sdk_security: AMQP authz response discarded timestamp={} exchange=\"{}\" routing_key={} "
                + "tenant_id={} reason={}",
                clock.instant().truncatedTo(ChronoUnit.MILLIS), exchange, routingKey, tenantId, reason.code);
        delivery.nackWithoutRequeue();
    }

    private record Verified(Decision decision, String correlationId, Pending pending) {
    }

    /** A response that is not a decision; carries only the reason code, never a value. */
    private static final class Discard extends Exception {
        private static final long serialVersionUID = 1L;
        private final transient Reason reason;

        Discard(Reason reason) {
            super(reason.code, null, false, false);
            this.reason = reason;
        }

        Reason reason() {
            return reason;
        }
    }

    /**
     * Applies the &sect;8 consumer obligations 1&ndash;3 to {@code body}. It never re-serializes: the
     * signature is checked over {@code body} minus its trailing signature member, and the decision is
     * decoded from those same bytes.
     */
    private Verified verifyResponse(byte[] body) throws Discard {
        JsonNode root = parseStrict(body);
        if (!root.isObject()) {
            throw new Discard(Reason.MALFORMED);
        }
        rejectCaseVariantKeys(root);
        // Rule 1: no hmac_signature member at all is an unsigned response. There is no opt-out
        // (CONTRACT 1.69 §8, A.1): no server sends one to a reply queue, so whoever did is not it.
        if (!root.has("hmac_signature")) {
            throw new Discard(Reason.UNSIGNED);
        }
        // Rule 1 (strict parse) for the member every response carries.
        JsonNode allowed = root.get("allowed");
        if (allowed == null || !allowed.isBoolean()) {
            throw new Discard(Reason.MALFORMED);
        }

        // The canonical bytes: the body with the final `,"hmac_signature":"<64 hex>"` taken out of the
        // closing brace. A body that does not end in that member is discarded, never repaired.
        int suffixLength = SIGNATURE_MEMBER.length() + SIGNATURE_HEX_LENGTH + 2;
        if (body.length <= suffixLength || body[body.length - 2] != '"' || body[body.length - 1] != '}') {
            throw new Discard(Reason.MALFORMED);
        }
        int start = body.length - suffixLength;
        String member = new String(body, start, SIGNATURE_MEMBER.length(), StandardCharsets.ISO_8859_1);
        if (!SIGNATURE_MEMBER.equals(member)) {
            throw new Discard(Reason.MALFORMED);
        }
        String sigHex = new String(body, start + SIGNATURE_MEMBER.length(), SIGNATURE_HEX_LENGTH,
                StandardCharsets.ISO_8859_1);
        byte[] received;
        try {
            received = HexFormat.of().parseHex(sigHex);
        } catch (IllegalArgumentException e) {
            throw new Discard(Reason.MALFORMED);
        }
        JsonNode embedded = root.get("hmac_signature");
        if (!embedded.isTextual() || !embedded.asText().equals(sigHex)) {
            throw new Discard(Reason.MALFORMED);
        }
        byte[] canonical = new byte[start + 1];
        System.arraycopy(body, 0, canonical, 0, start);
        canonical[start] = '}';

        // Discard order 3 (before the HMAC, CONTRACT 1.69 §8): the members the binding reads must be
        // present and strings, whatever the signature says; a response that lacks one is malformed, not a
        // signature failure.
        if (text(root, "correlation_id") == null || text(root, "tenant_id") == null
                || text(root, "nonce") == null) {
            throw new Discard(Reason.MALFORMED);
        }

        // Rule 2: HMAC-SHA256 under the requester's own tenant subkey, in constant time.
        if (!MessageDigest.isEqual(hmac(canonical), received)) {
            throw new Discard(Reason.SIGNATURE);
        }

        // Everything below reads the verified canonical bytes, never body (C2).
        JsonNode verified = parseStrict(canonical);
        String correlationId = text(verified, "correlation_id");
        String responseTenant = text(verified, "tenant_id");
        String nonce = text(verified, "nonce");
        JsonNode verifiedAllowed = verified.get("allowed");
        if (correlationId == null || responseTenant == null || nonce == null
                || verifiedAllowed == null || !verifiedAllowed.isBoolean()) {
            throw new Discard(Reason.MALFORMED);
        }

        // Rule 3: bound to this requester's tenant and to one outstanding request.
        if (!responseTenant.equals(tenantId)) {
            throw new Discard(Reason.TENANT);
        }
        Pending p = pending.get(correlationId);
        if (p == null || !p.nonce().equals(nonce)) {
            throw new Discard(Reason.UNKNOWN_REQUEST);
        }
        return new Verified(
                new Decision(verifiedAllowed.booleanValue(), text(verified, "reason"), text(verified, "reason_code")),
                correlationId, p);
    }

    private static @Nullable String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && value.isTextual() && !value.asText().isEmpty() ? value.asText() : null;
    }

    private static JsonNode parseStrict(byte[] bytes) throws Discard {
        try {
            JsonNode node = STRICT.readTree(bytes);
            if (node == null) {
                throw new Discard(Reason.MALFORMED);
            }
            return node;
        } catch (IOException e) {
            throw new Discard(Reason.MALFORMED);
        }
    }

    /** Two top-level keys that differ only by case name one field to a case-folding decoder. */
    private static void rejectCaseVariantKeys(JsonNode root) throws Discard {
        Set<String> folded = new HashSet<>();
        for (Iterator<String> names = root.fieldNames(); names.hasNext();) {
            if (!folded.add(names.next().toLowerCase(Locale.ROOT))) {
                throw new Discard(Reason.MALFORMED);
            }
        }
    }

    // ---- RabbitMQ transport ---------------------------------------------------------------

    private static final class RabbitTransport implements Transport {
        private final Channel channel;
        private volatile String consumerTag;

        RabbitTransport(Channel channel) {
            this.channel = channel;
        }

        @Override
        public String declareReplyQueue(ResponseSink sink) throws IOException {
            // Empty name: the broker names it (`amq.gen-…`). Not durable, auto-delete, EXCLUSIVE:
            // only this connection may consume it.
            String name = channel.queueDeclare("", false, true, true, null).getQueue();
            consumerTag = channel.basicConsume(name, false /* manual ack */, "", false, true /* exclusive */, null,
                    (tag, delivery) -> sink.accept(new ResponseDelivery() {
                        private final long deliveryTag = delivery.getEnvelope().getDeliveryTag();

                        @Override
                        public byte[] body() {
                            return delivery.getBody();
                        }

                        @Override
                        public String exchange() {
                            String exchange = delivery.getEnvelope().getExchange();
                            return exchange == null ? "" : exchange;
                        }

                        @Override
                        public String routingKey() {
                            return delivery.getEnvelope().getRoutingKey();
                        }

                        @Override
                        public void ack() {
                            try {
                                channel.basicAck(deliveryTag, false);
                            } catch (IOException e) {
                                throw new NetworkError("failed to ack an authz response", e);
                            }
                        }

                        @Override
                        public void nackWithoutRequeue() {
                            try {
                                channel.basicNack(deliveryTag, false, false);
                            } catch (IOException e) {
                                throw new NetworkError("failed to nack an authz response", e);
                            }
                        }
                    }),
                    tag -> sink.closed());
            return name;
        }

        @Override
        public void publishRequest(String queue, String replyTo, String correlationId, byte[] body)
                throws IOException {
            AMQP.BasicProperties props = new AMQP.BasicProperties.Builder()
                    .contentType("application/json")
                    .correlationId(correlationId)
                    .replyTo(replyTo)
                    .build();
            channel.basicPublish("", queue, props, body);
        }

        @Override
        public void close() {
            String tag = consumerTag;
            if (tag != null) {
                try {
                    channel.basicCancel(tag);
                } catch (IOException | RuntimeException e) {
                    // The channel is already gone; the exclusive auto-delete queue goes with it.
                }
            }
        }
    }
}
