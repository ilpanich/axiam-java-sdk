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
 * <p><strong>Against a server older than 1.68</strong> (unsigned responses) every response is
 * refused unless the integrator sets {@link Options#allowUnsignedResponses()} for one rolling
 * upgrade; with it, a response with <em>no</em> {@code hmac_signature} member is accepted on its
 * {@code correlation_id} alone, flagged {@link Decision#unsigned()} and logged as a warning. A
 * response that carries a signature member is verified in full whatever the option says.
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
     * @param allowed    the decision; {@code true} only for a response that verified under the tenant subkey (or,
     *                   with the unsigned opt-out, one that carried no signature at all, see {@code unsigned})
     * @param reason     the server's human-readable reason, or {@code null} when absent
     * @param reasonCode the machine-readable code ({@code allowed}, {@code no_grant}, {@code denied_by_rule},
     *                   {@code tenant_suspended}, ...), or {@code null} when absent; a code this SDK does not know is
     *                   surfaced verbatim
     * @param unsigned   {@code true} when the response carried no {@code hmac_signature} and was accepted only
     *                   because the unsigned opt-out is set
     */
    public record Decision(boolean allowed, @Nullable String reason, @Nullable String reasonCode, boolean unsigned) {
    }

    /**
     * Options for an {@link AuthzRequester}.
     *
     * @param allowUnsignedResponses the explicit opt-out for ONE rolling upgrade against a server older than
     *                               contract 1.68 (off by default); see the class documentation
     * @param logger                 receives security events for discarded responses and for an unsigned response
     *                               the opt-out admits; never given a signature value. {@code null} for the default
     * @param timeout                bounds each check; {@code null} for {@link #DEFAULT_TIMEOUT}
     * @param clock                  stamps {@code issued_at}; {@code null} for the system clock
     */
    public record Options(boolean allowUnsignedResponses, @Nullable Logger logger, @Nullable Duration timeout,
            @Nullable Clock clock) {

        /**
         * The defaults: unsigned responses refused, {@link #DEFAULT_TIMEOUT}, the system clock.
         *
         * @return the default options
         */
        public static Options defaults() {
            return new Options(false, null, null, null);
        }

        /**
         * Copy with the explicit unsigned-response opt-out set (see the class documentation).
         *
         * @return the new options
         */
        public Options withAllowUnsignedResponses() {
            return new Options(true, logger, timeout, clock);
        }

        /**
         * Copy with a security logger.
         *
         * @param value the logger
         * @return the new options
         */
        public Options withLogger(Logger value) {
            return new Options(allowUnsignedResponses, value, timeout, clock);
        }

        /**
         * Copy with a per-check timeout.
         *
         * @param value a positive duration
         * @return the new options
         */
        public Options withTimeout(Duration value) {
            return new Options(allowUnsignedResponses, logger, value, clock);
        }

        /**
         * Copy with a clock for {@code issued_at}.
         *
         * @param value the clock
         * @return the new options
         */
        public Options withClock(Clock value) {
            return new Options(allowUnsignedResponses, logger, timeout, value);
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
    private final boolean allowUnsigned;
    private final Logger logger;
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
        this.allowUnsigned = options.allowUnsignedResponses();
        this.logger = options.logger() != null ? options.logger() : LoggerFactory.getLogger(AuthzRequester.class);
        Duration t = options.timeout() != null ? options.timeout() : DEFAULT_TIMEOUT;
        if (t.isZero() || t.isNegative()) {
            throw new IllegalArgumentException("timeout must be positive");
        }
        this.timeout = t;
        this.clock = options.clock() != null ? options.clock() : Clock.systemUTC();

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
    }

    // ---- requests -------------------------------------------------------------------------

    /**
     * Asks the server whether {@code subjectId} may perform {@code action} on {@code resourceId}
     * (optionally narrowed by one {@code scope}) and waits for the verified answer. A response that
     * fails verification or binding is discarded and this keeps waiting for the genuine one until
     * the timeout ends.
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
     * exceptionally with a {@link NetworkError} on a timeout, a publish failure or a close.
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
            if (error == null) {
                out.complete(decision);
            } else if (error instanceof TimeoutException) {
                out.completeExceptionally(new NetworkError("timed out waiting for the authz response"));
            } else {
                out.completeExceptionally(error);
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
        Verified verified;
        try {
            verified = verifyResponse(delivery.body());
        } catch (Discard d) {
            // Fact of failure only — never a signature value (§8 protocol rule 4).
            logger.warn("axiam_sdk_security: AMQP authz response discarded: {}", d.getMessage());
            delivery.nackWithoutRequeue();
            return;
        }
        // Retire on acceptance: a second response for the same request finds nothing to complete.
        if (!pending.remove(verified.correlationId(), verified.pending())) {
            logger.warn("axiam_sdk_security: AMQP authz response discarded: no outstanding request");
            delivery.nackWithoutRequeue();
            return;
        }
        verified.pending().future().complete(verified.decision());
        delivery.ack();
    }

    private record Verified(Decision decision, String correlationId, Pending pending) {
    }

    /** A response that is not a decision. The message names the failed check, never a value. */
    private static final class Discard extends Exception {
        private static final long serialVersionUID = 1L;

        Discard(String message) {
            super(message, null, false, false);
        }
    }

    /**
     * Applies the &sect;8 consumer obligations 1&ndash;3 to {@code body}. It never re-serializes: the
     * signature is checked over {@code body} minus its trailing signature member, and the decision is
     * decoded from those same bytes.
     */
    private Verified verifyResponse(byte[] body) throws Discard {
        JsonNode root = parseStrict(body, "the body is not an object with unambiguous keys");
        if (!root.isObject()) {
            throw new Discard("the body is not a JSON object");
        }
        rejectCaseVariantKeys(root);
        // Rule 1 (strict parse) for the member every response carries.
        JsonNode allowed = root.get("allowed");
        if (allowed == null || !allowed.isBoolean()) {
            throw new Discard("allowed is missing or not a boolean");
        }
        if (!root.has("hmac_signature")) {
            return acceptUnsigned(root);
        }

        // The canonical bytes: the body with the final `,"hmac_signature":"<64 hex>"` taken out of the
        // closing brace. A body that does not end in that member is discarded, never repaired.
        int suffixLength = SIGNATURE_MEMBER.length() + SIGNATURE_HEX_LENGTH + 2;
        if (body.length <= suffixLength || body[body.length - 2] != '"' || body[body.length - 1] != '}') {
            throw new Discard("the body does not end in the hmac_signature member");
        }
        int start = body.length - suffixLength;
        String member = new String(body, start, SIGNATURE_MEMBER.length(), StandardCharsets.ISO_8859_1);
        if (!SIGNATURE_MEMBER.equals(member)) {
            throw new Discard("the body does not end in the hmac_signature member");
        }
        String sigHex = new String(body, start + SIGNATURE_MEMBER.length(), SIGNATURE_HEX_LENGTH,
                StandardCharsets.ISO_8859_1);
        byte[] received;
        try {
            received = HexFormat.of().parseHex(sigHex);
        } catch (IllegalArgumentException e) {
            throw new Discard("hmac_signature is not hex");
        }
        JsonNode embedded = root.get("hmac_signature");
        if (!embedded.isTextual() || !embedded.asText().equals(sigHex)) {
            throw new Discard("hmac_signature is not the trailing member");
        }
        byte[] canonical = new byte[start + 1];
        System.arraycopy(body, 0, canonical, 0, start);
        canonical[start] = '}';

        // Rule 2: HMAC-SHA256 under the requester's own tenant subkey, in constant time.
        if (!MessageDigest.isEqual(hmac(canonical), received)) {
            throw new Discard("the signature does not verify");
        }

        // Everything below reads the verified canonical bytes, never body (C2).
        JsonNode verified = parseStrict(canonical, "the verified bytes do not decode");
        String correlationId = text(verified, "correlation_id");
        String responseTenant = text(verified, "tenant_id");
        String nonce = text(verified, "nonce");
        JsonNode verifiedAllowed = verified.get("allowed");
        if (correlationId == null || responseTenant == null || nonce == null
                || verifiedAllowed == null || !verifiedAllowed.isBoolean()) {
            throw new Discard("tenant_id, nonce, correlation_id or allowed is missing");
        }

        // Rule 3: bound to this requester's tenant and to one outstanding request.
        if (!responseTenant.equals(tenantId)) {
            throw new Discard("tenant_id is not the requester's");
        }
        Pending p = pending.get(correlationId);
        if (p == null || !p.nonce().equals(nonce)) {
            throw new Discard("correlation_id and nonce match no outstanding request");
        }
        return new Verified(
                new Decision(verifiedAllowed.booleanValue(), text(verified, "reason"), text(verified, "reason_code"),
                        false),
                correlationId, p);
    }

    /**
     * A response with no {@code hmac_signature} member: refused unless the integrator set the
     * opt-out, in which case it is accepted on its {@code correlation_id} alone (a pre-1.68 server
     * answers with no {@code tenant_id} or {@code nonce}).
     */
    private Verified acceptUnsigned(JsonNode root) throws Discard {
        if (!allowUnsigned) {
            throw new Discard("the response is unsigned");
        }
        String correlationId = text(root, "correlation_id");
        if (correlationId == null) {
            throw new Discard("the unsigned response has no correlation_id");
        }
        Pending p = pending.get(correlationId);
        if (p == null) {
            throw new Discard("correlation_id matches no outstanding request");
        }
        logger.warn("axiam_sdk_security: AMQP authz response accepted UNSIGNED because allowUnsignedResponses is set");
        return new Verified(
                new Decision(root.get("allowed").booleanValue(), text(root, "reason"), text(root, "reason_code"), true),
                correlationId, p);
    }

    private static @Nullable String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && value.isTextual() && !value.asText().isEmpty() ? value.asText() : null;
    }

    private static JsonNode parseStrict(byte[] bytes, String failure) throws Discard {
        try {
            JsonNode node = STRICT.readTree(bytes);
            if (node == null) {
                throw new Discard(failure);
            }
            return node;
        } catch (IOException e) {
            throw new Discard(failure);
        }
    }

    /** Two top-level keys that differ only by case name one field to a case-folding decoder. */
    private static void rejectCaseVariantKeys(JsonNode root) throws Discard {
        Set<String> folded = new HashSet<>();
        for (Iterator<String> names = root.fieldNames(); names.hasNext();) {
            if (!folded.add(names.next().toLowerCase(Locale.ROOT))) {
                throw new Discard("the body has keys that differ only by case");
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
