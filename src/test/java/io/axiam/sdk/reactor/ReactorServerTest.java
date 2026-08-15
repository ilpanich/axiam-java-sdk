package io.axiam.sdk.reactor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DeliverCallback;
import com.rabbitmq.client.Delivery;
import com.rabbitmq.client.Envelope;
import io.axiam.sdk.Sensitive;
import io.axiam.sdk.telemetry.TelemetryEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;22.10 and &sect;22.13's "Runtime" group: the verify-before-
 * handler gate, the no-topology rule, fail-closed-on-our-own-errors, the
 * unfiltered patch, the timeout window, &sect;18 shutdown, and the guarantee that
 * the signing key never reaches a log line.
 *
 * <p>Everything runs against a {@link Proxy}-backed fake {@link Channel} that
 * records every method the runtime calls — which is what makes "declares no
 * exchange, queue or binding" an assertion about behaviour rather than about
 * source code.
 */
class ReactorServerTest {

    /** The fixture's own {@code verified_at}; every event vector is fresh at this instant. */
    private static final Instant NOW = Instant.parse("2026-07-10T12:00:00Z");
    private static final Clock FIXED = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String REPLY_QUEUE = "amq.rabbitmq.reply-to.abc";

    private JsonNode fixture;
    private byte[] subkey;
    private String subkeyHex;
    private UUID tenantId;
    private UUID reactorId;

    private List<Call> calls;
    private List<byte[]> published;
    private Channel channel;
    private List<String> logLines;
    private Logger logger;

    /** One recorded invocation on the fake {@link Channel}. */
    private record Call(String method, Object[] args) {
    }

    @BeforeEach
    void setUp() throws Exception {
        fixture = ReactorVectors.load();
        subkey = ReactorVectors.subkey(fixture);
        subkeyHex = fixture.get("hkdf").get("derived_subkey_hex").asText();
        tenantId = ReactorVectors.tenantId(fixture);
        reactorId = UUID.fromString(fixture.get("reactor_id").asText());

        calls = new ArrayList<>();
        published = new ArrayList<>();
        channel = fakeChannel(calls, published);
        logLines = new ArrayList<>();
        logger = fakeLogger(logLines);
    }

    // ---- happy path --------------------------------------------------------

    @Test
    void aVerifiedEventReachesTheHandlerAndItsReplyIsSignedAndCorrelated() throws Exception {
        AtomicReference<ReactorEvent> seen = new AtomicReference<>();
        try (ReactorServer server = serve(event -> {
            seen.set(event);
            return ReactorDecision.mutate(Map.of("ext.department", "eng"));
        })) {
            deliver(server, eventBody("token_pre_issue"));
        }

        ReactorEvent event = seen.get();
        assertNotNull(event, "a verified event must reach the handler");
        assertEquals(ReactorEvents.TOKEN_PRE_ISSUE, event.event());
        assertEquals(tenantId, event.tenantId());
        assertEquals(ReactorVectors.correlationId(fixture), event.correlationId());
        assertEquals(500, event.timeoutMs());
        assertEquals("alice", event.payload().get("sub").asText());
        assertEquals(Map.of(), event.priorPatch());

        assertEquals(1, published.size(), "exactly one reply");
        byte[] reply = published.get(0);
        assertTrue(ReactorProtocol.verifyEvent(subkey, reply),
                "the reply must be signed with the same tenant subkey");
        JsonNode parsed = ReactorVectors.MAPPER.readTree(reply);
        assertEquals(event.correlationId().toString(), parsed.get("correlation_id").asText(),
                "the correlation the server authenticates lives inside the signed body");
        assertEquals("mutate", parsed.get("decision").asText());
        assertEquals("eng", parsed.get("patch").get("ext.department").asText());
        assertEquals(2, parsed.get("key_version").asInt());
        assertTrue(acked(), "a handled delivery is acked");

        // The AMQP property is echoed too — standard RPC — but it is not what
        // the server authenticates.
        AMQP.BasicProperties props = (AMQP.BasicProperties) call("basicPublish").args()[2];
        assertEquals(event.correlationId().toString(), props.getCorrelationId());
        assertEquals(REPLY_QUEUE, call("basicPublish").args()[1]);
        assertEquals("", call("basicPublish").args()[0], "replies go to the default exchange");
    }

    // ---- §22.10 rule 1: no topology ----------------------------------------

    @Test
    void theRuntimeDeclaresNoExchangeNoQueueAndNoBinding() throws Exception {
        try (ReactorServer server = serve(event -> ReactorDecision.allow())) {
            deliver(server, eventBody("login_post_auth"));
        }

        for (Call call : calls) {
            String method = call.method();
            assertFalse(method.startsWith("exchangeDeclare") || method.startsWith("queueDeclare")
                            || method.startsWith("queueBind") || method.startsWith("exchangeBind"),
                    "actors consume; they never declare topology — saw " + method);
        }
        assertTrue(calls.stream().anyMatch(c -> c.method().equals("basicConsume")));
        assertEquals(ReactorProtocol.queueName(tenantId, reactorId),
                call("basicConsume").args()[0],
                "the runtime consumes the queue it is registered as, and no other");
    }

    // ---- §22.10 rule 2: fail closed on our own errors ----------------------

    @Test
    void aHandlerThatThrowsProducesNoReplyRatherThanASynthesizedAllow() throws Exception {
        try (ReactorServer server = serve(event -> {
            throw new IllegalStateException("fraud backend unreachable");
        })) {
            deliver(server, eventBody("login_post_auth"));
        }

        assertEquals(0, published.size(),
                "zero published messages — an SDK that answers `allow` for a crashed handler has "
                        + "overridden the operator's fail_closed setting from inside the library");
    }

    @Test
    void anEventThatFailsAnySection8GateNeverReachesTheHandler() throws Exception {
        // (a) wrong signature
        assertHandlerNeverRuns(tamper(body -> body.put("payload",
                ReactorVectors.MAPPER.createObjectNode().put("sub", "root"))));
        // (b) key_version downgraded after signing — refused before the MAC is computed
        assertHandlerNeverRuns(tamper(body -> body.put("key_version", 1)));
        // (c) stale
        assertHandlerNeverRuns(signedEvent(ReactorEvents.TOKEN_PRE_ISSUE, UUID.randomUUID(),
                NOW.minusSeconds(301)));
        // (d) future
        assertHandlerNeverRuns(signedEvent(ReactorEvents.TOKEN_PRE_ISSUE, UUID.randomUUID(),
                NOW.plusSeconds(301)));
        // (e) another tenant's event, correctly signed for that tenant
        assertHandlerNeverRuns(signedEventForTenant(UUID.randomUUID()));
    }

    @Test
    void aReplayedNonceIsRefusedOnTheSecondDelivery() throws Exception {
        AtomicInteger handled = new AtomicInteger();
        byte[] body = eventBody("token_pre_issue");
        try (ReactorServer server = serve(event -> {
            handled.incrementAndGet();
            return ReactorDecision.allow();
        })) {
            deliver(server, body);
            deliver(server, body);
        }
        assertEquals(1, handled.get(), "the second delivery of one nonce is a replay");
        assertEquals(1, published.size());
    }

    // ---- §22.10 rule 3: never filter a patch -------------------------------

    /**
     * &sect;22.4 rule 1 / &sect;22.13: a handler returning a patch containing a
     * forbidden key sends it <strong>unfiltered</strong>. Silently dropping
     * {@code sub} would leave the reactor author believing it was set.
     */
    @Test
    void aForbiddenPatchKeyIsSentUnfilteredRatherThanQuietlyDropped() throws Exception {
        try (ReactorServer server = serve(event -> ReactorDecision.mutate(
                Map.of("ext.department", "eng", "sub", "root")))) {
            deliver(server, eventBody("token_pre_issue"));
        }

        assertEquals(1, published.size());
        JsonNode patch = ReactorVectors.MAPPER.readTree(published.get(0)).get("patch");
        assertEquals("root", patch.get("sub").asText(),
                "the SDK must NOT drop `sub` — one forbidden key rejects the whole patch, "
                        + "server-side, and the author finds out");
        assertEquals("eng", patch.get("ext.department").asText());
        assertFalse(ReactorEvents.spec(ReactorEvents.TOKEN_PRE_ISSUE).patchFieldAllowed("sub"),
                "and the SDK knows perfectly well that the server will refuse it");
    }

    // ---- §22.3 / rule 4: the window ----------------------------------------

    @Test
    void aReplyIsAbandonedRatherThanPublishedAfterTheWindowClosed() throws Exception {
        // A clock that jumps two seconds after the event is received: the
        // 500 ms window has closed by the time the handler returns.
        MovingClock clock = new MovingClock(NOW);
        try (ReactorServer server = serve(event -> {
            clock.advance(Duration.ofSeconds(2));
            return ReactorDecision.allow();
        }, clock)) {
            deliver(server, eventBody("token_pre_issue"));
        }

        assertEquals(0, published.size(), "a late reply is discarded by the server anyway");
        assertTrue(acked(), "the delivery is still settled");
    }

    @Test
    void anEventCarriesItsWindowToTheHandler() throws Exception {
        AtomicReference<Duration> remaining = new AtomicReference<>();
        try (ReactorServer server = serve(event -> {
            remaining.set(event.remaining(NOW));
            return ReactorDecision.allow();
        })) {
            deliver(server, eventBody("login_post_auth"));
        }
        assertEquals(Duration.ofMillis(1000), remaining.get(),
                "login.post_auth's vector declares a 1000 ms window");
    }

    // ---- §22.5 listeners ---------------------------------------------------

    @Test
    void aListenerObservesAndPublishesNothing() throws Exception {
        AtomicBoolean observed = new AtomicBoolean();
        ReactorServeOptions options = baseOptions(FIXED)
                .listener(event -> observed.set(true))
                .build();
        try (ReactorServer server = ReactorServer.reactorServe(options)) {
            deliver(server, eventBody("token_pre_issue"));
        }
        assertTrue(observed.get());
        assertEquals(0, published.size(), "a listener MUST NOT publish a reply");
    }

    @Test
    void handlerAndListenerAreMutuallyExclusiveAndOneIsRequired() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                () -> baseOptions(FIXED).build());
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                () -> baseOptions(FIXED)
                        .handler(event -> ReactorDecision.allow())
                        .listener(event -> { })
                        .build());
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                () -> ReactorServeOptions.builder(channel, tenantId, Sensitive.of(subkeyHex))
                        .handler(event -> ReactorDecision.allow())
                        .build());
    }

    // ---- §18 deterministic shutdown ----------------------------------------

    @Test
    void closeCancelsTheConsumerDrainsInFlightWorkAndIsIdempotent() throws Exception {
        CountDownLatch handlerEntered = new CountDownLatch(1);
        CountDownLatch releaseHandler = new CountDownLatch(1);

        ReactorServer server = serve(event -> {
            handlerEntered.countDown();
            try {
                releaseHandler.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return ReactorDecision.allow();
        });

        byte[] body = eventBody("login_post_auth");
        Thread worker = new Thread(() -> {
            try {
                deliver(server, body);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        worker.start();
        assertTrue(handlerEntered.await(5, TimeUnit.SECONDS));
        assertEquals(1, server.inFlight());

        Thread closer = new Thread(server::close);
        closer.start();
        Thread.sleep(50);
        releaseHandler.countDown();
        closer.join(5_000);
        worker.join(5_000);

        assertTrue(server.isClosed());
        assertEquals(0, server.inFlight(), "close() drains in-flight events (§18)");
        assertEquals(1, published.size(), "the in-flight event still got its reply");
        assertTrue(calls.stream().anyMatch(c -> c.method().equals("basicCancel")),
                "close() cancels the consumer so no new delivery starts");

        server.close(); // idempotent
        assertEquals(1, calls.stream().filter(c -> c.method().equals("basicCancel")).count());
    }

    @Test
    void aDeliveryArrivingAfterCloseIsRequeuedRatherThanAnswered() throws Exception {
        ReactorServer server = serve(event -> ReactorDecision.allow());
        server.close();
        deliver(server, eventBody("login_post_auth"));

        assertEquals(0, published.size());
        Call nack = call("basicNack");
        assertTrue((boolean) nack.args()[2], "requeue: the next runtime to attach is entitled to it");
    }

    // ---- §19 telemetry -----------------------------------------------------

    @Test
    void onePairOfTelemetryEventsIsEmittedPerDispatch() throws Exception {
        List<TelemetryEvent> events = new ArrayList<>();
        ReactorServeOptions options = baseOptions(FIXED)
                .handler(event -> ReactorDecision.allow())
                .telemetryHook(events::add)
                .build();
        try (ReactorServer server = ReactorServer.reactorServe(options)) {
            deliver(server, eventBody("login_post_auth"));
        }

        assertEquals(2, events.size());
        TelemetryEvent.RequestStart start = (TelemetryEvent.RequestStart) events.get(0);
        assertEquals("reactorServe", start.operation());
        assertEquals("AMQP", start.method());
        assertEquals(ReactorEvents.LOGIN_POST_AUTH, start.pathTemplate(),
                "the path template is the event name — a closed set of five, never a UUID");
        TelemetryEvent.RequestEnd end = (TelemetryEvent.RequestEnd) events.get(1);
        assertEquals(TelemetryEvent.Outcome.SUCCESS, end.outcome());
    }

    @Test
    void aTelemetryHookThatThrowsCannotFailTheDispatch() throws Exception {
        ReactorServeOptions options = baseOptions(FIXED)
                .handler(event -> ReactorDecision.allow())
                .telemetryHook(event -> {
                    throw new IllegalStateException("metrics backend down");
                })
                .build();
        try (ReactorServer server = ReactorServer.reactorServe(options)) {
            deliver(server, eventBody("login_post_auth"));
        }
        assertEquals(1, published.size(), "telemetry is not permitted to fail a dispatch");
    }

    // ---- §22.12 the signing key is never logged ----------------------------

    @Test
    void theSigningKeyNeverAppearsInAnyLogLineOrErrorPayload() throws Exception {
        try (ReactorServer server = serve(event -> {
            throw new IllegalStateException("boom");
        })) {
            deliver(server, eventBody("login_post_auth"));
            deliver(server, tamper(body -> body.put("key_version", 1)));
            deliver(server, "not json".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }

        assertFalse(logLines.isEmpty(), "the rejections above must be reported");
        for (String line : logLines) {
            assertFalse(line.contains(subkeyHex), "a log line leaked the signing key: " + line);
            assertFalse(line.toLowerCase(java.util.Locale.ROOT).contains("alice"),
                    "the payload is tenant business data and is never logged: " + line);
        }
        assertEquals("[SENSITIVE]", Sensitive.of(subkeyHex).toString());
    }

    @Test
    void anEventsToStringCarriesNoPayload() throws Exception {
        AtomicReference<String> rendered = new AtomicReference<>();
        try (ReactorServer server = serve(event -> {
            rendered.set(event.toString());
            return ReactorDecision.allow();
        })) {
            deliver(server, eventBody("token_pre_issue"));
        }
        assertFalse(rendered.get().contains("alice"));
        assertTrue(rendered.get().contains(ReactorEvents.TOKEN_PRE_ISSUE));
    }

    // ---- chained events ----------------------------------------------------

    @Test
    void anEarlierReactorsPatchIsSurfacedAsReadOnlyContext() throws Exception {
        ObjectNode payload = ReactorVectors.MAPPER.createObjectNode();
        payload.put("sub", "alice");
        payload.putObject(ReactorEvent.REACTOR_PATCH_KEY).put("ext.department", "eng");

        AtomicReference<Map<String, String>> prior = new AtomicReference<>();
        try (ReactorServer server = serve(event -> {
            prior.set(event.priorPatch());
            return ReactorDecision.allow();
        })) {
            deliver(server, signedEvent(ReactorEvents.TOKEN_PRE_ISSUE, UUID.randomUUID(), NOW, payload));
        }
        assertEquals(Map.of("ext.department", "eng"), prior.get());
    }

    // ---- helpers -----------------------------------------------------------

    private void assertHandlerNeverRuns(byte[] body) throws Exception {
        AtomicBoolean ran = new AtomicBoolean();
        published.clear();
        try (ReactorServer server = serve(event -> {
            ran.set(true);
            return ReactorDecision.allow();
        })) {
            deliver(server, body);
        }
        assertFalse(ran.get(), "the handler must be structurally unreachable for a refused event");
        assertEquals(0, published.size(), "and nothing is published");
    }

    private ReactorServer serve(ReactorHandler handler) throws Exception {
        return serve(handler, FIXED);
    }

    private ReactorServer serve(ReactorHandler handler, Clock clock) throws Exception {
        return ReactorServer.reactorServe(baseOptions(clock).handler(handler).build());
    }

    private ReactorServeOptions.Builder baseOptions(Clock clock) {
        return ReactorServeOptions.builder(channel, tenantId, Sensitive.of(subkeyHex))
                .reactorId(reactorId)
                .logger(logger)
                .clock(clock)
                .shutdownGrace(Duration.ofSeconds(5));
    }

    private void deliver(ReactorServer server, byte[] body) throws Exception {
        DeliverCallback callback = server.deliverCallback();
        Envelope envelope = new Envelope(1L, false, ReactorProtocol.EXCHANGE,
                ReactorProtocol.routingKey(tenantId, ReactorEvents.TOKEN_PRE_ISSUE));
        AMQP.BasicProperties props = new AMQP.BasicProperties.Builder()
                .replyTo(REPLY_QUEUE)
                .correlationId(ReactorVectors.correlationId(fixture).toString())
                .build();
        callback.handle("consumer-tag", new Delivery(envelope, props, body));
    }

    private byte[] eventBody(String vectorName) throws Exception {
        return ReactorVectors.wireBody(fixture.get("server_to_reactor").get(vectorName));
    }

    /** Re-signs a token.pre_issue event with a fresh nonce/timestamp/payload. */
    private byte[] signedEvent(String event, UUID nonce, Instant issuedAt) throws Exception {
        return signedEvent(event, nonce, issuedAt,
                ReactorVectors.MAPPER.createObjectNode().put("sub", "alice"));
    }

    private byte[] signedEvent(String event, UUID nonce, Instant issuedAt, ObjectNode payload)
            throws Exception {
        return signEventNode(subkey, tenantId, event, nonce, issuedAt, payload);
    }

    private byte[] signedEventForTenant(UUID otherTenant) throws Exception {
        // Signed with a key that verifies here, but naming a tenant this runtime
        // does not serve. The tenant gate is what refuses it — which is the gate
        // worth having, because a signature check alone would let it through.
        return signEventNode(subkey, otherTenant, ReactorEvents.TOKEN_PRE_ISSUE, UUID.randomUUID(),
                NOW, ReactorVectors.MAPPER.createObjectNode().put("sub", "alice"));
    }

    private static byte[] signEventNode(byte[] key, UUID tenant, String event, UUID nonce,
                                        Instant issuedAt, ObjectNode payload) throws Exception {
        ObjectNode node = ReactorVectors.MAPPER.createObjectNode();
        node.put("tenant_id", tenant.toString());
        node.put("event", event);
        node.put("correlation_id", UUID.randomUUID().toString());
        node.set("payload", payload);
        node.put("timeout_ms", 500);
        node.put("key_version", 2);
        node.put("nonce", nonce.toString());
        node.put("issued_at", java.time.format.DateTimeFormatter.ISO_INSTANT.format(
                issuedAt.truncatedTo(java.time.temporal.ChronoUnit.SECONDS)));
        node.putNull("hmac_signature");

        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
        String hex = HexFormat.of().formatHex(
                mac.doFinal(ReactorVectors.MAPPER.writeValueAsBytes(node)));
        node.put("hmac_signature", hex);
        return ReactorVectors.MAPPER.writeValueAsBytes(node);
    }

    private byte[] tamper(java.util.function.Consumer<ObjectNode> mutation) throws Exception {
        JsonNode vector = fixture.get("server_to_reactor").get("token_pre_issue");
        ObjectNode node = ReactorVectors.canonicalNode(vector);
        node.put("hmac_signature", vector.get("hmac_signature_hex").asText());
        mutation.accept(node);
        return ReactorVectors.MAPPER.writeValueAsBytes(node);
    }

    private boolean acked() {
        return calls.stream().anyMatch(c -> c.method().equals("basicAck"));
    }

    private Call call(String method) {
        return calls.stream().filter(c -> c.method().equals(method)).findFirst()
                .orElseThrow(() -> new AssertionError("no " + method + " call was recorded"));
    }

    /** A clock a handler can move forward, to close a window without sleeping. */
    private static final class MovingClock extends Clock {
        private Instant now;

        MovingClock(Instant start) {
            this.now = start;
        }

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private static Channel fakeChannel(List<Call> calls, List<byte[]> published) {
        InvocationHandler handler = (proxy, method, args) -> {
            switch (method.getName()) {
                case "toString":
                    return "fakeChannel";
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "equals":
                    return proxy == args[0];
                default:
                    break;
            }
            calls.add(new Call(method.getName(), args));
            if ("basicPublish".equals(method.getName())) {
                published.add((byte[]) args[args.length - 1]);
                return null;
            }
            if ("basicConsume".equals(method.getName())) {
                return "consumer-tag";
            }
            return defaultReturnValue(method.getReturnType());
        };
        return (Channel) Proxy.newProxyInstance(
                Channel.class.getClassLoader(), new Class<?>[]{Channel.class}, handler);
    }

    private static Logger fakeLogger(List<String> lines) {
        InvocationHandler handler = (proxy, method, args) -> {
            String name = method.getName();
            if (("warn".equals(name) || "debug".equals(name) || "error".equals(name) || "info".equals(name))
                    && args != null && args.length > 0 && args[0] instanceof String) {
                lines.add(formatSlf4j(args));
                return null;
            }
            switch (name) {
                case "toString":
                    return "fakeLogger";
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "equals":
                    return proxy == args[0];
                default:
                    return defaultReturnValue(method.getReturnType());
            }
        };
        return (Logger) Proxy.newProxyInstance(
                Logger.class.getClassLoader(), new Class<?>[]{Logger.class}, handler);
    }

    private static String formatSlf4j(Object[] args) {
        String template = (String) args[0];
        StringBuilder out = new StringBuilder();
        int argIndex = 1;
        int cursor = 0;
        while (true) {
            int placeholder = template.indexOf("{}", cursor);
            if (placeholder < 0 || argIndex >= args.length) {
                out.append(template, cursor, template.length());
                break;
            }
            out.append(template, cursor, placeholder).append(args[argIndex++]);
            cursor = placeholder + 2;
        }
        for (int i = argIndex; i < args.length; i++) {
            out.append(' ').append(args[i]);
        }
        return out.toString();
    }

    private static Object defaultReturnValue(Class<?> type) {
        if (!type.isPrimitive() || type == void.class) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == int.class) {
            return 0;
        }
        return 0;
    }
}
