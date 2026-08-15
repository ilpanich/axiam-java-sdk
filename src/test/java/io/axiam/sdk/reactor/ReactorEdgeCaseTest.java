package io.axiam.sdk.reactor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Delivery;
import com.rabbitmq.client.Envelope;
import io.axiam.sdk.Sensitive;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The refusal paths and the configuration surface: every malformed reactor body
 * the runtime can be handed, and every builder knob it can be built with.
 *
 * <p>These are separated from {@link ReactorServerTest} because they prove a
 * different claim. That class proves the &sect;22 pipeline does the right thing
 * with a well-formed event; this one proves nothing gets through when the event
 * is not well-formed — which is the half a reactor runtime is judged on, since
 * a hole here is a hole in the authorization server it is attached to.
 */
class ReactorEdgeCaseTest {

    private static final Instant NOW = Instant.parse("2026-07-10T12:00:00Z");
    private static final Clock FIXED = Clock.fixed(NOW, ZoneOffset.UTC);

    private JsonNode fixture;
    private byte[] subkey;
    private String subkeyHex;
    private UUID tenantId;
    private UUID reactorId;
    private List<String> methods;
    private List<byte[]> published;
    private Channel channel;
    private List<String> logLines;
    private Logger logger;

    @BeforeEach
    void setUp() throws Exception {
        fixture = ReactorVectors.load();
        subkey = ReactorVectors.subkey(fixture);
        subkeyHex = fixture.get("hkdf").get("derived_subkey_hex").asText();
        tenantId = ReactorVectors.tenantId(fixture);
        reactorId = UUID.fromString(fixture.get("reactor_id").asText());
        methods = new ArrayList<>();
        published = new ArrayList<>();
        channel = fakeChannel(methods, published);
        logLines = new ArrayList<>();
        logger = fakeLogger(logLines);
    }

    // ---- every malformed body is refused, and none reaches a handler -------

    @Test
    void everyMalformedBodyIsRefusedBeforeTheHandler() throws Exception {
        assertRefused("not json at all".getBytes(StandardCharsets.UTF_8));
        assertRefused("[1,2,3]".getBytes(StandardCharsets.UTF_8));
        assertRefused(mutated(node -> node.remove("key_version")));
        assertRefused(mutated(node -> node.put("key_version", "two")));
        assertRefused(resigned(node -> node.remove("issued_at")));
        assertRefused(resigned(node -> node.put("issued_at", "the day before yesterday")));
        assertRefused(resigned(node -> node.remove("nonce")));
        assertRefused(resigned(node -> node.put("nonce", "not-a-uuid")));
        assertRefused(resigned(node -> node.put("tenant_id", "not-a-uuid")));
        assertRefused(resigned(node -> node.put("correlation_id", "not-a-uuid")));
        assertRefused(resigned(node -> node.put("event", "")));
        assertRefused(resigned(node -> node.remove("event")));
        assertRefused(resigned(node -> node.put("payload", "a string is not a payload")));
        assertRefused(resigned(node -> node.remove("payload")));
        assertRefused(resigned(node -> node.put("timeout_ms", 0)));
        assertRefused(resigned(node -> node.remove("timeout_ms")));

        assertFalse(logLines.isEmpty(), "every refusal is reported");
        for (String line : logLines) {
            assertTrue(line.contains("axiam_sdk_security"), "as a security event: " + line);
            assertFalse(line.contains(subkeyHex), "and never carrying the key");
        }
    }

    @Test
    void aDeliveryWithNoReplyToPublishesNothing() throws Exception {
        try (ReactorServer server = serve(event -> ReactorDecision.allow())) {
            AMQP.BasicProperties noReplyTo = new AMQP.BasicProperties.Builder().build();
            server.deliverCallback().handle("tag", new Delivery(envelope(), noReplyTo, eventBody()));
        }
        assertEquals(0, published.size(), "there is nowhere to answer, so nothing is published");
        assertTrue(methods.contains("basicAck"), "and the delivery is still settled");
    }

    @Test
    void aHandlerReturningNullProducesNoReply() throws Exception {
        try (ReactorServer server = serve(event -> null)) {
            deliver(server, eventBody());
        }
        assertEquals(0, published.size());
    }

    @Test
    void theTimeoutIsClampedToTheChainCeiling() throws Exception {
        byte[] body = ReactorServerTestSupport.signEvent(subkey, tenantId,
                ReactorEvents.TOKEN_PRE_ISSUE, UUID.randomUUID(), NOW, 60_000);
        java.util.concurrent.atomic.AtomicInteger seen = new java.util.concurrent.atomic.AtomicInteger();
        try (ReactorServer server = serve(event -> {
            seen.set(event.timeoutMs());
            return ReactorDecision.allow();
        })) {
            deliver(server, body);
        }
        assertEquals(ReactorProtocol.CHAIN_CEILING_MS, seen.get(),
                "no dispatch outlives the chain's 5 000 ms wall-clock ceiling");
    }

    // ---- the event's own surface ------------------------------------------

    @Test
    void anEventExposesItsSignedEnvelopeAndItsRegistrySpec() throws Exception {
        java.util.concurrent.atomic.AtomicReference<ReactorEvent> seen =
                new java.util.concurrent.atomic.AtomicReference<>();
        try (ReactorServer server = serve(event -> {
            seen.set(event);
            return ReactorDecision.allow();
        })) {
            deliver(server, eventBody());
        }

        ReactorEvent event = seen.get();
        assertEquals(2, event.keyVersion());
        assertEquals(UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), event.nonce());
        assertEquals(NOW, event.issuedAt());
        assertEquals(NOW.plusMillis(500), event.deadline());
        assertEquals(Duration.ZERO, event.remaining(NOW.plusSeconds(10)),
                "a closed window reports zero remaining, never a negative duration");
        ReactorEventSpec spec = event.spec();
        assertNotNull(spec);
        assertEquals(ReactorEvents.TOKEN_PRE_ISSUE, spec.name());
        assertTrue(spec.mutable());
    }

    @Test
    void aPriorPatchWithNonStringValuesIsIgnoredRatherThanCoerced() throws Exception {
        ObjectNode payload = ReactorVectors.MAPPER.createObjectNode();
        ObjectNode prior = payload.putObject(ReactorEvent.REACTOR_PATCH_KEY);
        prior.put("ext.department", "eng");
        prior.put("ext.headcount", 12);
        byte[] body = ReactorServerTestSupport.signEvent(subkey, tenantId,
                ReactorEvents.TOKEN_PRE_ISSUE, UUID.randomUUID(), NOW, 500, payload);

        java.util.concurrent.atomic.AtomicReference<Map<String, String>> seen =
                new java.util.concurrent.atomic.AtomicReference<>();
        try (ReactorServer server = serve(event -> {
            seen.set(event.priorPatch());
            return ReactorDecision.allow();
        })) {
            deliver(server, body);
        }
        assertEquals(Map.of("ext.department", "eng"), seen.get(),
                "the patch is string→string; a non-string value is not a patch entry");
    }

    // ---- the protocol's own edges -----------------------------------------

    @Test
    void canonicalEventBytesRewritesTheSignatureToNullInPlace() throws Exception {
        JsonNode vector = fixture.get("server_to_reactor").get("token_pre_issue");
        byte[] canonical = ReactorProtocol.canonicalEventBytes(ReactorVectors.wireBody(vector));
        assertEquals(vector.get("canonical_signed_json").asText(),
                new String(canonical, StandardCharsets.UTF_8),
                "the signature field keeps its position and becomes null");
    }

    @Test
    void malformedBodiesFailVerificationRatherThanThrowing() {
        assertFalse(ReactorProtocol.verifyEvent(subkey, "{".getBytes(StandardCharsets.UTF_8)));
        assertFalse(ReactorProtocol.verifyEvent(subkey, "[]".getBytes(StandardCharsets.UTF_8)));
        assertFalse(ReactorProtocol.verifyEvent(subkey, "{}".getBytes(StandardCharsets.UTF_8)));
        assertFalse(ReactorProtocol.verifyEvent(subkey,
                "{\"hmac_signature\":null}".getBytes(StandardCharsets.UTF_8)));
        assertFalse(ReactorProtocol.verifyEvent(subkey,
                "{\"hmac_signature\":\"zz\"}".getBytes(StandardCharsets.UTF_8)));
        assertFalse(ReactorProtocol.verifyEvent(subkey,
                "{\"hmac_signature\":7}".getBytes(StandardCharsets.UTF_8)));

        assertThrows(IllegalArgumentException.class,
                () -> ReactorProtocol.canonicalEventBytes("nope".getBytes(StandardCharsets.UTF_8)));
        assertThrows(IllegalArgumentException.class,
                () -> ReactorProtocol.canonicalEventBytes("[]".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void anUnusableSigningKeyFailsLoudlyRatherThanSigningWithSomethingElse() {
        assertThrows(IllegalArgumentException.class, () -> ReactorProtocol.signedReply(
                new byte[0], UUID.randomUUID(), tenantId, ReactorEvents.LOGIN_POST_AUTH,
                ReactorDecision.allow(), UUID.randomUUID(), NOW));
    }

    @Test
    void patchKeysAreOrderedByUtf8BytesIncludingThePrefixCase() {
        // "ext.a" is a prefix of "ext.ab": the shorter sorts first, which is the
        // length-difference arm of the byte comparator.
        String json = new String(ReactorProtocol.canonicalReplyBytes(
                UUID.randomUUID(), tenantId, ReactorEvents.TOKEN_PRE_ISSUE,
                ReactorDecision.mutate(Map.of("ext.ab", "2", "ext.a", "1", "ext.b", "3")),
                UUID.randomUUID(), NOW), StandardCharsets.UTF_8);
        assertTrue(json.contains("\"patch\":{\"ext.a\":\"1\",\"ext.ab\":\"2\",\"ext.b\":\"3\"}"), json);
    }

    @Test
    void anEmptyMutationIsRefusedAtConstructionRatherThanOnTheWire() {
        assertThrows(IllegalArgumentException.class, () -> ReactorDecision.mutate(Map.of()));
    }

    // ---- the builder -------------------------------------------------------

    @Test
    void everyBuilderKnobIsHonouredAndValidated() throws Exception {
        ReactorServeOptions options = ReactorServeOptions
                .builder(channel, tenantId, Sensitive.of(subkeyHex))
                .queue("axiam.reactor.q.explicit")
                .handler(event -> ReactorDecision.allow())
                .logger(logger)
                .clock(FIXED)
                .freshnessSkew(Duration.ofSeconds(60))
                .shutdownGrace(Duration.ofSeconds(1))
                .prefetch(4)
                .telemetryHook(event -> { })
                .build();

        assertEquals("axiam.reactor.q.explicit", options.queue());
        assertEquals(tenantId, options.tenantId());
        assertEquals(Duration.ofSeconds(60), options.freshnessSkew());
        assertEquals(Duration.ofSeconds(1), options.shutdownGrace());
        assertEquals(4, options.prefetch());
        assertEquals(FIXED, options.clock());
        assertNotNull(options.handler());
        assertNull(options.listener());
        assertNotNull(options.telemetryHook());
        assertNotNull(options.logger());
        assertEquals(channel, options.channel());

        try (ReactorServer server = ReactorServer.reactorServe(options)) {
            assertEquals("axiam.reactor.q.explicit", server.queue());
            assertFalse(server.isClosed());
        }

        ReactorServeOptions.Builder builder =
                ReactorServeOptions.builder(channel, tenantId, Sensitive.of(subkeyHex));
        assertThrows(IllegalArgumentException.class, () -> builder.freshnessSkew(Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> builder.shutdownGrace(Duration.ofSeconds(-1)));
        assertThrows(IllegalArgumentException.class, () -> builder.prefetch(0));
        assertThrows(IllegalStateException.class, () -> builder
                .queue("q").reactorId(reactorId).handler(event -> ReactorDecision.allow()).build());
    }

    @Test
    void closingATornDownChannelStillCompletes() throws Exception {
        Channel exploding = (Channel) Proxy.newProxyInstance(
                Channel.class.getClassLoader(), new Class<?>[]{Channel.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "basicConsume" -> "tag";
                    case "basicCancel" -> throw new java.io.IOException("channel already closed");
                    case "toString" -> "explodingChannel";
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> null;
                });

        ReactorServer server = ReactorServer.reactorServe(
                ReactorServeOptions.builder(exploding, tenantId, Sensitive.of(subkeyHex))
                        .reactorId(reactorId)
                        .handler(event -> ReactorDecision.allow())
                        .logger(logger)
                        .clock(FIXED)
                        .build());
        server.close();
        assertTrue(server.isClosed(), "a broker that tore the channel down first is not a close failure");
    }

    // ---- helpers -----------------------------------------------------------

    private void assertRefused(byte[] body) throws Exception {
        published.clear();
        java.util.concurrent.atomic.AtomicBoolean ran = new java.util.concurrent.atomic.AtomicBoolean();
        try (ReactorServer server = serve(event -> {
            ran.set(true);
            return ReactorDecision.allow();
        })) {
            deliver(server, body);
        }
        assertFalse(ran.get(), "handler ran for a body it should never have seen");
        assertEquals(0, published.size(), "and something was published anyway");
    }

    private ReactorServer serve(ReactorHandler handler) throws Exception {
        return ReactorServer.reactorServe(
                ReactorServeOptions.builder(channel, tenantId, Sensitive.of(subkeyHex))
                        .reactorId(reactorId)
                        .handler(handler)
                        .logger(logger)
                        .clock(FIXED)
                        .shutdownGrace(Duration.ofSeconds(2))
                        .build());
    }

    private void deliver(ReactorServer server, byte[] body) throws Exception {
        server.deliverCallback().handle("tag", new Delivery(envelope(), replyProperties(), body));
    }

    private Envelope envelope() {
        return new Envelope(1L, false, ReactorProtocol.EXCHANGE,
                ReactorProtocol.routingKey(tenantId, ReactorEvents.TOKEN_PRE_ISSUE));
    }

    private static AMQP.BasicProperties replyProperties() {
        return new AMQP.BasicProperties.Builder().replyTo("reply.q").build();
    }

    private byte[] eventBody() throws Exception {
        return ReactorVectors.wireBody(fixture.get("server_to_reactor").get("token_pre_issue"));
    }

    /** Mutates the signed body without re-signing — the signature no longer matches. */
    private byte[] mutated(Consumer<ObjectNode> mutation) throws Exception {
        JsonNode vector = fixture.get("server_to_reactor").get("token_pre_issue");
        ObjectNode node = ReactorVectors.canonicalNode(vector);
        node.put("hmac_signature", vector.get("hmac_signature_hex").asText());
        mutation.accept(node);
        return ReactorVectors.MAPPER.writeValueAsBytes(node);
    }

    /**
     * Mutates the body and re-signs it, so the refusal below can only come from
     * the field check rather than from a broken MAC.
     */
    private byte[] resigned(Consumer<ObjectNode> mutation) throws Exception {
        ObjectNode node = ReactorVectors.canonicalNode(
                fixture.get("server_to_reactor").get("token_pre_issue"));
        mutation.accept(node);
        node.putNull("hmac_signature");
        return ReactorServerTestSupport.sign(subkey, node);
    }

    private static Channel fakeChannel(List<String> methods, List<byte[]> published) {
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
            methods.add(method.getName());
            if ("basicPublish".equals(method.getName())) {
                published.add((byte[]) args[args.length - 1]);
                return null;
            }
            if ("basicConsume".equals(method.getName())) {
                return "consumer-tag";
            }
            return method.getReturnType().isPrimitive() && method.getReturnType() != void.class
                    ? defaultPrimitive(method.getReturnType()) : null;
        };
        return (Channel) Proxy.newProxyInstance(
                Channel.class.getClassLoader(), new Class<?>[]{Channel.class}, handler);
    }

    private static Object defaultPrimitive(Class<?> type) {
        if (type == boolean.class) {
            return false;
        }
        if (type == long.class) {
            return 0L;
        }
        return 0;
    }

    private static Logger fakeLogger(List<String> lines) {
        InvocationHandler handler = (proxy, method, args) -> {
            String name = method.getName();
            if (("warn".equals(name) || "debug".equals(name) || "info".equals(name) || "error".equals(name))
                    && args != null && args.length > 0 && args[0] instanceof String template) {
                StringBuilder line = new StringBuilder(template);
                for (int i = 1; i < args.length; i++) {
                    line.append(' ').append(args[i]);
                }
                lines.add(line.toString());
                return null;
            }
            return switch (name) {
                case "toString" -> "fakeLogger";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> method.getReturnType() == boolean.class ? Boolean.FALSE : null;
            };
        };
        return (Logger) Proxy.newProxyInstance(
                Logger.class.getClassLoader(), new Class<?>[]{Logger.class}, handler);
    }
}
