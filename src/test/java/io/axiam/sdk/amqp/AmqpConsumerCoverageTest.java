package io.axiam.sdk.amqp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import com.rabbitmq.client.Delivery;
import com.rabbitmq.client.Envelope;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Coverage for the {@link AmqpConsumer} surface not already exercised by
 * {@link AmqpConsumerTest}/{@link ReplayProtectionTest}: the two
 * {@link AmqpConsumer#consume} registration overloads (proven against a fake
 * {@link Channel} without a live broker), the convenience 4-arg
 * {@link AmqpConsumer#deliverCallback} factory, the
 * {@link AmqpConsumer#configureAutomaticRecovery} helpers (D-13), and the
 * remaining NEW-4 replay-protection rejection reasons (missing / unparseable
 * {@code issued_at}, missing {@code nonce}).
 */
class AmqpConsumerCoverageTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String FIXTURE_PATH = "/v2_reference_vectors.json";

    private static final Instant FIXTURE_ISSUED_AT = Instant.parse("2026-07-10T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(FIXTURE_ISSUED_AT, ZoneOffset.UTC);

    // ---- consume(...) registration overloads --------------------------------

    @Test
    void consumeRegistersManualAckConsumerAndSetsQos() throws Exception {
        List<String> calls = new ArrayList<>();
        Channel channel = recordingChannel(calls);

        AmqpConsumer.consume(channel, "axiam.events", new byte[32], body -> { }, fakeLogger(new ArrayList<>()));

        assertTrue(calls.contains("basicQos:" + AmqpConsumer.DEFAULT_PREFETCH),
                "consume() must set the CF-03 default prefetch QoS");
        assertTrue(calls.stream().anyMatch(c -> c.startsWith("basicConsume:axiam.events:false")),
                "consume() must register a manual-ack (autoAck=false) consumer on the queue");
    }

    @Test
    void consumeWithExplicitClockSkewAlsoRegisters() throws Exception {
        List<String> calls = new ArrayList<>();
        Channel channel = recordingChannel(calls);

        AmqpConsumer.consume(channel, "axiam.audit", new byte[32], body -> { },
                fakeLogger(new ArrayList<>()), Duration.ofSeconds(120));

        assertTrue(calls.stream().anyMatch(c -> c.startsWith("basicConsume:axiam.audit:false")),
                "the clock-skew overload must still register a manual-ack consumer");
    }

    // ---- convenience 4-arg deliverCallback factory --------------------------

    @Test
    void fourArgDeliverCallbackIsUsableAndVerifiesBeforeHandler() throws Exception {
        List<AckNackCall> calls = new ArrayList<>();
        Channel channel = fakeChannel(calls);
        byte[] wrongKey = new byte[32]; // will not match the fixture signature

        AtomicInteger handlerInvocations = new AtomicInteger();
        DeliverCallback callback = AmqpConsumer.deliverCallback(
                channel, wrongKey, body -> handlerInvocations.incrementAndGet(), fakeLogger(new ArrayList<>()));

        JsonNode root = loadFixture();
        byte[] body = MAPPER.writeValueAsBytes(wireNode(root.get("authz_request")));
        callback.handle("tag", delivery(1L, body));

        assertEquals(0, handlerInvocations.get(), "an unverifiable body must never reach the handler");
        assertEquals(1, calls.size());
        assertEquals("nack", calls.get(0).type());
        assertFalse(calls.get(0).requeue(), "HMAC failure nacks without requeue");
    }

    // ---- configureAutomaticRecovery helpers (D-13) --------------------------

    @Test
    void configureAutomaticRecoveryAppliesExplicitInterval() {
        ConnectionFactory factory = new ConnectionFactory();
        AmqpConsumer.configureAutomaticRecovery(factory, Duration.ofSeconds(17));

        assertTrue(factory.isAutomaticRecoveryEnabled(), "automatic recovery must be left ON (D-13)");
        assertEquals(17_000L, factory.getNetworkRecoveryInterval(),
                "the explicit recovery interval must be applied (in millis)");
    }

    @Test
    void configureAutomaticRecoveryAppliesDefaultInterval() {
        ConnectionFactory factory = new ConnectionFactory();
        AmqpConsumer.configureAutomaticRecovery(factory);

        assertTrue(factory.isAutomaticRecoveryEnabled());
        assertEquals(AmqpConsumer.DEFAULT_NETWORK_RECOVERY_INTERVAL.toMillis(),
                factory.getNetworkRecoveryInterval(),
                "the no-interval overload must apply DEFAULT_NETWORK_RECOVERY_INTERVAL");
    }

    // ---- remaining NEW-4 replay-protection rejection reasons ----------------

    @Test
    void missingIssuedAtIsRejectedWithoutRequeue() throws Exception {
        assertRejectedAfterMutation(node -> node.remove("issued_at"));
    }

    @Test
    void unparseableIssuedAtIsRejectedWithoutRequeue() throws Exception {
        assertRejectedAfterMutation(node -> node.put("issued_at", "not-a-timestamp"));
    }

    @Test
    void missingNonceIsRejectedWithoutRequeue() throws Exception {
        assertRejectedAfterMutation(node -> node.remove("nonce"));
    }

    /**
     * Applies {@code mutation} to a copy of the real v2 authz_request wire
     * node, re-signs it with the fixture subkey (so the HMAC verifies and the
     * rejection is attributable purely to the NEW-4 check), delivers it, and
     * asserts the handler never ran and the message was nacked without requeue
     * with a security event logged.
     */
    private void assertRejectedAfterMutation(java.util.function.Consumer<ObjectNode> mutation) throws Exception {
        JsonNode root = loadFixture();
        byte[] subkey = subkey(root);
        ObjectNode message = wireNode(root.get("authz_request"));
        mutation.accept(message);
        sign(message, subkey);
        byte[] body = MAPPER.writeValueAsBytes(message);

        List<AckNackCall> calls = new ArrayList<>();
        Channel channel = fakeChannel(calls);
        List<String> warnings = new ArrayList<>();
        NonceStore nonceStore = new NonceStore(Duration.ofSeconds(600));

        AtomicInteger handlerInvocations = new AtomicInteger();
        DeliverCallback callback = AmqpConsumer.deliverCallback(
                channel, subkey, b -> handlerInvocations.incrementAndGet(), fakeLogger(warnings),
                Duration.ofSeconds(300), FIXED_CLOCK, nonceStore);

        callback.handle("tag", delivery(2L, body));

        assertEquals(0, handlerInvocations.get(), "a NEW-4 rejection must never reach the handler");
        assertEquals(1, calls.size());
        AckNackCall call = calls.get(0);
        assertEquals("nack", call.type());
        assertFalse(call.requeue(), "a NEW-4 rejection must nack WITHOUT requeue");
        assertFalse(warnings.isEmpty(), "a security event must be logged on rejection");
    }

    // ---- fixtures / doubles -------------------------------------------------

    private record AckNackCall(String type, long deliveryTag, boolean multiple, boolean requeue) {
    }

    private static JsonNode loadFixture() throws Exception {
        try (InputStream in = AmqpConsumerCoverageTest.class.getResourceAsStream(FIXTURE_PATH)) {
            if (in == null) {
                throw new IllegalStateException("fixture not found on classpath: " + FIXTURE_PATH);
            }
            return MAPPER.readTree(in);
        }
    }

    private static byte[] subkey(JsonNode root) {
        return HexFormat.of().parseHex(root.get("hkdf").get("derived_subkey_hex").asText());
    }

    private static ObjectNode wireNode(JsonNode vector) throws Exception {
        String canonicalSignedJson = vector.get("canonical_signed_json").asText();
        ObjectNode node = (ObjectNode) MAPPER.readTree(canonicalSignedJson);
        node.put("hmac_signature", vector.get("hmac_signature_hex").asText());
        return node;
    }

    private static void sign(ObjectNode node, byte[] key) throws Exception {
        node.remove("hmac_signature");
        byte[] canonical = MAPPER.writeValueAsBytes(node);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        node.put("hmac_signature", HexFormat.of().formatHex(mac.doFinal(canonical)));
    }

    private static Delivery delivery(long deliveryTag, byte[] body) {
        Envelope envelope = new Envelope(deliveryTag, false, "axiam.authz.request", "authz.request");
        AMQP.BasicProperties properties = new AMQP.BasicProperties.Builder().build();
        return new Delivery(envelope, properties, body);
    }

    /** Fake channel that records ack/nack calls (for deliverCallback tests). */
    private static Channel fakeChannel(List<AckNackCall> calls) {
        InvocationHandler handler = (proxy, method, args) -> {
            switch (method.getName()) {
                case "basicAck":
                    calls.add(new AckNackCall("ack", (long) args[0], (boolean) args[1], false));
                    return null;
                case "basicNack":
                    calls.add(new AckNackCall("nack", (long) args[0], (boolean) args[1], (boolean) args[2]));
                    return null;
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "equals":
                    return proxy == args[0];
                default:
                    return defaultReturnValue(method.getReturnType());
            }
        };
        return (Channel) Proxy.newProxyInstance(
                Channel.class.getClassLoader(), new Class<?>[]{Channel.class}, handler);
    }

    /** Fake channel that records basicQos/basicConsume registration calls (for consume() tests). */
    private static Channel recordingChannel(List<String> calls) {
        InvocationHandler handler = (proxy, method, args) -> {
            switch (method.getName()) {
                case "basicQos":
                    calls.add("basicQos:" + args[0]);
                    return null;
                case "basicConsume":
                    calls.add("basicConsume:" + args[0] + ":" + args[1]);
                    return "consumer-tag";
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "equals":
                    return proxy == args[0];
                default:
                    return defaultReturnValue(method.getReturnType());
            }
        };
        return (Channel) Proxy.newProxyInstance(
                Channel.class.getClassLoader(), new Class<?>[]{Channel.class}, handler);
    }

    private static Logger fakeLogger(List<String> warnings) {
        InvocationHandler handler = (proxy, method, args) -> {
            if ("warn".equals(method.getName()) && args != null && args.length > 0 && args[0] instanceof String) {
                warnings.add((String) args[0]);
                return null;
            }
            switch (method.getName()) {
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "equals":
                    return proxy == args[0];
                case "getName":
                    return "fakeLogger";
                default:
                    return defaultReturnValue(method.getReturnType());
            }
        };
        return (Logger) Proxy.newProxyInstance(
                Logger.class.getClassLoader(), new Class<?>[]{Logger.class}, handler);
    }

    private static Object defaultReturnValue(Class<?> returnType) {
        if (!returnType.isPrimitive()) {
            return null;
        }
        if (returnType == boolean.class) {
            return true;
        }
        if (returnType == void.class) {
            return null;
        }
        return 0;
    }
}
