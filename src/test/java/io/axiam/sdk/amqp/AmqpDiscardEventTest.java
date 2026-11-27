package io.axiam.sdk.amqp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DeliverCallback;
import com.rabbitmq.client.Delivery;
import com.rabbitmq.client.Envelope;

import io.axiam.sdk.amqp.AmqpTestDoubles.AckNack;
import io.axiam.sdk.amqp.AuthzRequester.ResponseDelivery;
import io.axiam.sdk.amqp.AuthzRequester.ResponseSink;
import io.axiam.sdk.amqp.AuthzRequester.Transport;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;8 (contract 1.69; D-8, D-9, D-10): the typed event consumer, the one discard event with its
 * normative reason order, and the rule that no body escapes either AMQP consumer.
 */
class AmqpDiscardEventTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-07-10T12:00:00Z"), ZoneOffset.UTC);
    /** The consumer's own tenant: deliberately NOT the tenant the fixture's bodies carry. */
    private static final String OWN_TENANT = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    private static final byte[] BOM = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};

    private static JsonNode fixture() throws Exception {
        try (InputStream in = AmqpDiscardEventTest.class.getResourceAsStream("/v2_reference_vectors.json")) {
            return MAPPER.readTree(in);
        }
    }

    private static byte[] subkey() throws Exception {
        return HexFormat.of().parseHex(fixture().get("hkdf").get("derived_subkey_hex").asText());
    }

    private static String wire(String vector) throws Exception {
        return fixture().get(vector).get("wire_json").asText();
    }

    private static byte[] signed(String canonical) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(subkey(), "HmacSHA256"));
        String sig = HexFormat.of().formatHex(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
        return (canonical.substring(0, canonical.length() - 1) + ",\"hmac_signature\":\"" + sig + "\"}")
                .getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] withBom(byte[] body) {
        byte[] out = new byte[BOM.length + body.length];
        System.arraycopy(BOM, 0, out, 0, BOM.length);
        System.arraycopy(body, 0, out, BOM.length, body.length);
        return out;
    }

    /** Flips the last hex digit of the trailing signature. */
    private static String withChangedSignatureDigit(String wire) {
        int i = wire.length() - 3;
        char c = wire.charAt(i);
        return wire.substring(0, i) + (c == '0' ? '1' : '0') + wire.substring(i + 1);
    }

    private static final class Harness {
        final List<AckNack> calls = new ArrayList<>();
        final List<byte[]> seen = new ArrayList<>();
        final List<String> warnings = new ArrayList<>();
        final DeliverCallback callback;

        Harness(EventType type) throws Exception {
            Channel channel = AmqpTestDoubles.recordingChannel(calls);
            Logger logger = AmqpTestDoubles.recordingLogger(warnings);
            callback = AmqpConsumer.deliverCallback(channel, type, OWN_TENANT, subkey(), seen::add, logger,
                    Duration.ofSeconds(300), CLOCK, new NonceStore(Duration.ofSeconds(600)));
        }

        void deliver(byte[] body) throws Exception {
            callback.handle("tag", new Delivery(new Envelope(calls.size() + 1L, false, "axiam.events", "events.rk"),
                    new AMQP.BasicProperties.Builder().build(), body));
        }

        /** The reason of the single discard event the last delivery produced. */
        String lastReason() {
            String line = warnings.get(warnings.size() - 1);
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("reason=(\\w+)").matcher(line);
            assertTrue(m.find(), line);
            return m.group(1);
        }

        void assertDiscarded(String reason, byte[] body) throws Exception {
            int events = warnings.size();
            int nacks = calls.size();
            deliver(body);
            assertEquals(events + 1, warnings.size(), reason + ": exactly one event per discard");
            assertEquals(reason, lastReason());
            assertEquals(nacks + 1, calls.size());
            AckNack last = calls.get(calls.size() - 1);
            assertEquals("nack", last.type(), reason);
            assertFalse(last.requeue(), reason);
            assertTrue(seen.isEmpty(), reason + ": the handler must never run");
        }
    }

    // ---- D-9: typed consume --------------------------------------------------------------------------

    @Test
    void anotherTypesGenuineWireJsonIsMalformedAtTheTypedCheck_evenWithAChangedSignatureDigit() throws Exception {
        Harness authzConsumer = new Harness(EventType.AUTHZ_REQUEST);
        authzConsumer.assertDiscarded("malformed", bytes(wire("audit_event")));
        authzConsumer.assertDiscarded("malformed", bytes(withChangedSignatureDigit(wire("audit_event"))));

        Harness auditConsumer = new Harness(EventType.AUDIT_EVENT);
        auditConsumer.assertDiscarded("malformed", bytes(wire("authz_request")));
        auditConsumer.assertDiscarded("malformed", bytes(withChangedSignatureDigit(wire("authz_request"))));
    }

    @Test
    void eachConsumerStillAcceptsItsOwnTypesWireJson() throws Exception {
        Harness authzConsumer = new Harness(EventType.AUTHZ_REQUEST);
        authzConsumer.deliver(bytes(wire("authz_request")));
        assertEquals(1, authzConsumer.seen.size());
        assertArrayEquals(bytes(fixture().get("authz_request").get("canonical_signed_json").asText()),
                authzConsumer.seen.get(0));
        Harness auditConsumer = new Harness(EventType.AUDIT_EVENT);
        auditConsumer.deliver(bytes(wire("audit_event")));
        assertEquals(1, auditConsumer.seen.size());
        assertTrue(authzConsumer.warnings.isEmpty() && auditConsumer.warnings.isEmpty());
    }

    // ---- D-8: the discard event ----------------------------------------------------------------------

    @Test
    void theEventCarriesExchangeRoutingKeyAndTheConfiguredTenantAndNoSignatureOrNonce() throws Exception {
        String wire = wire("authz_request");
        String signature = fixture().get("authz_request").get("hmac_signature_hex").asText();
        String nonce = "55555555-5555-5555-5555-555555555555";
        String bodyTenant = "11111111-1111-1111-1111-111111111111";
        record Case(byte[] body, String reason) { }
        for (Case c : List.of(
                new Case(bytes(wire("audit_event")), "malformed"),
                new Case(bytes(wire.substring(0, wire.indexOf(",\"hmac_signature\"")) + "}"), "unsigned"),
                new Case(bytes(withChangedSignatureDigit(wire)), "signature"))) {
            byte[] body = c.body();
            Harness h = new Harness(EventType.AUTHZ_REQUEST);
            h.deliver(body);
            assertEquals(1, h.warnings.size());
            String line = h.warnings.get(0);
            assertTrue(line.contains("exchange=axiam.events"), line);
            assertTrue(line.contains("routing_key=events.rk"), line);
            assertTrue(line.contains("tenant_id=" + OWN_TENANT), line);
            assertTrue(line.contains("timestamp=2026-07-10T12:00:00Z"), line);
            assertTrue(line.endsWith("reason=" + c.reason() + ")"), c.reason() + ": " + line);
            assertFalse(line.contains(bodyTenant), "tenant_id is never read from the body: " + line);
            assertFalse(line.contains(signature), line);
            assertFalse(line.contains(nonce), line);
            assertFalse(line.contains(wire.substring(wire.length() - 20)), line);
        }
    }

    @Test
    @SuppressWarnings("deprecation")
    void typedVerifyReturnsTheCanonicalBytesOfItsTypeOnly_andTheUntypedOneAcceptsEither() throws Exception {
        byte[] authz = bytes(wire("authz_request"));
        assertArrayEquals(bytes(fixture().get("authz_request").get("canonical_signed_json").asText()),
                Hmac.verify(subkey(), authz, EventType.AUTHZ_REQUEST));
        assertEquals(null, Hmac.verify(subkey(), authz, EventType.AUDIT_EVENT));
        assertEquals(null, Hmac.verify(subkey(), bytes(withChangedSignatureDigit(wire("audit_event"))),
                EventType.AUDIT_EVENT));
        assertEquals(null, Hmac.verify(subkey(), withBom(authz), EventType.AUTHZ_REQUEST));
        assertTrue(Hmac.verify(subkey(), authz));
        assertTrue(Hmac.verify(subkey(), bytes(wire("audit_event"))));
    }

    @Test
    void anEmptyRoutingKeyAndExchangeAreReportedAsEmpty() throws Exception {
        List<AckNack> calls = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        DeliverCallback cb = AmqpConsumer.deliverCallback(AmqpTestDoubles.recordingChannel(calls),
                EventType.AUTHZ_REQUEST, OWN_TENANT, subkey(), b -> { }, AmqpTestDoubles.recordingLogger(warnings),
                Duration.ofSeconds(300), CLOCK, new NonceStore(Duration.ofSeconds(600)), "the-queue");
        cb.handle("tag", new Delivery(new Envelope(1L, false, "", ""), new AMQP.BasicProperties.Builder().build(),
                bytes("nope")));
        assertTrue(warnings.get(0).contains("exchange=, routing_key=, tenant_id=" + OWN_TENANT), warnings.get(0));
    }

    @Test
    void reasonsFollowTheNormativeOrder() throws Exception {
        String canonical = fixture().get("authz_request").get("canonical_signed_json").asText();
        Harness h = new Harness(EventType.AUTHZ_REQUEST);
        // (1) not one JSON object: BOM, whitespace prefix, not JSON, trailing content, empty.
        h.assertDiscarded("malformed", withBom(bytes(wire("authz_request"))));
        h.assertDiscarded("malformed", bytes(" " + wire("authz_request")));
        h.assertDiscarded("malformed", bytes("not json"));
        h.assertDiscarded("malformed", bytes(wire("authz_request") + " "));
        h.assertDiscarded("malformed", new byte[0]);
        // (2) no top-level hmac_signature: unsigned, even with a repeated member (a (3) condition).
        h.assertDiscarded("unsigned", bytes(canonical));
        h.assertDiscarded("unsigned", bytes(canonical.replace("\"action\":\"documents:read\"",
                "\"action\":\"documents:read\",\"action\":\"x\"")));
        h.assertDiscarded("unsigned", bytes("{}"));
        // (3) hmac_signature null, not trailing, a repeated member, another type's layout.
        h.assertDiscarded("malformed", bytes(canonical.replaceAll("}$", ",\"hmac_signature\":null}")));
        h.assertDiscarded("malformed", bytes(wire("authz_request").replaceAll(
                ",\"hmac_signature\":\"([0-9a-f]{64})\"}$", ",\"hmac_signature\":\"$1\",\"z\":1}")));
        h.assertDiscarded("malformed", signed(canonical.replace("\"action\":\"documents:read\"",
                "\"action\":\"documents:read\",\"action\":\"x\"")));
        // (4) the HMAC fails.
        h.assertDiscarded("signature", bytes(withChangedSignatureDigit(wire("authz_request"))));
        // (5) verified but does not decode: ill-typed member, a nonce that is not a UUID, a timestamp that is not.
        h.assertDiscarded("malformed", signed(canonical.replace("\"key_version\":2", "\"key_version\":\"2\"")));
        h.assertDiscarded("malformed", signed(canonical.replace("55555555-5555-5555-5555-555555555555", "n1")));
        h.assertDiscarded("malformed", signed(canonical.replace("2026-07-10T12:00:00Z", "yesterday")));
        // (6) key_version below 2 (decode passes), before stale.
        h.assertDiscarded("key_version", signed(canonical.replace("\"key_version\":2", "\"key_version\":1")
                .replace("2026-07-10T12:00:00Z", "2020-01-01T00:00:00Z")));
        // (7) stale.
        h.assertDiscarded("stale", signed(canonical.replace("2026-07-10T12:00:00Z", "2026-07-10T13:00:00Z")));
        // The refusals above left no nonce behind: the genuine message is accepted, then (8) replay.
        h.deliver(bytes(wire("authz_request")));
        assertEquals(1, h.seen.size(), "a nonce refused at (1)-(7) must not have been recorded");
        h.seen.clear();
        h.assertDiscarded("replay", bytes(wire("authz_request")));
    }

    // ---- D-10: no body escapes the event consumer ----------------------------------------------------

    @Test
    void aBomPrefixedValidVectorIsMalformedWithoutExceptionAndTheNextDeliveryIsProcessed() throws Exception {
        for (EventType type : EventType.values()) {
            String vector = type == EventType.AUTHZ_REQUEST ? "authz_request" : "audit_event";
            Harness h = new Harness(type);
            assertDoesNotThrow(() -> h.assertDiscarded("malformed", withBom(bytes(wire(vector)))));
            h.deliver(bytes(wire(vector)));
            assertEquals(1, h.seen.size(), "the next delivery is still processed");
            assertEquals("ack", h.calls.get(h.calls.size() - 1).type());
        }
    }

    @Test
    void noBodyEscapesTheEventConsumer() throws Exception {
        Harness h = new Harness(EventType.AUTHZ_REQUEST);
        List<byte[]> hostile = new ArrayList<>();
        hostile.add(new byte[0]);
        hostile.add(new byte[] {(byte) 0xFF, (byte) 0xFE, 0x00, (byte) 0xC3, 0x28});
        hostile.add(bytes("{\"a\":" + "[".repeat(100_000)));
        hostile.add(bytes("[".repeat(100_000) + "]".repeat(100_000)));
        hostile.add(bytes("{\"hmac_signature\":\"" + "0".repeat(64) + "\""));
        hostile.add(bytes(wire("authz_request")).length > 10
                ? java.util.Arrays.copyOf(bytes(wire("authz_request")), 50) : new byte[0]);
        hostile.add(bytes("{\"a\":" + "{\"a\":".repeat(50_000) + "1" + "}".repeat(50_001)
                + ",\"hmac_signature\":\"" + "0".repeat(64) + "\"}"));
        for (byte[] body : hostile) {
            int before = h.calls.size();
            assertDoesNotThrow(() -> h.deliver(body));
            assertEquals(before + 1, h.calls.size());
            assertEquals("nack", h.calls.get(before).type());
            assertFalse(h.calls.get(before).requeue());
        }
        assertEquals(hostile.size(), h.warnings.size());
        h.deliver(bytes(wire("authz_request")));
        assertEquals(1, h.seen.size(), "the loop goes on to the next delivery");
    }

    // ---- D-10: no body escapes the requester ---------------------------------------------------------

    private static final class NoopTransport implements Transport {
        @Override
        public String declareReplyQueue(ResponseSink sink) {
            return "amq.gen-x";
        }

        @Override
        public void publishRequest(String q, String r, String c, byte[] body) {
        }
    }

    private static final class Delivered implements ResponseDelivery {
        private final byte[] body;
        int nacks;

        Delivered(byte[] body) {
            this.body = body;
        }

        @Override
        public byte[] body() {
            return body;
        }

        @Override
        public void ack() {
        }

        @Override
        public void nackWithoutRequeue() {
            nacks++;
        }
    }

    @Test
    void noBodyEscapesTheRequesterAndABomIsMalformed() throws Exception {
        List<String> log = new ArrayList<>();
        try (AuthzRequester r = AuthzRequester.create(new NoopTransport(), "11111111-1111-1111-1111-111111111111",
                subkey(), AuthzRequester.Options.defaults().withLogger(AmqpTestDoubles.recordingLogger(log)))) {
            String response = "{\"correlation_id\":\"22222222-2222-2222-2222-222222222222\",\"allowed\":true,"
                    + "\"reason_code\":\"allowed\",\"tenant_id\":\"11111111-1111-1111-1111-111111111111\","
                    + "\"nonce\":\"55555555-5555-5555-5555-555555555555\"}";
            List<byte[]> hostile = List.of(new byte[0], new byte[] {(byte) 0xFF, (byte) 0xFE, (byte) 0xC3, 0x28},
                    bytes("[".repeat(100_000)), bytes("{\"a\":" + "{\"a\":".repeat(50_000)),
                    withBom(signed(response)), withBom(bytes("{}")));
            for (byte[] body : hostile) {
                Delivered d = new Delivered(body);
                assertDoesNotThrow(() -> r.handle(d));
                assertEquals(1, d.nacks);
            }
            assertEquals(hostile.size(), log.size(), "one discard event each");
            assertTrue(log.get(4).contains("reason=malformed"), log.get(4));
        }
    }
}
