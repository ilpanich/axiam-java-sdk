package io.axiam.sdk.amqp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DeliverCallback;

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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT 1.69 &sect;8 alignment (OI-14): the layout check (step 2c), the reference vectors' {@code wire_json},
 * the producer's byte-for-byte wire form, and the requester's normative discard order and after-Close rule.
 */
class AmqpContract169AlignTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-07-10T12:00:00Z"), ZoneOffset.UTC);
    private static final String TENANT = "11111111-1111-1111-1111-111111111111";
    private static final String CORRELATION = "22222222-2222-2222-2222-222222222222";
    private static final String NONCE = "55555555-5555-5555-5555-555555555555";

    private static JsonNode fixture() throws Exception {
        try (InputStream in = AmqpContract169AlignTest.class.getResourceAsStream("/v2_reference_vectors.json")) {
            return MAPPER.readTree(in);
        }
    }

    private static byte[] subkey() throws Exception {
        return HexFormat.of().parseHex(fixture().get("hkdf").get("derived_subkey_hex").asText());
    }

    private static byte[] sign(String canonical) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(subkey(), "HmacSHA256"));
        String sig = HexFormat.of().formatHex(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
        return (canonical.substring(0, canonical.length() - 1) + ",\"hmac_signature\":\"" + sig + "\"}")
                .getBytes(StandardCharsets.UTF_8);
    }

    private record Outcome(List<byte[]> seen, List<AckNack> calls) {
    }

    private static Outcome consume(byte[] body) throws Exception {
        List<AckNack> calls = new ArrayList<>();
        List<byte[]> seen = new ArrayList<>();
        Channel channel = AmqpTestDoubles.recordingChannel(calls);
        Logger logger = AmqpTestDoubles.recordingLogger(new ArrayList<>());
        DeliverCallback cb = AmqpConsumer.deliverCallback(channel, subkey(), seen::add, logger,
                Duration.ofSeconds(300), CLOCK, new NonceStore(Duration.ofSeconds(600)));
        cb.handle("tag", AmqpTestDoubles.delivery(1L, body));
        return new Outcome(seen, calls);
    }

    private static void assertRefused(String name, byte[] body) throws Exception {
        Outcome o = consume(body);
        assertTrue(o.seen().isEmpty(), name + ": the handler must never run");
        assertEquals(1, o.calls().size(), name);
        assertEquals("nack", o.calls().get(0).type(), name);
        assertFalse(o.calls().get(0).requeue(), name);
    }

    // ---- point 3: wire_json ---------------------------------------------------------------------

    @Test
    void wireJsonOfBothVectorsCutsToCanonicalVerifiesPassesTheLayoutAndDispatches() throws Exception {
        for (String name : List.of("authz_request", "audit_event")) {
            JsonNode v = fixture().get(name);
            byte[] wire = v.get("wire_json").asText().getBytes(StandardCharsets.UTF_8);
            Outcome o = consume(wire);
            assertEquals(1, o.seen().size(), name);
            assertEquals("ack", o.calls().get(0).type(), name);
            assertArrayEquals(v.get("canonical_signed_json").asText().getBytes(StandardCharsets.UTF_8),
                    o.seen().get(0), name);
        }
    }

    @Test
    void aGenuineMessageWithHtmlCharactersNonAsciiAndAUnicodeEscapeVerifies() throws Exception {
        String canonical = fixture().get("audit_event").get("canonical_signed_json").asText()
                .replace("\"action\":\"user.login\"", "\"action\":\"a<b>&c \u00e9 \\u0041\"")
                .replace("{\"method\":\"password\"}", "{\"q\":\"<>&\u65e5\\u0042\"}");
        Outcome o = consume(sign(canonical));
        assertEquals(1, o.seen().size());
        assertEquals(canonical, new String(o.seen().get(0), StandardCharsets.UTF_8));
    }

    // ---- point 1, step 2c: the layout check -------------------------------------------------------

    @Test
    void membersInAnotherOrderThatAreValidlySignedAreRefused() throws Exception {
        String reordered = "{\"tenant_id\":\"" + TENANT + "\",\"correlation_id\":\"" + CORRELATION
                + "\",\"subject_id\":\"33333333-3333-3333-3333-333333333333\",\"action\":\"a\","
                + "\"resource_id\":\"44444444-4444-4444-4444-444444444444\",\"key_version\":2,\"nonce\":\""
                + NONCE + "\",\"issued_at\":\"2026-07-10T12:00:00Z\"}";
        assertRefused("authz request reordered", sign(reordered));
        String audit = fixture().get("audit_event").get("canonical_signed_json").asText();
        assertRefused("audit event, outcome before action",
                sign(audit.replace("\"action\":\"user.login\",\"resource_id\":\"77777777-7777-7777-7777-777777777777\","
                        + "\"outcome\":\"Success\",",
                        "\"outcome\":\"Success\",\"action\":\"user.login\",\"resource_id\":"
                                + "\"77777777-7777-7777-7777-777777777777\",")));
    }

    @Test
    void anExtraUnknownMemberOrAMissingRequiredMemberIsRefused() throws Exception {
        String audit = fixture().get("audit_event").get("canonical_signed_json").asText();
        assertRefused("extra member", sign(audit.replace(",\"key_version\"", ",\"extra\":1,\"key_version\"")));
        assertRefused("missing required actor_id",
                sign(audit.replace("\"actor_id\":\"66666666-6666-6666-6666-666666666666\",", "")));
        assertRefused("case-variant member name", sign(audit.replace("\"outcome\"", "\"Outcome\"")));
    }

    @Test
    void aValidlySignedAuthzResponseOrACacheInvalidationShapeSentToTheEventConsumerIsRefused() throws Exception {
        String response = "{\"correlation_id\":\"" + CORRELATION + "\",\"allowed\":true,\"reason_code\":\"allowed\","
                + "\"tenant_id\":\"" + TENANT + "\",\"key_version\":2,\"nonce\":\"" + NONCE
                + "\",\"issued_at\":\"2026-07-10T12:00:00Z\"}";
        // Carries every v2 field, so the replay checks pass and only the layout check can refuse it.
        assertRefused("authz response", sign(response));
        // A shape whose members are a subset of AuditEventMessage's that an absent-means-default decoder
        // would otherwise fill in.
        String invalidation = "{\"tenant_id\":\"" + TENANT + "\",\"action\":\"cache.invalidate\","
                + "\"key_version\":2,\"nonce\":\"" + NONCE + "\",\"issued_at\":\"2026-07-10T12:00:00Z\"}";
        assertRefused("cache invalidation shaped", sign(invalidation));
    }

    @Test
    void duplicateTrailingAndNullSignatureBodiesFromTheVectorsAreRefused() throws Exception {
        String wire = fixture().get("authz_request").get("wire_json").asText();
        assertRefused("trailing whitespace", (wire + "\n").getBytes(StandardCharsets.UTF_8));
        assertRefused("null signature", fixture().get("authz_request").get("canonical_signed_json").asText()
                .replaceAll("}$", ",\"hmac_signature\":null}").getBytes(StandardCharsets.UTF_8));
        assertRefused("duplicate top-level member", sign(fixture().get("authz_request").get("canonical_signed_json")
                .asText().replace("\"action\":\"documents:read\"",
                        "\"action\":\"documents:read\",\"action\":\"documents:read\"")));
        assertRefused("unsigned", fixture().get("authz_request").get("canonical_signed_json").asText()
                .getBytes(StandardCharsets.UTF_8));
    }

    // ---- point 4: the producer emits wire_json byte for byte ---------------------------------------

    private static final class NoopTransport implements Transport {
        @Override
        public String declareReplyQueue(ResponseSink sink) {
            return "amq.gen-x";
        }

        @Override
        public void publishRequest(String q, String r, String c, byte[] body) {
        }
    }

    @Test
    void theProducerEmitsExactlyTheVectorsWireJson() throws Exception {
        try (AuthzRequester r = AuthzRequester.create(new NoopTransport(), TENANT, subkey(),
                AuthzRequester.Options.defaults().withClock(CLOCK))) {
            byte[] body = r.buildRequest(CORRELATION, "33333333-3333-3333-3333-333333333333", "documents:read",
                    "44444444-4444-4444-4444-444444444444", "confidential", NONCE);
            assertArrayEquals(fixture().get("authz_request").get("wire_json").asText()
                    .getBytes(StandardCharsets.UTF_8), body);
            byte[] noScope = r.buildRequest(CORRELATION, "33333333-3333-3333-3333-333333333333", "documents:read",
                    "44444444-4444-4444-4444-444444444444", null, NONCE);
            assertFalse(new String(noScope, StandardCharsets.UTF_8).contains("scope"));
        }
    }

    // ---- point 5: the requester's discard order and after-Close -------------------------------------

    private static final class Delivered implements ResponseDelivery {
        private final byte[] body;
        int acks;
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
            acks++;
        }

        @Override
        public void nackWithoutRequeue() {
            nacks++;
        }
    }

    private static String reasonOf(String canonicalOrWire, boolean signed, List<String> warnings) throws Exception {
        List<String> log = warnings;
        AuthzRequester r = AuthzRequester.create(new NoopTransport(), TENANT, subkey(),
                AuthzRequester.Options.defaults().withLogger(AmqpTestDoubles.recordingLogger(log)));
        r.registerOutstanding(CORRELATION, NONCE);
        Delivered d = new Delivered(signed ? sign(canonicalOrWire) : canonicalOrWire.getBytes(StandardCharsets.UTF_8));
        r.handle(d);
        assertEquals(1, d.nacks);
        assertEquals(1, log.size());
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("reason=(\\w+)").matcher(log.get(0));
        assertTrue(m.find());
        return m.group(1);
    }

    private static final String RESPONSE = "{\"correlation_id\":\"" + CORRELATION + "\",\"allowed\":true,"
            + "\"reason_code\":\"allowed\",\"tenant_id\":\"" + TENANT + "\",\"nonce\":\"" + NONCE + "\"}";

    private static byte[] badSignatureWire(String canonical) {
        return (canonical.substring(0, canonical.length() - 1) + ",\"hmac_signature\":\"" + "ab".repeat(32) + "\"}")
                .getBytes(StandardCharsets.UTF_8);
    }

    private static String reasonOfBytes(byte[] body) throws Exception {
        List<String> log = new ArrayList<>();
        AuthzRequester r = AuthzRequester.create(new NoopTransport(), TENANT, subkey(),
                AuthzRequester.Options.defaults().withLogger(AmqpTestDoubles.recordingLogger(log)));
        r.registerOutstanding(CORRELATION, NONCE);
        r.handle(new Delivered(body));
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("reason=(\\w+)").matcher(log.get(0));
        assertTrue(m.find());
        return m.group(1);
    }

    @Test
    void theDiscardReasonOrderIsNormative() throws Exception {
        // (1) not one JSON object -> malformed, even with nothing else to look at
        assertEquals("malformed", reasonOf("[]", false, new ArrayList<>()));
        // (2) no hmac_signature member -> unsigned, whatever else is missing
        assertEquals("unsigned", reasonOf("{}", false, new ArrayList<>()));
        assertEquals("unsigned", reasonOf(RESPONSE.replace("\"allowed\":true,", ""), false, new ArrayList<>()));
        // (3) a bad signature member, or an ill-typed/missing binding member -> malformed, BEFORE the HMAC
        for (String field : List.of("tenant_id", "nonce", "correlation_id")) {
            String without = RESPONSE.replaceAll(",?\"" + field + "\":\"[^\"]*\"", "").replace("{,", "{");
            assertEquals("malformed", reasonOfBytes(badSignatureWire(without)), field + " missing, bad signature");
            String illTyped = RESPONSE.replaceAll("\"" + field + "\":\"[^\"]*\"", "\"" + field + "\":7");
            assertEquals("malformed", reasonOfBytes(badSignatureWire(illTyped)), field + " ill-typed, bad signature");
        }
        assertEquals("malformed", reasonOfBytes(badSignatureWire(RESPONSE.replace("\"allowed\":true",
                "\"allowed\":\"yes\""))));
        assertEquals("malformed", reasonOfBytes((RESPONSE.substring(0, RESPONSE.length() - 1)
                + ",\"hmac_signature\":null}").getBytes(StandardCharsets.UTF_8)));
        // (4) HMAC fails -> signature (even for another tenant)
        assertEquals("signature", reasonOfBytes(badSignatureWire(RESPONSE)));
        assertEquals("signature", reasonOfBytes(badSignatureWire(RESPONSE.replace(TENANT,
                "99999999-9999-9999-9999-999999999999"))));
        // (5) wrong tenant -> tenant, before the outstanding-request lookup
        assertEquals("tenant", reasonOf(RESPONSE.replace(TENANT, "99999999-9999-9999-9999-999999999999")
                .replace(CORRELATION, "77777777-7777-7777-7777-777777777777"), true, new ArrayList<>()));
        // (6) no outstanding request -> unknown_request
        assertEquals("unknown_request", reasonOf(RESPONSE.replace(CORRELATION,
                "77777777-7777-7777-7777-777777777777"), true, new ArrayList<>()));
    }

    @Test
    void afterCloseAnAnswerIsNackedWithoutRequeueWithoutAnEventAndNeverDecoded() throws Exception {
        List<String> log = new ArrayList<>();
        AuthzRequester r = AuthzRequester.create(new NoopTransport(), TENANT, subkey(),
                AuthzRequester.Options.defaults().withLogger(AmqpTestDoubles.recordingLogger(log)));
        r.registerOutstanding(CORRELATION, NONCE);
        r.close();
        for (byte[] body : List.of(sign(RESPONSE), "not json".getBytes(StandardCharsets.UTF_8),
                badSignatureWire(RESPONSE))) {
            Delivered d = new Delivered(body);
            r.handle(d);
            assertEquals(0, d.acks);
            assertEquals(1, d.nacks);
        }
        assertTrue(log.isEmpty(), "no discard event after Close: " + log);
    }

    @Test
    void aBodyWithALeadingByteOrderMarkIsRefusedByBothConsumers() throws Exception {
        byte[] bom = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
        byte[] wire = fixture().get("authz_request").get("wire_json").asText().getBytes(StandardCharsets.UTF_8);
        byte[] withBom = new byte[bom.length + wire.length];
        System.arraycopy(bom, 0, withBom, 0, bom.length);
        System.arraycopy(wire, 0, withBom, bom.length, wire.length);
        assertRefused("event consumer", withBom);

        byte[] resp = sign(RESPONSE);
        byte[] respBom = new byte[bom.length + resp.length];
        System.arraycopy(bom, 0, respBom, 0, bom.length);
        System.arraycopy(resp, 0, respBom, bom.length, resp.length);
        assertEquals("malformed", reasonOfBytes(respBom));
    }
}
