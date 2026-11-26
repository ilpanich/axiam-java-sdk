package io.axiam.sdk.amqp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DeliverCallback;
import com.rabbitmq.client.Envelope;

import io.axiam.sdk.amqp.AuthzRequester.Decision;
import io.axiam.sdk.amqp.AuthzRequester.ResponseDelivery;
import io.axiam.sdk.amqp.AuthzRequester.ResponseSink;
import io.axiam.sdk.amqp.AuthzRequester.Transport;
import io.axiam.sdk.errors.NetworkError;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The AMQP authorization requester (CONTRACT.md &sect;8 "Signed authorization responses",
 * contract 1.68; N2, D-9), against the contract's four normative test vectors and the negative
 * cases of its "Required tests" clause, over a fake transport; the RabbitMQ transport is checked
 * against a recording channel.
 */
class AuthzRequesterTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String MASTER_KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private static final String SUBKEY_HEX = "919e125ec83799c1e113a27707cac5008a2608d0557e00dfe1b3a316abed4b89";
    private static final String TENANT = "11111111-1111-1111-1111-111111111111";
    private static final String OTHER_TENANT = "99999999-9999-9999-9999-999999999999";
    private static final String CORRELATION = "22222222-2222-2222-2222-222222222222";
    private static final String NONCE = "55555555-5555-5555-5555-555555555555";
    private static final String SUBJECT = "33333333-3333-3333-3333-333333333333";
    private static final String RESOURCE = "44444444-4444-4444-4444-444444444444";

    /** One normative vector: canonical bytes, signature, and the decision they decode to. */
    private record Vector(String name, String canonical, String sig, boolean allowed, String reason, String code) {
        byte[] wire() {
            return (canonical.substring(0, canonical.length() - 1) + ",\"hmac_signature\":\"" + sig + "\"}")
                    .getBytes(StandardCharsets.UTF_8);
        }
    }

    private static final List<Vector> VECTORS = List.of(
            new Vector("1 allow",
                    "{\"correlation_id\":\"22222222-2222-2222-2222-222222222222\",\"allowed\":true,\"reason_code\":\"allowed\",\"tenant_id\":\"11111111-1111-1111-1111-111111111111\",\"nonce\":\"55555555-5555-5555-5555-555555555555\"}",
                    "8d81f0437df6c6fffafd13f4265bd41d3cfd6fcbf7c251b3bb79e0846578574a", true, null, "allowed"),
            new Vector("2 deny no_grant",
                    "{\"correlation_id\":\"22222222-2222-2222-2222-222222222222\",\"allowed\":false,\"reason\":\"no permission grants action 'documents:read'\",\"reason_code\":\"no_grant\",\"tenant_id\":\"11111111-1111-1111-1111-111111111111\",\"nonce\":\"55555555-5555-5555-5555-555555555555\"}",
                    "f3105ee678acd79da6ffd28c02b86311e16bb8d8dfd3fd0addbacdf73bd5a400", false,
                    "no permission grants action 'documents:read'", "no_grant"),
            new Vector("3 deny denied_by_rule",
                    "{\"correlation_id\":\"22222222-2222-2222-2222-222222222222\",\"allowed\":false,\"reason\":\"an explicit deny rule refuses action 'documents:read'\",\"reason_code\":\"denied_by_rule\",\"tenant_id\":\"11111111-1111-1111-1111-111111111111\",\"nonce\":\"55555555-5555-5555-5555-555555555555\"}",
                    "4bfc2ce9a035bd4a028ee2a5cb75a08832915c60cd2b176c8d4bf28910a61adc", false,
                    "an explicit deny rule refuses action 'documents:read'", "denied_by_rule"),
            new Vector("4 escapes encoders disagree on",
                    "{\"correlation_id\":\"22222222-2222-2222-2222-222222222222\",\"allowed\":false,\"reason\":\"no permission grants action 'docs:a&b</\\\"c\\\">/é€'\",\"reason_code\":\"no_grant\",\"tenant_id\":\"11111111-1111-1111-1111-111111111111\",\"nonce\":\"55555555-5555-5555-5555-555555555555\"}",
                    "5194142df4bf66b07e9e8d516caf6be099af025219ab12deb26fea39e93490ff", false,
                    "no permission grants action 'docs:a&b</\"c\">/é€'", "no_grant"));

    // ---- key derivation (test-side), contract §8 -----------------------------------------------

    /** HKDF-SHA256(salt, ikm = master, info = "axiam-amqp-v1" || key_version || tenant raw bytes, L = 32). */
    private static byte[] subkeyFor(String tenant, int keyVersion) throws Exception {
        byte[] master = HexFormat.of().parseHex(MASTER_KEY_HEX);
        byte[] salt = "axiam-amqp-hkdf-salt-v1".getBytes(StandardCharsets.UTF_8);
        byte[] prk = hmac(salt, master);
        byte[] tenantRaw = HexFormat.of().parseHex(tenant.replace("-", ""));
        byte[] label = "axiam-amqp-v1".getBytes(StandardCharsets.UTF_8);
        byte[] info = new byte[label.length + 1 + tenantRaw.length + 1];
        System.arraycopy(label, 0, info, 0, label.length);
        info[label.length] = (byte) keyVersion;
        System.arraycopy(tenantRaw, 0, info, label.length + 1, tenantRaw.length);
        info[info.length - 1] = 0x01; // T(1)
        return hmac(prk, info);
    }

    private static byte[] hmac(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    private static byte[] signWith(byte[] key, String canonical) throws Exception {
        String sig = HexFormat.of().formatHex(hmac(key, canonical.getBytes(StandardCharsets.UTF_8)));
        return (canonical.substring(0, canonical.length() - 1) + ",\"hmac_signature\":\"" + sig + "\"}")
                .getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] subkey() {
        return HexFormat.of().parseHex(SUBKEY_HEX);
    }

    // ---- doubles ---------------------------------------------------------------------------------

    private static class RecordedDelivery implements ResponseDelivery {
        private final byte[] body;
        int acks;
        int nacksWithoutRequeue;

        RecordedDelivery(byte[] body) {
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
            nacksWithoutRequeue++;
        }
    }

    private record Published(String queue, String replyTo, String correlationId, byte[] body) {
    }

    private static final class FakeTransport implements Transport {
        String queue = "amq.gen-Xk3pQ";
        ResponseSink sink;
        final List<Published> published = new CopyOnWriteArrayList<>();
        boolean closedByRequester;
        boolean failPublish;

        @Override
        public String declareReplyQueue(ResponseSink s) {
            this.sink = s;
            return queue;
        }

        @Override
        public void publishRequest(String q, String replyTo, String correlationId, byte[] body) throws IOException {
            if (failPublish) {
                throw new IOException("broker unavailable");
            }
            published.add(new Published(q, replyTo, correlationId, body));
        }

        @Override
        public void close() {
            closedByRequester = true;
        }
    }

    private static AuthzRequester requester(AuthzRequester.Options options) throws Exception {
        return AuthzRequester.create(new FakeTransport(), TENANT, subkey(), options);
    }

    private static Logger recordingLogger(List<String> warnings) {
        return AmqpTestDoubles.recordingLogger(warnings);
    }

    /** A requester with one outstanding request (the vectors' correlation_id and nonce). */
    private record Fixture(AuthzRequester requester, CompletableFuture<Decision> outstanding) {
        RecordedDelivery offer(byte[] body) {
            RecordedDelivery d = new RecordedDelivery(body);
            requester.handle(d);
            return d;
        }
    }

    private static Fixture fixture(AuthzRequester.Options options) throws Exception {
        AuthzRequester r = requester(options);
        return new Fixture(r, r.registerOutstanding(CORRELATION, NONCE));
    }

    // ---- derivation sanity -------------------------------------------------------------------------

    @Test
    void theTestSideHkdfMatchesTheContractsSubkey() throws Exception {
        assertEquals(SUBKEY_HEX, HexFormat.of().formatHex(subkeyFor(TENANT, 2)));
    }

    // ---- the four vectors --------------------------------------------------------------------------

    @Test
    void everyContractVectorVerifiesOverItsWireJson() throws Exception {
        for (Vector v : VECTORS) {
            Fixture f = fixture(AuthzRequester.Options.defaults());
            RecordedDelivery d = f.offer(v.wire());

            assertTrue(f.outstanding().isDone(), v.name() + " must verify and complete the request");
            Decision decision = f.outstanding().get();
            assertEquals(v.allowed(), decision.allowed(), v.name());
            assertEquals(v.reason(), decision.reason(), v.name());
            assertEquals(v.code(), decision.reasonCode(), v.name());
            assertEquals(1, d.acks, "an accepted response is acked");

            // Retired on acceptance: the same response again is dropped and nacked.
            RecordedDelivery again = f.offer(v.wire());
            assertEquals(0, again.acks);
            assertEquals(1, again.nacksWithoutRequeue);
        }
    }

    // ---- the negative cases ------------------------------------------------------------------------

    @Test
    void everyFailedResponseIsNackedWithoutRequeueNeverAnAllowAndNeverCompletesTheRequest() throws Exception {
        Vector v1 = VECTORS.get(0);
        Vector v2 = VECTORS.get(1);
        byte[] good = subkey();
        String wire1 = new String(v1.wire(), StandardCharsets.UTF_8);
        String wire2 = new String(v2.wire(), StandardCharsets.UTF_8);

        record Case(String name, byte[] body) {
        }
        List<Case> cases = List.of(
                new Case("vector 1 under another tenant's subkey", signWith(subkeyFor(OTHER_TENANT, 2), v1.canonical())),
                new Case("vector 1 under key_version 3", signWith(subkeyFor(TENANT, 3), v1.canonical())),
                new Case("tampered: allowed flipped to false, signature kept",
                        wire1.replace("\"allowed\":true", "\"allowed\":false").getBytes(StandardCharsets.UTF_8)),
                new Case("tampered: vector 2 flipped to true, signature kept",
                        wire2.replace("\"allowed\":false", "\"allowed\":true").getBytes(StandardCharsets.UTF_8)),
                new Case("tampered reason_code",
                        wire2.replace("no_grant", "allowed").getBytes(StandardCharsets.UTF_8)),
                new Case("a response for another nonce (validly signed)", signWith(good,
                        v1.canonical().replace(NONCE, "66666666-6666-6666-6666-666666666666"))),
                new Case("a response for another correlation_id (validly signed)", signWith(good,
                        v1.canonical().replace(CORRELATION, "77777777-7777-7777-7777-777777777777"))),
                new Case("a response for another tenant (validly signed with our key)", signWith(good,
                        v1.canonical().replace(TENANT, OTHER_TENANT))),
                new Case("no allowed: a signed AuthzRequest delivered on the response queue", signWith(good,
                        "{\"correlation_id\":\"" + CORRELATION + "\",\"tenant_id\":\"" + TENANT + "\",\"subject_id\":\""
                                + SUBJECT + "\",\"action\":\"documents:read\",\"resource_id\":\"" + RESOURCE
                                + "\",\"key_version\":2,\"nonce\":\"" + NONCE
                                + "\",\"issued_at\":\"2026-07-10T12:00:00Z\"}")),
                new Case("allowed is a string, not a boolean", signWith(good,
                        v1.canonical().replace("\"allowed\":true", "\"allowed\":\"true\""))),
                new Case("no tenant_id", signWith(good,
                        v1.canonical().replace("\"tenant_id\":\"" + TENANT + "\",", ""))),
                new Case("no nonce", signWith(good, v1.canonical().replace(",\"nonce\":\"" + NONCE + "\"", ""))),
                new Case("the signature is not the trailing member",
                        wire1.replace("\"allowed\":true", "\"allowed\":true,\"x\":1").getBytes(StandardCharsets.UTF_8)),
                new Case("duplicate allowed keys, validly signed", signWith(good,
                        v1.canonical().replace("\"allowed\":true", "\"allowed\":false,\"allowed\":true"))),
                new Case("a case-variant allowed key, validly signed", signWith(good,
                        v1.canonical().replace("\"reason_code\"", "\"ALLOWED\":false,\"reason_code\""))),
                new Case("trailing whitespace after the closing brace",
                        (wire1 + "\n").getBytes(StandardCharsets.UTF_8)),
                new Case("a non-hex signature",
                        wire1.replace(v1.sig(), "z".repeat(64)).getBytes(StandardCharsets.UTF_8)),
                new Case("a short signature",
                        wire1.replace(v1.sig(), v1.sig().substring(0, 62)).getBytes(StandardCharsets.UTF_8)),
                new Case("not JSON", "not json".getBytes(StandardCharsets.UTF_8)),
                new Case("an empty body", new byte[0]));

        for (Case c : cases) {
            Fixture f = fixture(AuthzRequester.Options.defaults());
            RecordedDelivery d = f.offer(c.body());

            assertFalse(f.outstanding().isDone(), c.name() + ": must neither allow nor complete the request");
            assertEquals(0, d.acks, c.name());
            assertEquals(1, d.nacksWithoutRequeue, c.name() + ": nacked without requeue");
            // The request is still outstanding: the genuine answer completes it.
            f.offer(v1.wire());
            assertTrue(f.outstanding().isDone() && f.outstanding().get().allowed(),
                    c.name() + ": a discarded response must leave the request waiting for the genuine answer");
        }
    }

    @Test
    void aDiscardedResponseIsLoggedWithoutEitherSignatureValue() throws Exception {
        List<String> warnings = new ArrayList<>();
        Fixture f = fixture(AuthzRequester.Options.defaults().withLogger(recordingLogger(warnings)));
        Vector v2 = VECTORS.get(1);
        String tampered = new String(v2.wire(), StandardCharsets.UTF_8).replace("\"allowed\":false", "\"allowed\":true");

        f.offer(tampered.getBytes(StandardCharsets.UTF_8));

        assertFalse(warnings.isEmpty(), "a security event must be logged");
        for (String w : warnings) {
            assertFalse(w.contains(v2.sig()), "the received signature must not be logged");
            assertFalse(w.contains(HexFormat.of().formatHex(hmac(subkey(),
                    tampered.substring(0, tampered.indexOf(",\"hmac_signature\"") ).concat("}")
                            .getBytes(StandardCharsets.UTF_8)))), "the expected signature must not be logged");
        }
    }

    // ---- unsigned responses: no opt-out (CONTRACT 1.69 §8, A.1) -------------------------------------

    private static final byte[] UNSIGNED = ("{\"correlation_id\":\"" + CORRELATION
            + "\",\"allowed\":true,\"reason_code\":\"allowed\"}").getBytes(StandardCharsets.UTF_8);

    @Test
    void aWellFormedUnsignedResponseForAnOutstandingRequestIsDiscardedAsUnsignedAndTheCheckKeepsWaiting()
            throws Exception {
        List<String> warnings = new ArrayList<>();
        Fixture f = fixture(AuthzRequester.Options.defaults().withLogger(recordingLogger(warnings)));
        RecordedDelivery d = f.offer(UNSIGNED);

        assertFalse(f.outstanding().isDone());
        assertEquals(1, d.nacksWithoutRequeue);
        assertEquals(0, d.acks);
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).contains("reason=unsigned"), warnings.get(0));
        // The genuine answer still completes it.
        f.offer(VECTORS.get(0).wire());
        assertTrue(f.outstanding().isDone() && f.outstanding().get().allowed());
    }

    @Test
    void theOptionsHaveNoUnsignedResponseSwitch() {
        for (java.lang.reflect.RecordComponent c : AuthzRequester.Options.class.getRecordComponents()) {
            assertFalse(c.getName().toLowerCase().contains("unsigned"), c.getName());
        }
        for (java.lang.reflect.Method m : AuthzRequester.Options.class.getMethods()) {
            assertFalse(m.getName().toLowerCase().contains("unsigned"), m.getName());
        }
    }

    // ---- the discard security event (CONTRACT 1.69 §8 obligation 4; A.2; #883, JAV-R1-4) --------------

    private static String field(String line, String name) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(name + "=(\"[^\"]*\"|\\S+)").matcher(line);
        assertTrue(m.find(), name + " missing from: " + line);
        return m.group(1);
    }

    private void assertDiscardEvent(byte[] body, String reason, String exchange, String routingKey) throws Exception {
        List<String> warnings = new ArrayList<>();
        Fixture f = fixture(AuthzRequester.Options.defaults().withLogger(recordingLogger(warnings))
                .withClock(Clock.fixed(Instant.parse("2026-07-10T12:00:00Z"), ZoneOffset.UTC)));
        RecordedDelivery d = new RecordedDelivery(body) {
            @Override
            public String exchange() {
                return exchange;
            }

            @Override
            public String routingKey() {
                return routingKey;
            }
        };
        f.requester().handle(d);

        assertEquals(1, warnings.size(), reason);
        String line = warnings.get(0);
        assertEquals(reason, field(line, "reason"));
        assertEquals(TENANT, field(line, "tenant_id"), "the requester's own tenant");
        assertEquals("amq.gen-Xk3pQ", field(line, "routing_key"), "the reply queue");
        assertEquals("\"" + exchange + "\"", field(line, "exchange"));
        assertEquals("2026-07-10T12:00:00Z", field(line, "timestamp"));
        // Nothing from the body, no signature (received or computed), no nonce.
        assertFalse(line.contains(NONCE), line);
        assertFalse(line.contains(CORRELATION), line);
        String text = new String(body, StandardCharsets.UTF_8);
        java.util.regex.Matcher sig = java.util.regex.Pattern.compile("[0-9a-f]{64}").matcher(text);
        while (sig.find()) {
            assertFalse(line.contains(sig.group()), "received signature in the event");
        }
        assertFalse(line.contains(SUBKEY_HEX), line);
        if (text.contains("\"hmac_signature\"")) {
            String canonical = text.substring(0, text.indexOf(",\"hmac_signature\"")) + "}";
            assertFalse(line.contains(HexFormat.of().formatHex(
                    hmac(subkey(), canonical.getBytes(StandardCharsets.UTF_8)))), "computed signature in the event");
        }
    }

    @Test
    void everyDiscardPathLogsTheEventWithRoutingKeyAndOwnTenant() throws Exception {
        Vector v1 = VECTORS.get(0);
        String wire1 = new String(v1.wire(), StandardCharsets.UTF_8);
        byte[] good = subkey();
        // signature
        assertDiscardEvent(wire1.replace("\"allowed\":true", "\"allowed\":false").getBytes(StandardCharsets.UTF_8),
                "signature", "", "amq.gen-Xk3pQ");
        // tenant: validly signed, another tenant
        assertDiscardEvent(signWith(good, v1.canonical().replace(TENANT, OTHER_TENANT)), "tenant", "", "amq.gen-Xk3pQ");
        // unsigned
        assertDiscardEvent(UNSIGNED, "unsigned", "", "amq.gen-Xk3pQ");
        // malformed
        assertDiscardEvent("not json".getBytes(StandardCharsets.UTF_8), "malformed", "", "amq.gen-Xk3pQ");
        // unknown_request: validly signed, a correlation id nobody asked about
        assertDiscardEvent(signWith(good, v1.canonical().replace(CORRELATION,
                "77777777-7777-7777-7777-777777777777")), "unknown_request", "", "amq.gen-Xk3pQ");
        // a broker-reported exchange is reported as such; a transport with no routing key gets the reply queue
        assertDiscardEvent(UNSIGNED, "unsigned", "amq.direct", null);
    }

    @Test
    void aSecondAnswerToARetiredRequestIsAnUnknownRequestDiscardWithTheEvent() throws Exception {
        List<String> warnings = new ArrayList<>();
        Fixture f = fixture(AuthzRequester.Options.defaults().withLogger(recordingLogger(warnings)));
        f.offer(VECTORS.get(0).wire());
        assertTrue(warnings.isEmpty());
        f.offer(VECTORS.get(0).wire());
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).contains("reason=unknown_request"), warnings.get(0));
        assertTrue(warnings.get(0).contains("routing_key=amq.gen-Xk3pQ"), warnings.get(0));
        assertTrue(warnings.get(0).contains("tenant_id=" + TENANT), warnings.get(0));
    }

    // ---- JAV-R1-6: decisions complete off the consumer thread ----------------------------------------

    @Test
    void aDecisionCompletesOnTheExecutorNotOnTheConsumerThread() throws Exception {
        FakeTransport transport = new FakeTransport();
        java.util.concurrent.ExecutorService supplied = java.util.concurrent.Executors.newSingleThreadExecutor(
                r -> new Thread(r, "caller-supplied"));
        try (AuthzRequester r = AuthzRequester.create(transport, TENANT, subkey(),
                AuthzRequester.Options.defaults().withExecutor(supplied))) {
            CompletableFuture<String> thread = r.checkAsync(SUBJECT, "documents:read", RESOURCE, null)
                    .thenApply(d -> Thread.currentThread().getName());
            Published pub = transport.published.get(0);
            JsonNode req = MAPPER.readTree(pub.body());
            String answer = "{\"correlation_id\":\"" + pub.correlationId() + "\",\"tenant_id\":\"" + TENANT
                    + "\",\"allowed\":true,\"reason_code\":\"allowed\",\"nonce\":\"" + req.get("nonce").asText()
                    + "\"}";
            Thread consumer = new Thread(() -> transport.sink.accept(
                    new RecordedDelivery(answerSigned(answer))), "rabbit-consumer");
            consumer.start();
            consumer.join();

            assertEquals("caller-supplied", thread.get(2, TimeUnit.SECONDS),
                    "the continuation must not run on the RabbitMQ consumer thread");
        } finally {
            supplied.shutdownNow();
        }
    }

    @Test
    void aBlockingContinuationCannotStallTheReplyQueue() throws Exception {
        // check A, then (blocking) check B inside the continuation: B's answer must still be dispatched.
        FakeTransport transport = new FakeTransport();
        try (AuthzRequester r = AuthzRequester.create(transport, TENANT, subkey(),
                AuthzRequester.Options.defaults().withTimeout(Duration.ofSeconds(5)))) {
            CompletableFuture<Boolean> both = r.checkAsync(SUBJECT, "a", RESOURCE, null)
                    .thenApply(d -> d.allowed() && r.check(SUBJECT, "b", RESOURCE, null).allowed());

            Thread consumer = new Thread(() -> {
                try {
                    answer(transport, 0);
                    // the consumer thread would be blocked here by a synchronous continuation
                    long until = System.currentTimeMillis() + 2000;
                    while (transport.published.size() < 2 && System.currentTimeMillis() < until) {
                        Thread.sleep(5);
                    }
                    answer(transport, 1);
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }, "rabbit-consumer");
            consumer.start();
            consumer.join();

            assertTrue(both.get(5, TimeUnit.SECONDS));
        }
    }

    private static void answer(FakeTransport transport, int index) throws Exception {
        Published pub = transport.published.get(index);
        JsonNode req = MAPPER.readTree(pub.body());
        String answer = "{\"correlation_id\":\"" + pub.correlationId() + "\",\"tenant_id\":\"" + TENANT
                + "\",\"allowed\":true,\"reason_code\":\"allowed\",\"nonce\":\"" + req.get("nonce").asText()
                + "\"}";
        transport.sink.accept(new RecordedDelivery(answerSigned(answer)));
    }

    private static byte[] answerSigned(String canonical) {
        try {
            return signWith(subkey(), canonical);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ---- end to end --------------------------------------------------------------------------------

    @Test
    void checkPublishesASignedRequestOnAPrivateReplyQueueAndCompletesOnlyOnTheGenuineAnswer() throws Exception {
        FakeTransport transport = new FakeTransport();
        Clock clock = Clock.fixed(Instant.parse("2026-07-10T12:00:00Z"), ZoneOffset.UTC);
        try (AuthzRequester r = AuthzRequester.create(transport, TENANT, subkey(),
                AuthzRequester.Options.defaults().withTimeout(Duration.ofSeconds(5)).withClock(clock))) {
            assertEquals("amq.gen-Xk3pQ", r.replyTo());

            CompletableFuture<Decision> future = r.checkAsync(SUBJECT, "docs:a&b</\"c\">", RESOURCE, "confidential");
            Published pub = transport.published.get(0);

            // The request: default-exchange routing to the request queue, a private reply_to, and a
            // correlation_id property equal to the body's.
            assertEquals(AuthzRequester.AUTHZ_REQUEST_QUEUE, pub.queue());
            assertEquals("amq.gen-Xk3pQ", pub.replyTo());
            JsonNode req = MAPPER.readTree(pub.body());
            assertEquals(pub.correlationId(), req.get("correlation_id").asText());
            assertEquals(TENANT, req.get("tenant_id").asText());
            assertEquals(2, req.get("key_version").asInt());
            assertEquals("confidential", req.get("scope").asText());
            assertEquals("2026-07-10T12:00:00Z", req.get("issued_at").asText());
            // Server field order, compact, action characters raw as serde_json writes them.
            String text = new String(pub.body(), StandardCharsets.UTF_8);
            assertTrue(text.startsWith("{\"correlation_id\":\"" + pub.correlationId() + "\",\"tenant_id\":\"" + TENANT
                    + "\",\"subject_id\":\"" + SUBJECT + "\",\"action\":\"docs:a&b</\\\"c\\\">\",\"resource_id\":\""
                    + RESOURCE + "\",\"scope\":\"confidential\",\"key_version\":2,\"nonce\":\""), text);
            // It verifies under the subkey over its canonical form (the bytes with the signature cut out).
            int cut = text.lastIndexOf(",\"hmac_signature\":\"");
            String canonical = text.substring(0, cut) + "}";
            String sig = text.substring(cut + ",\"hmac_signature\":\"".length(), text.length() - 2);
            assertEquals(HexFormat.of().formatHex(hmac(subkey(), canonical.getBytes(StandardCharsets.UTF_8))), sig);

            // A forgery with the right ids under another tenant's subkey is discarded...
            String nonce = req.get("nonce").asText();
            String answer = "{\"correlation_id\":\"" + pub.correlationId() + "\",\"allowed\":true,\"reason_code\":"
                    + "\"allowed\",\"tenant_id\":\"" + TENANT + "\",\"nonce\":\"" + nonce + "\"}";
            RecordedDelivery forged = new RecordedDelivery(signWith(subkeyFor(OTHER_TENANT, 2), answer));
            transport.sink.accept(forged);
            assertFalse(future.isDone(), "a forged response must not complete the check");
            assertEquals(1, forged.nacksWithoutRequeue);

            // ...and the genuine answer completes it.
            RecordedDelivery genuine = new RecordedDelivery(signWith(subkey(), answer));
            transport.sink.accept(genuine);
            Decision decision = future.get(2, TimeUnit.SECONDS);
            assertTrue(decision.allowed());
            assertEquals("allowed", decision.reasonCode());
            assertEquals(1, genuine.acks);
            assertEquals(0, r.outstanding());

            // Fresh, distinct, unpredictable ids per request.
            r.checkAsync(SUBJECT, "documents:read", RESOURCE, null);
            Published pub2 = transport.published.get(1);
            JsonNode req2 = MAPPER.readTree(pub2.body());
            assertNotEquals(pub.correlationId(), pub2.correlationId());
            assertNotEquals(nonce, req2.get("nonce").asText());
            assertNotEquals(pub2.correlationId(), req2.get("nonce").asText());
            assertNull(req2.get("scope"), "no scope member when none was given");
        }
    }

    @Test
    void theRequestsOwnSignatureIsAcceptedByTheSdksConsumerVerification() throws Exception {
        FakeTransport transport = new FakeTransport();
        try (AuthzRequester r = AuthzRequester.create(transport, TENANT, subkey(), AuthzRequester.Options.defaults())) {
            r.checkAsync(SUBJECT, "documents:read", RESOURCE, "confidential");
            assertTrue(Hmac.verify(subkey(), transport.published.get(0).body()));
        }
    }

    @Test
    void closeFailsOutstandingChecksAndStopsTheTransport() throws Exception {
        FakeTransport transport = new FakeTransport();
        AuthzRequester r = AuthzRequester.create(transport, TENANT, subkey(), AuthzRequester.Options.defaults());
        CompletableFuture<Decision> future = r.checkAsync(SUBJECT, "a", RESOURCE, null);

        r.close();

        assertTrue(transport.closedByRequester);
        // Completions run on the executor (JAV-R1-6), so wait for it rather than assume it is done.
        assertThrows(java.util.concurrent.ExecutionException.class, () -> future.get(2, TimeUnit.SECONDS));
        assertTrue(future.isCompletedExceptionally());
        assertThrows(NetworkError.class, () -> r.check(SUBJECT, "a", RESOURCE, null));
        // A reply queue that goes away closes the requester too.
        FakeTransport t2 = new FakeTransport();
        AuthzRequester r2 = AuthzRequester.create(t2, TENANT, subkey(), AuthzRequester.Options.defaults());
        t2.sink.closed();
        assertThrows(NetworkError.class, () -> r2.check(SUBJECT, "a", RESOURCE, null));
    }

    @Test
    void checkTimesOutWithoutAnAnswerAndLeavesNoOutstandingEntry() throws Exception {
        try (AuthzRequester r = requester(AuthzRequester.Options.defaults().withTimeout(Duration.ofMillis(40)))) {
            NetworkError e = assertThrows(NetworkError.class, () -> r.check(SUBJECT, "a", RESOURCE, null));
            assertTrue(e.getMessage().contains("timed out"), e.getMessage());
            assertEquals(0, r.outstanding());
        }
    }

    @Test
    void aPublishFailureIsANetworkErrorAndLeavesNoOutstandingEntry() throws Exception {
        FakeTransport transport = new FakeTransport();
        transport.failPublish = true;
        try (AuthzRequester r = AuthzRequester.create(transport, TENANT, subkey(), AuthzRequester.Options.defaults())) {
            assertThrows(NetworkError.class, () -> r.check(SUBJECT, "a", RESOURCE, null));
            assertEquals(0, r.outstanding());
        }
    }

    // ---- construction and request building -----------------------------------------------------------

    @Test
    void aReplyQueueThatIsNotPrivateIsRefused() {
        for (String queue : new String[] {"", "axiam.authz.response", "axiam.mail.outbound"}) {
            FakeTransport transport = new FakeTransport();
            transport.queue = queue;
            assertThrows(IllegalArgumentException.class,
                    () -> AuthzRequester.create(transport, TENANT, subkey(), AuthzRequester.Options.defaults()),
                    "reply queue \"" + queue + "\" must be refused");
            assertTrue(transport.closedByRequester, "the refused queue's consumer must be stopped");
        }
        assertThrows(IllegalArgumentException.class,
                () -> AuthzRequester.create(new FakeTransport(), "not-a-uuid", subkey(), AuthzRequester.Options.defaults()));
        assertThrows(IllegalArgumentException.class,
                () -> AuthzRequester.create(new FakeTransport(), TENANT, new byte[0], AuthzRequester.Options.defaults()));
        assertThrows(IllegalArgumentException.class,
                () -> AuthzRequester.create(new FakeTransport(), TENANT, subkey(),
                        AuthzRequester.Options.defaults().withTimeout(Duration.ZERO)));
    }

    @Test
    void unsignableInputIsRefusedBeforeAnythingIsPublished() throws Exception {
        FakeTransport transport = new FakeTransport();
        try (AuthzRequester r = AuthzRequester.create(transport, TENANT, subkey(), AuthzRequester.Options.defaults())) {
            assertThrows(IllegalArgumentException.class, () -> r.checkAsync("x", "a", RESOURCE, null));
            assertThrows(IllegalArgumentException.class, () -> r.checkAsync(SUBJECT, "a", "x", null));
            assertThrows(IllegalArgumentException.class, () -> r.checkAsync(SUBJECT, "a\ud800b", RESOURCE, null));
            assertThrows(IllegalArgumentException.class, () -> r.checkAsync(SUBJECT, "a", RESOURCE, "b\udc00"));
            assertThrows(IllegalArgumentException.class, () -> r.checkAsync(null, "a", RESOURCE, null));
            assertTrue(transport.published.isEmpty());
        }
    }

    @Test
    void controlCharactersAreEscapedTheWayTheServerWritesThem() throws Exception {
        try (AuthzRequester r = requester(AuthzRequester.Options.defaults())) {
            byte[] wire = r.buildRequest(CORRELATION, SUBJECT, "a\u0001\b\f\n\r\t\u001fz\u007f ", RESOURCE, null, NONCE);
            String text = new String(wire, StandardCharsets.UTF_8);
            assertTrue(text.contains("\"action\":\"a\\u0001\\b\\f\\n\\r\\t\\u001fz\u007f \""), text);
        }
    }

    // ---- the RabbitMQ transport ---------------------------------------------------------------------

    @Test
    void theRabbitTransportDeclaresAPrivateExclusiveReplyQueueAndPublishesOnTheDefaultExchange() throws Exception {
        List<Object[]> calls = new ArrayList<>();
        DeliverCallback[] deliver = new DeliverCallback[1];
        List<AmqpTestDoubles.AckNack> acks = new ArrayList<>();
        InvocationHandler handler = (proxy, method, args) -> {
            switch (method.getName()) {
                case "queueDeclare":
                    calls.add(new Object[] {"queueDeclare", args[0], args[1], args[2], args[3]});
                    return new com.rabbitmq.client.impl.AMQImpl.Queue.DeclareOk("amq.gen-abc", 0, 0);
                case "basicConsume":
                    // (queue, autoAck, consumerTag, noLocal, exclusive, arguments, deliverCallback, cancelCallback)
                    calls.add(new Object[] {"basicConsume", args[0], args[1], args[3], args[4]});
                    deliver[0] = (DeliverCallback) args[6];
                    return "ctag-1";
                case "basicPublish":
                    calls.add(new Object[] {"basicPublish", args[0], args[1], args[2], args[3]});
                    return null;
                case "basicCancel":
                    calls.add(new Object[] {"basicCancel", args[0]});
                    return null;
                case "basicAck":
                    acks.add(new AmqpTestDoubles.AckNack("ack", (long) args[0], (boolean) args[1], false));
                    return null;
                case "basicNack":
                    acks.add(new AmqpTestDoubles.AckNack("nack", (long) args[0], (boolean) args[1], (boolean) args[2]));
                    return null;
                case "toString":
                    return "channel";
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "equals":
                    return proxy == args[0];
                default:
                    return null;
            }
        };
        Channel channel = (Channel) Proxy.newProxyInstance(
                Channel.class.getClassLoader(), new Class<?>[] {Channel.class}, handler);

        AuthzRequester r = AuthzRequester.create(channel, TENANT, subkey());
        assertEquals("amq.gen-abc", r.replyTo());

        // Broker-named (empty name), not durable, auto-delete, EXCLUSIVE; consumed exclusively, manual ack.
        assertArrayEqualsRow(calls.get(0), "queueDeclare", "", false, true, true);
        assertArrayEqualsRow(calls.get(1), "basicConsume", "amq.gen-abc", false, false, true);

        CompletableFuture<Decision> future = r.checkAsync(SUBJECT, "documents:read", RESOURCE, null);
        Object[] publish = calls.get(2);
        assertEquals("basicPublish", publish[0]);
        assertEquals("", publish[1], "the default exchange");
        assertEquals(AuthzRequester.AUTHZ_REQUEST_QUEUE, publish[2]);
        AMQP.BasicProperties props = (AMQP.BasicProperties) publish[3];
        assertEquals("amq.gen-abc", props.getReplyTo());
        assertNotNull(props.getCorrelationId());
        JsonNode req = MAPPER.readTree((byte[]) publish[4]);
        assertEquals(props.getCorrelationId(), req.get("correlation_id").asText());

        // A genuine delivery through the consumer callback is acked on the channel; a forged one is nacked
        // without requeue.
        String answer = "{\"correlation_id\":\"" + props.getCorrelationId() + "\",\"allowed\":false,\"reason_code\":"
                + "\"no_grant\",\"tenant_id\":\"" + TENANT + "\",\"nonce\":\"" + req.get("nonce").asText() + "\"}";
        Envelope env7 = new Envelope(7L, false, "", "amq.gen-abc");
        deliver[0].handle("ctag-1", new com.rabbitmq.client.Delivery(env7, new AMQP.BasicProperties(),
                signWith(subkeyFor(OTHER_TENANT, 2), answer)));
        assertFalse(future.isDone());
        deliver[0].handle("ctag-1", new com.rabbitmq.client.Delivery(new Envelope(8L, false, "", "amq.gen-abc"),
                new AMQP.BasicProperties(), signWith(subkey(), answer)));
        assertFalse(future.get(2, TimeUnit.SECONDS).allowed());
        assertEquals(List.of(new AmqpTestDoubles.AckNack("nack", 7L, false, false),
                new AmqpTestDoubles.AckNack("ack", 8L, false, false)), acks);

        r.close();
        assertEquals("basicCancel", calls.get(calls.size() - 1)[0]);
        assertEquals("ctag-1", calls.get(calls.size() - 1)[1]);
    }

    private static void assertArrayEqualsRow(Object[] actual, Object... expected) {
        assertEquals(List.of(expected), List.of(actual));
    }
}
