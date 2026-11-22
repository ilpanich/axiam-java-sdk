package io.axiam.sdk.amqp;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DeliverCallback;

import io.axiam.sdk.amqp.AmqpTestDoubles.AckNack;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C2 parity (CONTRACT.md &sect;8; audit finding C2, found in the Go SDK): only HMAC-covered
 * values may reach the handler. The Go consumer authenticated a canonical form rebuilt from a
 * case-folding struct decode and then handed the handler a parse of the raw body; a body carrying
 * forged keys followed by the signed values under case-variant keys verified while the handler saw
 * the forged ones.
 *
 * <p>This SDK authenticates a re-serialization of the received body too ({@link Hmac}), and hands
 * the handler the received bytes. So the question these tests answer is whether the bytes the
 * handler receives can say something the signature does not.
 */
class AmqpConsumerC2Test {

    private static final String SIGNED_SUBJECT = "33333333-3333-3333-3333-333333333333";
    private static final String SIGNED_TENANT = "22222222-2222-2222-2222-222222222222";
    private static final String FORGED_SUBJECT = "99999999-9999-9999-9999-999999999999";
    private static final String FORGED_TENANT = "88888888-8888-8888-8888-888888888888";
    private static final String CORRELATION = "11111111-1111-1111-1111-111111111111";
    private static final String RESOURCE = "44444444-4444-4444-4444-444444444444";
    private static final Instant ISSUED_AT = Instant.parse("2026-07-10T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(ISSUED_AT, ZoneOffset.UTC);
    private static final byte[] KEY = "c2-test-subkey-not-a-real-secret".getBytes(StandardCharsets.UTF_8);

    private static final String TAIL =
            "\"key_version\":2,\"nonce\":\"55555555-5555-5555-5555-555555555555\",\"issued_at\":\"2026-07-10T12:00:00Z\"";

    /** The server-order canonical form of the one legitimate request. */
    private static String canonical(String action) {
        return "{\"correlation_id\":\"" + CORRELATION + "\",\"tenant_id\":\"" + SIGNED_TENANT
                + "\",\"subject_id\":\"" + SIGNED_SUBJECT + "\",\"action\":\"" + action
                + "\",\"resource_id\":\"" + RESOURCE + "\"," + TAIL + "}";
    }

    private static String sign(String canonical) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
    }

    private record Outcome(List<byte[]> seen, List<AckNack> calls) {
        boolean handlerRan() {
            return !seen.isEmpty();
        }
    }

    private static Outcome run(byte[] body) throws Exception {
        List<AckNack> calls = new ArrayList<>();
        List<byte[]> seen = new ArrayList<>();
        Channel channel = AmqpTestDoubles.recordingChannel(calls);
        Logger logger = AmqpTestDoubles.recordingLogger(new ArrayList<>());
        DeliverCallback callback = AmqpConsumer.deliverCallback(channel, KEY, seen::add, logger,
                Duration.ofSeconds(300), CLOCK, new NonceStore(Duration.ofSeconds(600)));
        callback.handle("tag", AmqpTestDoubles.delivery(1L, body));
        return new Outcome(seen, calls);
    }

    private static void assertNackedAndHandlerNeverRan(Outcome o) {
        assertFalse(o.handlerRan(), "the handler must never be invoked");
        assertEquals(1, o.calls().size());
        assertEquals("nack", o.calls().get(0).type());
        assertFalse(o.calls().get(0).requeue());
    }

    /** What a first-wins, streaming reader of the delivered bytes takes {@code field} to be. */
    private static String firstWins(byte[] json, String field) throws Exception {
        try (JsonParser p = new ObjectMapper().getFactory().createParser(json)) {
            if (p.nextToken() != JsonToken.START_OBJECT) {
                return null;
            }
            while (p.nextToken() == JsonToken.FIELD_NAME) {
                String name = p.currentName();
                p.nextToken();
                if (name.equals(field)) {
                    return p.getValueAsString();
                }
                p.skipChildren();
            }
        }
        return null;
    }

    // --- the Go regression test, ported --------------------------------------

    @Test
    void forgedLowerCaseKeysFollowedBySignedValuesUnderCaseVariantKeysNeverReachTheHandler() throws Exception {
        String sig = sign(canonical("documents:read"));
        String forged = "{\"correlation_id\":\"" + CORRELATION + "\","
                + "\"subject_id\":\"" + FORGED_SUBJECT + "\",\"action\":\"documents:delete\",\"tenant_id\":\""
                + FORGED_TENANT + "\","
                + "\"SUBJECT_ID\":\"" + SIGNED_SUBJECT + "\",\"ACTION\":\"documents:read\",\"TENANT_ID\":\""
                + SIGNED_TENANT + "\","
                + "\"resource_id\":\"" + RESOURCE + "\"," + TAIL + ",\"hmac_signature\":\"" + sig + "\"}";

        assertNackedAndHandlerNeverRan(run(forged.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void plainTamperControlIsNacked() throws Exception {
        String sig = sign(canonical("documents:read"));
        String tampered = canonical("documents:delete").replaceAll("}$", ",\"hmac_signature\":\"" + sig + "\"}");
        assertNackedAndHandlerNeverRan(run(tampered.getBytes(StandardCharsets.UTF_8)));
    }

    // --- the same root cause through the other door: duplicate keys ------------

    @Test
    void exactDuplicateKeysForgedValueFirstAreNeverDeliveredToTheHandler() throws Exception {
        String sig = sign(canonical("documents:read"));
        // The same key twice. A last-wins tree (the verifier's) sees the signed value; a first-wins or
        // streaming reader of the delivered bytes sees the forged one.
        String dup = "{\"correlation_id\":\"" + CORRELATION + "\",\"tenant_id\":\"" + SIGNED_TENANT + "\","
                + "\"subject_id\":\"" + FORGED_SUBJECT + "\",\"subject_id\":\"" + SIGNED_SUBJECT + "\","
                + "\"action\":\"documents:read\",\"resource_id\":\"" + RESOURCE + "\"," + TAIL
                + ",\"hmac_signature\":\"" + sig + "\"}";

        Outcome o = run(dup.getBytes(StandardCharsets.UTF_8));

        // Secure behaviour: the body is refused, and in any case no value the signature does not cover
        // may be readable from what the handler gets.
        assertNackedAndHandlerNeverRan(o);
    }

    @Test
    void trailingContentAfterTheSignedObjectIsNeverDeliveredToTheHandler() throws Exception {
        String sig = sign(canonical("documents:read"));
        String withTrailer = canonical("documents:read").replaceAll("}$", ",\"hmac_signature\":\"" + sig + "\"}")
                + "{\"subject_id\":\"" + FORGED_SUBJECT + "\"}";

        assertNackedAndHandlerNeverRan(run(withTrailer.getBytes(StandardCharsets.UTF_8)));
    }

    // --- the legitimate message --------------------------------------------------

    @Test
    void aLegitimateMessageIsDeliveredAsExactlyTheBytesTheSignatureCovers() throws Exception {
        String canonical = canonical("documents:read");
        String sig = sign(canonical);
        // Whitespace is insignificant to the signature; the delivered bytes are still the covered ones.
        String wire = canonical.replaceAll("}$", ",\"hmac_signature\":\"" + sig + "\"}");

        Outcome o = run(wire.getBytes(StandardCharsets.UTF_8));

        assertTrue(o.handlerRan());
        assertEquals("ack", o.calls().get(0).type());
        byte[] delivered = o.seen().get(0);
        assertEquals(SIGNED_SUBJECT, firstWins(delivered, "subject_id"));
        assertEquals("documents:read", firstWins(delivered, "action"));
        assertEquals(SIGNED_TENANT, firstWins(delivered, "tenant_id"));
        // The bytes handed over are the bytes the HMAC verifies over.
        assertEquals(sig, hmacHex(delivered));
        assertFalse(new String(delivered, StandardCharsets.UTF_8).contains("hmac_signature"));
    }

    private static String hmacHex(byte[] bytes) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(bytes));
    }
}
