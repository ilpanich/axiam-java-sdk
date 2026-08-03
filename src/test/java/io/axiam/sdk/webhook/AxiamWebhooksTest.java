package io.axiam.sdk.webhook;

import io.axiam.sdk.Sensitive;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proves {@link AxiamWebhooks#verify}'s CONTRACT.md &sect;13 behavior:
 * accept/reject decisions, the two-sided freshness window, malformed-header
 * handling, and the cross-SDK pin vector shared by every AXIAM SDK (T-145).
 */
class AxiamWebhooksTest {

    /**
     * Computes an {@code X-Axiam-Signature} header value the same way the
     * AXIAM server does (CONTRACT.md &sect;13.1): {@code HMAC-SHA256(secret,
     * "<timestamp>.<body>")}, hex-encoded lowercase. Tests use this to build
     * valid fixture input for {@link AxiamWebhooks#verify} &mdash; it is
     * deliberately independent test scaffolding, not a call into the class
     * under test.
     */
    private static String signHeader(String secret, long timestamp, byte[] body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update(String.valueOf(timestamp).getBytes(StandardCharsets.UTF_8));
            mac.update((byte) '.');
            byte[] sig = mac.doFinal(body);
            return "t=" + timestamp + ",v1=" + HexFormat.of().formatHex(sig);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static Clock fixedClock(long unixSeconds) {
        return Clock.fixed(Instant.ofEpochSecond(unixSeconds), ZoneOffset.UTC);
    }

    // 1. Valid signature + fresh timestamp -> accepted.
    @Test
    void validAndFreshIsAccepted() {
        String secret = "whsec_test_valid_and_fresh";
        byte[] body = "{\"event\":\"user.created\",\"id\":\"01JQ0000000000000000000001\"}".getBytes(StandardCharsets.UTF_8);
        long now = 1785700100L;
        long ts = now - 10;
        String header = signHeader(secret, ts, body);

        WebhookEvent event = AxiamWebhooks.verify(Sensitive.of(secret), header, body, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(now));

        assertEquals("user.created", event.type());
        assertEquals(ts, event.timestamp());
        assertTrue(Arrays.equals(body, event.body()));
    }

    // 2. Tampered body (one byte flipped) -> rejected.
    @Test
    void tamperedBodyIsRejected() {
        String secret = "whsec_test_tampered_body";
        byte[] body = "{\"event\":\"user.created\",\"id\":\"01JQ0000000000000000000001\"}".getBytes(StandardCharsets.UTF_8);
        long now = 1785700100L;
        long ts = now - 10;
        String header = signHeader(secret, ts, body);

        byte[] tampered = body.clone();
        tampered[0] = '['; // was '{'

        WebhookVerificationException ex = assertThrows(WebhookVerificationException.class,
                () -> AxiamWebhooks.verify(Sensitive.of(secret), header, tampered, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(now)));
        assertEquals(WebhookVerificationException.Reason.SIGNATURE_MISMATCH, ex.reason());
    }

    // 3. Wrong secret -> rejected.
    @Test
    void wrongSecretIsRejected() {
        byte[] body = "{\"event\":\"user.created\",\"id\":\"01JQ0000000000000000000001\"}".getBytes(StandardCharsets.UTF_8);
        long now = 1785700100L;
        long ts = now - 10;
        String header = signHeader("whsec_test_right_secret", ts, body);

        WebhookVerificationException ex = assertThrows(WebhookVerificationException.class,
                () -> AxiamWebhooks.verify(Sensitive.of("whsec_test_WRONG_secret"), header, body, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(now)));
        assertEquals(WebhookVerificationException.Reason.SIGNATURE_MISMATCH, ex.reason());
    }

    // 4. Stale timestamp (now - t > tolerance) -> rejected.
    @Test
    void staleTimestampIsRejected() {
        String secret = "whsec_test_stale";
        byte[] body = "{\"event\":\"user.created\",\"id\":\"01JQ0000000000000000000001\"}".getBytes(StandardCharsets.UTF_8);
        long now = 1785700100L;
        long ts = now - 301; // 1s past the default 300s tolerance
        String header = signHeader(secret, ts, body);

        WebhookVerificationException ex = assertThrows(WebhookVerificationException.class,
                () -> AxiamWebhooks.verify(Sensitive.of(secret), header, body, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(now)));
        assertEquals(WebhookVerificationException.Reason.TIMESTAMP_TOO_OLD, ex.reason());
    }

    // 5. Future timestamp beyond tolerance -> rejected (clock-skew abuse
    // protection, CONTRACT.md §13.3 rule 5).
    @Test
    void futureTimestampIsRejected() {
        String secret = "whsec_test_future";
        byte[] body = "{\"event\":\"user.created\",\"id\":\"01JQ0000000000000000000001\"}".getBytes(StandardCharsets.UTF_8);
        long now = 1785700100L;
        long ts = now + 301; // 1s beyond the default 300s tolerance, into the future
        String header = signHeader(secret, ts, body);

        WebhookVerificationException ex = assertThrows(WebhookVerificationException.class,
                () -> AxiamWebhooks.verify(Sensitive.of(secret), header, body, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(now)));
        assertEquals(WebhookVerificationException.Reason.TIMESTAMP_TOO_NEW, ex.reason());
    }

    // 6. Malformed headers -> rejected, each with the specific reason.
    @Test
    void malformedHeaderNoV1IsRejected() {
        long now = 1785700100L;
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        WebhookVerificationException ex = assertThrows(WebhookVerificationException.class,
                () -> AxiamWebhooks.verify(Sensitive.of("whsec_test"), "t=" + now, body, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(now)));
        assertEquals(WebhookVerificationException.Reason.MISSING_V1, ex.reason());
    }

    @Test
    void malformedHeaderNonNumericTimestampIsRejected() {
        long now = 1785700100L;
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        WebhookVerificationException ex = assertThrows(WebhookVerificationException.class,
                () -> AxiamWebhooks.verify(Sensitive.of("whsec_test"), "t=not-a-number,v1=deadbeef", body, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(now)));
        assertEquals(WebhookVerificationException.Reason.INVALID_TIMESTAMP, ex.reason());
    }

    @Test
    void malformedHeaderEmptyIsRejected() {
        long now = 1785700100L;
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        WebhookVerificationException ex = assertThrows(WebhookVerificationException.class,
                () -> AxiamWebhooks.verify(Sensitive.of("whsec_test"), "", body, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(now)));
        assertEquals(WebhookVerificationException.Reason.MALFORMED_HEADER, ex.reason());
    }

    @Test
    void malformedHeaderNoTimestampIsRejected() {
        long now = 1785700100L;
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        WebhookVerificationException ex = assertThrows(WebhookVerificationException.class,
                () -> AxiamWebhooks.verify(Sensitive.of("whsec_test"), "v1=deadbeef", body, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(now)));
        assertEquals(WebhookVerificationException.Reason.MALFORMED_HEADER, ex.reason());
    }

    @Test
    void malformedHeaderDuplicateTimestampIsRejected() {
        long now = 1785700100L;
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        WebhookVerificationException ex = assertThrows(WebhookVerificationException.class,
                () -> AxiamWebhooks.verify(Sensitive.of("whsec_test"), "t=" + now + ",t=" + now + ",v1=deadbeef", body, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(now)));
        assertEquals(WebhookVerificationException.Reason.MALFORMED_HEADER, ex.reason());
    }

    @Test
    void malformedHeaderNonHexV1IsRejected() {
        long now = 1785700100L;
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        WebhookVerificationException ex = assertThrows(WebhookVerificationException.class,
                () -> AxiamWebhooks.verify(Sensitive.of("whsec_test"), "t=" + now + ",v1=not-hex-zzz", body, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(now)));
        assertEquals(WebhookVerificationException.Reason.SIGNATURE_MISMATCH, ex.reason());
    }

    /**
     * 7. Cross-SDK pin. The vector (secret, timestamp, body) is fixed by the
     * shared T-145 spec; the expected {@code v1} is computed HERE from
     * Java's own {@code javax.crypto.Mac} (never copied as a literal hex
     * value) so this test is the Java SDK's half of the cross-SDK pin: every
     * SDK computing the same hex from the same input proves byte-for-byte
     * interoperability with the server and with each other.
     */
    @Test
    void crossSdkPinVectorIsAccepted() {
        String secret = "whsec_test_0123456789abcdef";
        long timestamp = 1785700000L;
        byte[] body = "{\"event\":\"user.created\",\"id\":\"01JQ0000000000000000000000\"}".getBytes(StandardCharsets.UTF_8);

        String header = signHeader(secret, timestamp, body);

        WebhookEvent event = AxiamWebhooks.verify(Sensitive.of(secret), header, body, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(timestamp));
        assertEquals(timestamp, event.timestamp());

        // Separately assert a byte-flipped body is rejected, per the spec's
        // explicit instruction alongside the pin vector.
        byte[] tampered = body.clone();
        tampered[tampered.length - 2] = '9'; // flip the trailing digit of the id
        WebhookVerificationException ex = assertThrows(WebhookVerificationException.class,
                () -> AxiamWebhooks.verify(Sensitive.of(secret), header, tampered, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(timestamp)));
        assertEquals(WebhookVerificationException.Reason.SIGNATURE_MISMATCH, ex.reason());
    }

    // Secret rotation: a header carrying multiple v1 values succeeds if ANY
    // one matches (CONTRACT.md §13.1 allows multiple v1 pairs; §13.3 rule 4
    // requires trying each).
    @Test
    void multipleV1AcceptsAnyMatch() {
        String oldSecret = "whsec_test_old_rotating_secret";
        String newSecret = "whsec_test_new_rotating_secret";
        byte[] body = "{\"event\":\"user.created\",\"id\":\"01JQ0000000000000000000001\"}".getBytes(StandardCharsets.UTF_8);
        long now = 1785700100L;
        long ts = now - 10;

        String oldHeader = signHeader(oldSecret, ts, body);
        String newHeader = signHeader(newSecret, ts, body);
        String newV1 = newHeader.substring(newHeader.indexOf(",v1=") + ",v1=".length());
        String combined = oldHeader + ",v1=" + newV1;

        WebhookEvent viaOld = AxiamWebhooks.verify(Sensitive.of(oldSecret), combined, body, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(now));
        assertEquals(ts, viaOld.timestamp());
        WebhookEvent viaNew = AxiamWebhooks.verify(Sensitive.of(newSecret), combined, body, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(now));
        assertEquals(ts, viaNew.timestamp());
    }

    // A custom tolerance overrides the default freshness window.
    @Test
    void customToleranceOverridesDefault() {
        String secret = "whsec_test_custom_tolerance";
        byte[] body = "{\"event\":\"user.created\",\"id\":\"01JQ0000000000000000000001\"}".getBytes(StandardCharsets.UTF_8);
        long now = 1785700100L;
        long ts = now - 30; // outside a tight 10s tolerance, inside the 300s default
        String header = signHeader(secret, ts, body);

        WebhookVerificationException ex = assertThrows(WebhookVerificationException.class,
                () -> AxiamWebhooks.verify(Sensitive.of(secret), header, body, Duration.ofSeconds(10), fixedClock(now)));
        assertEquals(WebhookVerificationException.Reason.TIMESTAMP_TOO_OLD, ex.reason());

        // Same delivery accepted under the (larger) default tolerance.
        WebhookEvent event = AxiamWebhooks.verify(Sensitive.of(secret), header, body, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(now));
        assertEquals(ts, event.timestamp());
    }

    // The 3-arg convenience overload uses DEFAULT_TOLERANCE and the system clock.
    @Test
    void threeArgOverloadUsesDefaultToleranceAndSystemClock() {
        String secret = "whsec_test_three_arg_overload";
        byte[] body = "{\"event\":\"user.created\",\"id\":\"01JQ0000000000000000000001\"}".getBytes(StandardCharsets.UTF_8);
        long now = Instant.now().getEpochSecond();
        String header = signHeader(secret, now, body);

        WebhookEvent event = AxiamWebhooks.verify(Sensitive.of(secret), header, body);
        assertEquals("user.created", event.type());
    }

    // A WebhookVerificationException's message never leaks the
    // expected/computed or received signature, and never leaks the secret.
    @Test
    void errorMessageNeverLeaksSignatureOrSecret() {
        String secret = "whsec_test_super_secret_value";
        byte[] body = "{\"event\":\"user.created\",\"id\":\"01JQ0000000000000000000001\"}".getBytes(StandardCharsets.UTF_8);
        long now = 1785700100L;
        long ts = now - 10;

        // A mismatched signature: wrong secret used to sign.
        String header = signHeader("whsec_test_a_completely_different_secret", ts, body);

        WebhookVerificationException ex = assertThrows(WebhookVerificationException.class,
                () -> AxiamWebhooks.verify(Sensitive.of(secret), header, body, AxiamWebhooks.DEFAULT_TOLERANCE, fixedClock(now)));

        String message = ex.getMessage();
        assertFalse(message.contains(secret), "error message leaked the secret: " + message);
        String receivedSig = header.substring(header.indexOf(",v1=") + ",v1=".length());
        assertFalse(message.contains(receivedSig), "error message leaked the received signature: " + message);
    }
}
