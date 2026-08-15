package io.axiam.sdk.reactor;

import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Builds server-side event bodies for tests: the same declared field order and
 * the same {@code "hmac_signature": null} canonicalization the AXIAM server uses,
 * written out longhand here rather than delegating to {@link ReactorProtocol}.
 *
 * <p>Writing it twice is the point. If a test signed events with the very code
 * under test, a canonicalization bug would cancel out and every assertion would
 * still pass — which is exactly the failure mode the &sect;22.13 vectors exist to
 * catch. Those vectors remain the ground truth; this helper only exists to vary
 * the fields the fixture pins (nonce, timestamp, timeout, payload).
 */
final class ReactorServerTestSupport {

    private ReactorServerTestSupport() {
    }

    static byte[] signEvent(byte[] key, UUID tenant, String event, UUID nonce, Instant issuedAt,
                            int timeoutMs) throws Exception {
        return signEvent(key, tenant, event, nonce, issuedAt, timeoutMs,
                ReactorVectors.MAPPER.createObjectNode().put("sub", "alice"));
    }

    static byte[] signEvent(byte[] key, UUID tenant, String event, UUID nonce, Instant issuedAt,
                            int timeoutMs, ObjectNode payload) throws Exception {
        ObjectNode node = ReactorVectors.MAPPER.createObjectNode();
        node.put("tenant_id", tenant.toString());
        node.put("event", event);
        node.put("correlation_id", UUID.randomUUID().toString());
        node.set("payload", payload);
        node.put("timeout_ms", timeoutMs);
        node.put("key_version", 2);
        node.put("nonce", nonce.toString());
        node.put("issued_at", DateTimeFormatter.ISO_INSTANT.format(
                issuedAt.truncatedTo(ChronoUnit.SECONDS)));
        node.putNull("hmac_signature");
        return sign(key, node);
    }

    /** Signs a tree whose {@code hmac_signature} is already present and null. */
    static byte[] sign(byte[] key, ObjectNode canonical) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        String hex = HexFormat.of().formatHex(
                mac.doFinal(ReactorVectors.MAPPER.writeValueAsBytes(canonical)));
        canonical.put("hmac_signature", hex);
        return ReactorVectors.MAPPER.writeValueAsBytes(canonical);
    }
}
