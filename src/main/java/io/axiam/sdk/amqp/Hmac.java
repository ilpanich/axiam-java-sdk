package io.axiam.sdk.amqp;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jspecify.annotations.Nullable;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * HMAC-SHA256 verify-before-handler primitive for inbound AMQP messages
 * (CONTRACT.md &sect;8, D-13).
 *
 * <p><strong>Canonicalization is wire/insertion-order preserving, NEVER
 * alphabetically sorted.</strong> The canonical Rust signer
 * ({@code crates/axiam-amqp/src/messages.rs}'s {@code sign_payload}) signs
 * the {@code serde_json} struct-declaration-order serialization of the
 * message body (with {@code hmac_signature} absent). Jackson's
 * {@link ObjectNode} is backed by a {@code LinkedHashMap} and preserves
 * insertion order from parsing by default — {@link ObjectNode#remove(String)}
 * mutates that same map in place, preserving the relative order of all
 * remaining keys. This is the single load-bearing property of this class:
 * do NOT introduce a {@code TreeMap}/sorted copy or enable any
 * key-ordering/alphabetizing Jackson feature here. This mirrors the
 * empirically-proven finding from Phase 19 (Python), re-verified in this
 * plan against the same real Rust-signed fixture (20-RESEARCH.md Pattern 5,
 * 20-PATTERNS.md "CRITICAL key-order divergence from Go").
 */
public final class Hmac {

    /**
     * Strict reader for a delivery body (C2): a key repeated at any depth, or any content after the
     * JSON object, is a parse failure. Both are ways for the received bytes to say one thing to this
     * verifier and another to whatever reads them next, and a legitimate AXIAM message has neither.
     */
    private static final ObjectMapper MAPPER = JsonMapper.builder()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();
    private static final String ALGO = "HmacSHA256";

    private Hmac() {
    }

    /**
     * Returns {@code true} iff {@code body}'s {@code hmac_signature} field
     * matches {@code HMAC-SHA256(signingKey, canonical_json_of(body_without_hmac_signature))},
     * computed via constant-time comparison.
     *
     * <p>Never throws: malformed JSON, a missing/null signature, non-hex
     * signature text, or a wrong-length signature all verify as
     * {@code false} — matching &sect;8.3's strict-mode default that rejects
     * (rather than silently accepts) an unparseable or absent signature.
     *
     * @param signingKey the per-tenant AMQP signing secret
     * @param body       the raw AMQP delivery body bytes
     * @return {@code true} if the signature is valid, {@code false} otherwise
     */
    public static boolean verify(byte[] signingKey, byte[] body) {
        return verifiedCanonical(signingKey, body) != null;
    }

    /**
     * Verifies {@code body} and returns the canonical bytes the HMAC covered &mdash; the one byte
     * sequence a caller may build its view of the message from (C2).
     *
     * <p>The received body is never what a handler should read: it can carry whitespace, a
     * repeated key or trailing content that the verifier's tree resolved one way and a different
     * reader resolves another. The returned bytes are exactly the {@code HMAC-SHA256} input
     * (the body minus {@code hmac_signature}, compact, in wire order), so what is delivered is what
     * was signed. A body with a repeated key at any depth, or with content after the JSON object,
     * is refused.
     *
     * @param signingKey the per-tenant AMQP signing secret
     * @param body       the raw AMQP delivery body bytes
     * @return the verified canonical bytes, or {@code null} when the body does not verify
     */
    static byte @Nullable [] verifiedCanonical(byte[] signingKey, byte[] body) {
        try {
            JsonNode root = MAPPER.readTree(body);
            if (!(root instanceof ObjectNode node)) {
                return null;
            }
            JsonNode sigNode = node.get("hmac_signature");
            if (sigNode == null || sigNode.isNull()) {
                return null; // §8.3 strict mode: missing signature = reject
            }
            String sigHex = sigNode.asText();

            // remove() mutates the SAME LinkedHashMap-backed ObjectNode in
            // place, preserving the relative order of all remaining keys —
            // this is the load-bearing property (see class Javadoc).
            node.remove("hmac_signature");
            byte[] canonical = MAPPER.writeValueAsBytes(node);

            byte[] expected = HexFormat.of().parseHex(sigHex);

            Mac mac = Mac.getInstance(ALGO);
            mac.init(new SecretKeySpec(signingKey, ALGO));
            byte[] computed = mac.doFinal(canonical);

            return MessageDigest.isEqual(computed, expected) ? canonical : null; // constant-time compare
        } catch (Exception e) {
            return null; // parse failure / bad hex / bad key length -> reject, never throw
        }
    }
}
