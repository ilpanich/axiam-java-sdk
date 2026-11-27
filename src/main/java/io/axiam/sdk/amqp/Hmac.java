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
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * HMAC-SHA256 verify-before-handler primitive for inbound AMQP messages
 * (CONTRACT.md &sect;8, D-13).
 *
 * <p><strong>The signature is checked over the received bytes, never over a
 * re-serialization</strong> (CONTRACT.md &sect;8 rule 2, contract 1.69; #882). The
 * canonical bytes are the delivered body with its trailing
 * {@code ,"hmac_signature":"<64 hex>"} member cut out. A signer's encoder and this
 * SDK's JSON writer can disagree (escape case, number rendering, key order), and a
 * rebuilt form then refuses a genuine message or, worse, lets a handler read
 * something other than what was verified (C2). A body whose signature is not the
 * trailing member, is {@code null} or is not a string, has a repeated key at any
 * depth, or has content after the object, is refused. So is a body whose canonical members are not
 * exactly an {@code AuthzRequest}'s or an {@code AuditEventMessage}'s declared members in declaration
 * order (rule 2c): another tenant-signed shape cannot pass for an event.
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
    /** Step (1)/(2) reader: one object, nothing after it, repeated names tolerated (they are refused at (3)). */
    private static final ObjectMapper LENIENT = JsonMapper.builder()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();
    private static final String ALGO = "HmacSHA256";

    private Hmac() {
    }

    /**
     * Returns {@code true} iff {@code body}'s trailing {@code hmac_signature} member
     * matches {@code HMAC-SHA256(signingKey, received_bytes_without_that_member)},
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

    /** Why a delivery was discarded (CONTRACT.md &sect;8 rule 4; the closed vocabulary of the discard event). */
    enum Reason {
        MALFORMED("malformed"), UNSIGNED("unsigned"), SIGNATURE("signature"), KEY_VERSION("key_version"),
        STALE("stale"), REPLAY("replay");

        private final String wire;

        Reason(String wire) {
            this.wire = wire;
        }

        String wire() {
            return wire;
        }
    }

    /** The result of {@link #inspect}: the verified canonical bytes, or the first reason that applies. */
    record Inspection(byte @Nullable [] canonical, @Nullable Reason reason) {
    }

    private static Inspection refused(Reason reason) {
        return new Inspection(null, reason);
    }

    /**
     * Verifies {@code body} for the one configured {@code type} and returns either the canonical bytes the HMAC
     * covered &mdash; the one byte sequence a caller may build its view of the message from (C2) &mdash; or the
     * first discard reason that applies, in the normative order of CONTRACT.md &sect;8 rule 4 (positions (1) to
     * (4); the decode and the v2 gates, (5) to (8), belong to the caller):
     * (1) not one JSON object (first byte not {@code {}, a byte-order mark included, or it does not parse, trailing
     * content included) is {@code malformed}; (2) no top-level {@code hmac_signature} is {@code unsigned};
     * (3) anything else steps 2a to 2c refuse &mdash; a repeated member name, a signature that is not the trailing
     * 64-hex string, a layout that is not {@code type}'s (the typed check) &mdash; is {@code malformed}, before the
     * HMAC is computed; (4) a failing HMAC is {@code signature}.
     */
    static Inspection inspect(byte[] signingKey, byte[] body, EventType type) {
        try {
            // (1) Exactly one JSON object, nothing after it. The first byte must be `{`: Jackson would skip a
            // leading UTF-8 byte order mark, and a BOM is refused, never stripped (D-10).
            if (body.length == 0 || body[0] != '{') {
                return refused(Reason.MALFORMED);
            }
            JsonNode root;
            try {
                root = LENIENT.readTree(body);
            } catch (Exception e) {
                return refused(Reason.MALFORMED);
            }
            if (!(root instanceof ObjectNode)) {
                return refused(Reason.MALFORMED);
            }
            // (2) No top-level hmac_signature at all: unsigned, whatever else the body lacks or repeats.
            if (!root.has("hmac_signature")) {
                return refused(Reason.UNSIGNED);
            }
            // (3) Rule a: no member name repeated at any depth.
            try {
                root = MAPPER.readTree(body);
            } catch (Exception e) {
                return refused(Reason.MALFORMED);
            }
            // Rule b: the body ends in `,"hmac_signature":"<64 hex>"}`; the canonical bytes are the
            // received bytes before that member, then `}`. Nothing is re-serialized (#882): an
            // encoder that writes a character, a number or an escape differently from serde_json
            // would otherwise refuse a genuine message.
            int suffix = SIGNATURE_MEMBER.length + SIGNATURE_HEX_LENGTH + 2;
            if (body.length <= suffix) {
                return refused(Reason.MALFORMED);
            }
            int start = body.length - suffix;
            for (int i = 0; i < SIGNATURE_MEMBER.length; i++) {
                if (body[start + i] != SIGNATURE_MEMBER[i]) {
                    return refused(Reason.MALFORMED);
                }
            }
            if (body[body.length - 2] != '"' || body[body.length - 1] != '}') {
                return refused(Reason.MALFORMED);
            }
            String sigHex = new String(body, start + SIGNATURE_MEMBER.length, SIGNATURE_HEX_LENGTH,
                    java.nio.charset.StandardCharsets.ISO_8859_1);
            byte[] expected = HexFormat.of().parseHex(sigHex);
            // The member the tree sees must be that same trailing one (a second, earlier
            // hmac_signature is a repeated key and was refused above).
            JsonNode sigNode = root.get("hmac_signature");
            if (sigNode == null || !sigNode.isTextual() || !sigNode.asText().equals(sigHex)) {
                return refused(Reason.MALFORMED);
            }
            byte[] canonical = new byte[start + 1];
            System.arraycopy(body, 0, canonical, 0, start);
            canonical[start] = '}';

            // Rule c (MUST), typed (D-9): the canonical bytes' top-level member names, compared exactly, are
            // THIS type's declared members in declaration order, optional ones present in place or absent,
            // nothing else. Every tenant-subkey-signed shape shares the key, so another type's genuine message
            // passes the HMAC; only the layout tells it apart, and it is refused here, before the HMAC.
            List<String> names = new ArrayList<>();
            MAPPER.readTree(canonical).fieldNames().forEachRemaining(names::add);
            if (!type.hasLayout(names)) {
                return refused(Reason.MALFORMED);
            }

            // (4) The HMAC, compared in constant time.
            Mac mac = Mac.getInstance(ALGO);
            mac.init(new SecretKeySpec(signingKey, ALGO));
            byte[] computed = mac.doFinal(canonical);

            return MessageDigest.isEqual(computed, expected)
                    ? new Inspection(canonical, null) : refused(Reason.SIGNATURE);
        } catch (Exception e) {
            return refused(Reason.MALFORMED); // bad hex / bad key length / anything unforeseen: never throw
        }
    }

    /**
     * Whether {@code body}'s trailing signature verifies over its canonical bytes for <em>either</em> signed
     * event layout. A signature primitive for tests and tooling: an event consumer never uses it, because a
     * consumer accepts exactly one configured type ({@link #inspect}).
     */
    static byte @Nullable [] verifiedCanonical(byte[] signingKey, byte[] body) {
        for (EventType type : EventType.values()) {
            Inspection i = inspect(signingKey, body, type);
            if (i.canonical() != null) {
                return i.canonical();
            }
        }
        return null;
    }

    private static final byte[] SIGNATURE_MEMBER =
            ",\"hmac_signature\":\"".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final int SIGNATURE_HEX_LENGTH = 64;
}
