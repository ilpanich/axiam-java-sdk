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
            // Rule a: exactly one JSON object, nothing after it, no repeated member name at any depth.
            // The first byte must be `{`: Jackson would skip a leading UTF-8 byte order mark.
            if (body.length == 0 || body[0] != '{') {
                return null;
            }
            JsonNode root = MAPPER.readTree(body);
            if (!(root instanceof ObjectNode)) {
                return null;
            }
            // Rule b: the body ends in `,"hmac_signature":"<64 hex>"}`; the canonical bytes are the
            // received bytes before that member, then `}`. Nothing is re-serialized (#882): an
            // encoder that writes a character, a number or an escape differently from serde_json
            // would otherwise refuse a genuine message.
            int suffix = SIGNATURE_MEMBER.length + SIGNATURE_HEX_LENGTH + 2;
            if (body.length <= suffix) {
                return null;
            }
            int start = body.length - suffix;
            for (int i = 0; i < SIGNATURE_MEMBER.length; i++) {
                if (body[start + i] != SIGNATURE_MEMBER[i]) {
                    return null;
                }
            }
            if (body[body.length - 2] != '"' || body[body.length - 1] != '}') {
                return null;
            }
            String sigHex = new String(body, start + SIGNATURE_MEMBER.length, SIGNATURE_HEX_LENGTH,
                    java.nio.charset.StandardCharsets.ISO_8859_1);
            byte[] expected = HexFormat.of().parseHex(sigHex);
            // The member the tree sees must be that same trailing one (a second, earlier
            // hmac_signature is a repeated key and was refused above).
            JsonNode sigNode = root.get("hmac_signature");
            if (sigNode == null || !sigNode.isTextual() || !sigNode.asText().equals(sigHex)) {
                return null;
            }
            byte[] canonical = new byte[start + 1];
            System.arraycopy(body, 0, canonical, 0, start);
            canonical[start] = '}';

            // Rule c (MUST): the canonical bytes' top-level member names, compared exactly, are one
            // signed type's declared members in declaration order, optional ones present in place or
            // absent, nothing else. Every tenant-subkey-signed shape (AuthzResponse, the reactor
            // messages, the cache-invalidation broadcast) shares this key; without this check a
            // decoder that fills absent fields with defaults could take one of them for an event.
            if (!hasDeclaredLayout(MAPPER.readTree(canonical))) {
                return null;
            }

            Mac mac = Mac.getInstance(ALGO);
            mac.init(new SecretKeySpec(signingKey, ALGO));
            byte[] computed = mac.doFinal(canonical);

            return MessageDigest.isEqual(computed, expected) ? canonical : null; // constant-time compare
        } catch (Exception e) {
            return null; // parse failure / bad hex / bad key length -> reject, never throw
        }
    }

    /** A declared member: its wire name and whether the server omits it when absent. */
    private record Member(String name, boolean optional) {
    }

    private static Member req(String name) {
        return new Member(name, false);
    }

    private static Member opt(String name) {
        return new Member(name, true);
    }

    /**
     * The signed event types' members in declaration order (crates/axiam-amqp {@code messages.rs};
     * CONTRACT &sect;8 "Exact signed field order"), {@code hmac_signature} excluded.
     */
    private static final List<List<Member>> LAYOUTS = List.of(
            // AuthzRequest
            List.of(req("correlation_id"), req("tenant_id"), req("subject_id"), req("action"),
                    req("resource_id"), opt("scope"), req("key_version"), req("nonce"), req("issued_at")),
            // AuditEventMessage
            List.of(req("tenant_id"), req("actor_id"), req("actor_type"), req("action"), opt("resource_id"),
                    req("outcome"), opt("ip_address"), opt("metadata"), req("key_version"), req("nonce"),
                    req("issued_at")));

    private static boolean hasDeclaredLayout(JsonNode canonicalRoot) {
        List<String> names = new ArrayList<>();
        canonicalRoot.fieldNames().forEachRemaining(names::add);
        for (List<Member> layout : LAYOUTS) {
            int i = 0;
            boolean ok = true;
            for (Member member : layout) {
                if (i < names.size() && names.get(i).equals(member.name())) {
                    i++;
                } else if (!member.optional()) {
                    ok = false;
                    break;
                }
            }
            if (ok && i == names.size()) {
                return true;
            }
        }
        return false;
    }

    private static final byte[] SIGNATURE_MEMBER =
            ",\"hmac_signature\":\"".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final int SIGNATURE_HEX_LENGTH = 64;
}
