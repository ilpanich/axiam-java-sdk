package io.axiam.sdk.reactor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jspecify.annotations.Nullable;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * The reactor wire protocol (CONTRACT.md &sect;22.1–&sect;22.4): topology names,
 * canonicalization, signing and verification.
 *
 * <p>{@link ReactorServer} is built on this class, and this class is public so
 * an integrator on a transport this SDK does not wrap (a different AMQP client,
 * a test harness, a bridge) can satisfy &sect;22 without reimplementing the one
 * rule that is easy to get wrong.
 *
 * <h2>The canonicalization rule</h2>
 *
 * <p>A reactor body is signed with its {@code hmac_signature} field
 * <strong>present and set to {@code null}</strong>, in declared field order.
 * That differs from &sect;8's own two message types ({@code AuthzRequest},
 * {@code AuditEventMessage}), whose {@code hmac_signature} is <em>absent</em>
 * from their canonical bytes — and it is the single most likely place for an
 * implementation to produce a MAC that will not verify. Everything else is
 * &sect;8 v2 verbatim: the same HKDF-derived per-tenant subkey, the same
 * {@code HMAC-SHA256} compared in constant time, the same &plusmn;300 s
 * freshness window, the same {@code key_version} floor of 2.
 *
 * <p>Field order, event (server &rarr; reactor): {@code tenant_id},
 * {@code event}, {@code correlation_id}, {@code payload}, {@code timeout_ms},
 * {@code key_version}, {@code nonce}, {@code issued_at}, {@code hmac_signature}.
 *
 * <p>Field order, reply (reactor &rarr; server): {@code correlation_id},
 * {@code tenant_id}, {@code event}, {@code decision}, {@code reason} (omitted
 * when absent), {@code patch} (omitted when absent), {@code require_mfa}
 * (<strong>omitted when {@code false}</strong>), {@code key_version},
 * {@code nonce}, {@code issued_at}, {@code hmac_signature}.
 *
 * <p>The three conditionally-omitted fields are load-bearing: a reply that
 * serializes {@code "require_mfa": false} rather than omitting it produces
 * different canonical bytes and therefore a different MAC.
 *
 * <h2>Signing is symmetric in direction</h2>
 *
 * <p>The server signs the event with the tenant subkey; the reactor signs its
 * reply with the same subkey. There is no second key and no asymmetric variant
 * in v1. An unsigned reply is not a weak reply — it is not a reply at all, and
 * the server discards it as though the reactor had never answered.
 */
public final class ReactorProtocol {

    /** The topic exchange every reactor event is published to. */
    public static final String EXCHANGE = "axiam.reactor.events";

    /** The &sect;8 envelope version reactor bodies are signed under. */
    public static final int KEY_VERSION = 2;

    /**
     * The lowest {@code key_version} that is even considered. A body carrying
     * less than this is refused before anything else about it is looked at —
     * it predates the mandatory {@code nonce}/{@code issued_at} fields.
     */
    public static final int MIN_ACCEPTED_KEY_VERSION = 2;

    /** The &sect;8 v2 freshness window applied to {@code issued_at}, in both directions. */
    public static final Duration DEFAULT_FRESHNESS_SKEW = Duration.ofSeconds(300);

    /** The {@code timeout_ms} a registration gets when it names none (&sect;22.8). */
    public static final int DEFAULT_TIMEOUT_MS = 500;

    /** The largest {@code timeout_ms} a registration may name; above this it is refused. */
    public static final int MAX_TIMEOUT_MS = 5_000;

    /** The chain's wall-clock ceiling: past this the remaining reactors are not contacted. */
    public static final int CHAIN_CEILING_MS = 5_000;

    /** The server's default per-tenant in-flight interception cap. */
    public static final int DEFAULT_MAX_IN_FLIGHT_PER_TENANT = 64;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String ALGO = "HmacSHA256";
    private static final String SIGNATURE_FIELD = "hmac_signature";

    /**
     * Byte-order comparator for patch keys.
     *
     * <p>The server's patch is a {@code BTreeMap<String, String>}, whose
     * serialization order is UTF-8 byte order. Java's natural {@link String}
     * ordering is UTF-16 code-unit order, which agrees for every realistic claim
     * name but diverges above the BMP — comparing the encoded bytes removes the
     * question rather than betting on the input.
     */
    private static final Comparator<String> UTF8_ORDER = (left, right) -> compareUnsignedBytes(
            left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8));

    private ReactorProtocol() {
    }

    // ---- topology (§22.1) --------------------------------------------------

    /**
     * The routing key an event for {@code event} in {@code tenantId} is published
     * under.
     *
     * @param tenantId the tenant
     * @param event    the registry event name
     * @return {@code <tenant_id>.<event>}
     */
    public static String routingKey(UUID tenantId, String event) {
        return tenantId + "." + event;
    }

    /**
     * The durable per-reactor queue the <strong>server</strong> declares.
     *
     * <p>Actors consume; they never declare topology. This helper exists so a
     * runtime can name the queue it was registered as — never another one. A
     * reactor that can bind is a reactor that can bind itself to
     * {@code *.token.pre_issue} and read another tenant's issuance events, so
     * this SDK holds no declare or bind capability at all.
     *
     * @param tenantId  the tenant the reactor is registered in
     * @param reactorId this reactor's own registration id
     * @return {@code axiam.reactor.q.<tenant_id>.<reactor_id>}
     */
    public static String queueName(UUID tenantId, UUID reactorId) {
        return "axiam.reactor.q." + tenantId + "." + reactorId;
    }

    // ---- canonicalization + MAC -------------------------------------------

    /**
     * The exact bytes an event was signed over: the received body with
     * {@code hmac_signature} set to {@code null} in place.
     *
     * <p>Setting the value rather than removing the key is what makes these bytes
     * a <em>reactor</em> body rather than a &sect;8 one. The field keeps its
     * position: Jackson's {@link ObjectNode} is backed by a {@code LinkedHashMap}
     * and re-putting an existing key preserves its insertion order, so the wire
     * order the server signed is the order reproduced here.
     *
     * @param body the raw delivery body
     * @return the canonical bytes
     * @throws IllegalArgumentException when {@code body} is not a JSON object
     */
    public static byte[] canonicalEventBytes(byte[] body) {
        ObjectNode node = parseObject(body);
        node.putNull(SIGNATURE_FIELD);
        return writeBytes(node);
    }

    /**
     * Verifies an event's MAC under {@code signingKey}.
     *
     * <p>This checks the signature and nothing else. {@link ReactorServer}
     * applies the full &sect;22.3 order around it — reject
     * {@code key_version < 2}, verify the MAC, check freshness, check the nonce —
     * and only then decodes the payload.
     *
     * <p>Never throws: a malformed body, a missing or null signature, non-hex
     * signature text and a wrong-length signature all verify as {@code false}.
     * There is no accept-when-absent path.
     *
     * @param signingKey the tenant's derived AMQP subkey
     * @param body       the raw delivery body
     * @return {@code true} only when the MAC matches, compared in constant time
     */
    public static boolean verifyEvent(byte[] signingKey, byte[] body) {
        try {
            ObjectNode node = parseObject(body);
            JsonNode sig = node.get(SIGNATURE_FIELD);
            if (sig == null || sig.isNull() || !sig.isTextual()) {
                return false;
            }
            byte[] presented = HexFormat.of().parseHex(sig.textValue());
            node.putNull(SIGNATURE_FIELD);
            byte[] computed = mac(signingKey, writeBytes(node));
            return MessageDigest.isEqual(computed, presented);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * The exact bytes a reply is signed over: the reply fields in declared order,
     * with the conditional omissions applied and {@code hmac_signature} present
     * and {@code null}.
     *
     * @param correlationId the event's correlation id, copied verbatim
     * @param tenantId      the event's tenant
     * @param event         the event's registry name
     * @param decision      what the handler decided
     * @param nonce         a fresh UUIDv4, unique per reply
     * @param issuedAt      the reply's signing time; truncated to whole seconds so
     *                      it round-trips through the server's RFC 3339 parser to
     *                      byte-identical text
     * @return the canonical bytes
     */
    public static byte[] canonicalReplyBytes(UUID correlationId, UUID tenantId, String event,
                                             ReactorDecision decision, UUID nonce, Instant issuedAt) {
        return writeBytes(replyNode(correlationId, tenantId, event, decision, nonce, issuedAt));
    }

    /**
     * Builds and signs a reply — the wire bytes a reactor publishes.
     *
     * @param signingKey    the tenant's derived AMQP subkey, the same one the
     *                      event was signed with
     * @param correlationId the event's correlation id, copied verbatim. The server
     *                      authenticates this field inside the signed body, not
     *                      the AMQP property.
     * @param tenantId      the event's tenant
     * @param event         the event's registry name
     * @param decision      what the handler decided
     * @param nonce         a fresh UUIDv4. It is inside the signed bytes, so a
     *                      unique one is what keeps two replies from being
     *                      byte-identical; a constant nonce removes the only
     *                      uniqueness the reply body carries beyond its timestamp.
     * @param issuedAt      the reply's signing time
     * @return the signed reply body, ready to publish
     */
    public static byte[] signedReply(byte[] signingKey, UUID correlationId, UUID tenantId,
                                     String event, ReactorDecision decision, UUID nonce,
                                     Instant issuedAt) {
        ObjectNode node = replyNode(correlationId, tenantId, event, decision, nonce, issuedAt);
        String signature = HexFormat.of().formatHex(mac(signingKey, writeBytes(node)));
        node.put(SIGNATURE_FIELD, signature);
        return writeBytes(node);
    }

    /**
     * Whether {@code issuedAt} lies within {@code skew} of {@code now}, in both
     * directions.
     *
     * <p>A future timestamp is not "extra fresh"; it is the shape of a captured
     * message held for later.
     *
     * @param issuedAt the timestamp inside the signed body
     * @param now      the verifier's clock reading
     * @param skew     the acceptance window, {@link #DEFAULT_FRESHNESS_SKEW} by
     *                 default
     * @return {@code true} when the timestamp is inside the window
     */
    public static boolean isFresh(Instant issuedAt, Instant now, Duration skew) {
        return Duration.between(issuedAt, now).abs().compareTo(skew) <= 0;
    }

    // ---- internals ---------------------------------------------------------

    private static ObjectNode replyNode(UUID correlationId, UUID tenantId, String event,
                                        ReactorDecision decision, UUID nonce, Instant issuedAt) {
        Objects.requireNonNull(correlationId, "correlationId");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(event, "event");
        Objects.requireNonNull(decision, "decision");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(issuedAt, "issuedAt");

        ObjectNode node = MAPPER.createObjectNode();
        node.put("correlation_id", correlationId.toString());
        node.put("tenant_id", tenantId.toString());
        node.put("event", event);

        String reason = null;
        Map<String, String> patch = null;
        boolean requireMfa = false;
        String word;
        if (decision instanceof ReactorDecision.Allow allow) {
            word = "allow";
            requireMfa = allow.requireMfa();
        } else if (decision instanceof ReactorDecision.Deny denial) {
            word = "deny";
            reason = denial.reason();
        } else if (decision instanceof ReactorDecision.Mutate mutation) {
            word = "mutate";
            patch = mutation.patch();
        } else {
            throw new IllegalArgumentException("unreachable: sealed ReactorDecision");
        }

        node.put("decision", word);
        if (reason != null) {
            node.put("reason", reason);
        }
        if (patch != null) {
            ObjectNode patchNode = node.putObject("patch");
            List<String> keys = new ArrayList<>(patch.keySet());
            keys.sort(UTF8_ORDER);
            for (String key : keys) {
                // Unfiltered, deliberately: §22.4 rule 1 forbids trimming a
                // handler's patch to the allowed subset. One forbidden key
                // rejects the whole reply, and the reactor author finds out.
                patchNode.put(key, patch.get(key));
            }
        }
        if (requireMfa) {
            node.put("require_mfa", true);
        }
        node.put("key_version", KEY_VERSION);
        node.put("nonce", nonce.toString());
        node.put("issued_at", formatInstant(issuedAt));
        node.putNull(SIGNATURE_FIELD);
        return node;
    }

    /**
     * Renders {@code instant} the way the server's RFC 3339 codec does, truncated
     * to whole seconds.
     *
     * <p>The server verifies a reply by deserializing it and re-serializing the
     * body, so the timestamp text has to survive that round trip unchanged.
     * Whole seconds always do; a sub-second value whose digit count does not
     * match the server's auto-selected precision would not.
     */
    private static String formatInstant(Instant instant) {
        return DateTimeFormatter.ISO_INSTANT.format(instant.truncatedTo(ChronoUnit.SECONDS));
    }

    private static ObjectNode parseObject(byte[] body) {
        try {
            JsonNode root = MAPPER.readTree(body);
            if (!(root instanceof ObjectNode node)) {
                throw new IllegalArgumentException("reactor body is not a JSON object");
            }
            return node;
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("reactor body is not valid JSON", e);
        }
    }

    private static byte[] writeBytes(ObjectNode node) {
        try {
            return MAPPER.writeValueAsBytes(node);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("a JSON tree failed to serialize", e);
        }
    }

    private static byte[] mac(byte[] key, byte[] canonical) {
        try {
            Mac mac = Mac.getInstance(ALGO);
            mac.init(new SecretKeySpec(key, ALGO));
            return mac.doFinal(canonical);
        } catch (java.security.GeneralSecurityException | IllegalArgumentException e) {
            // An empty or otherwise unusable key. Fail loudly rather than sign
            // with something that is not the tenant's subkey.
            throw new IllegalArgumentException("HMAC-SHA256 could not be initialized with this key", e);
        }
    }

    private static int compareUnsignedBytes(byte[] left, byte[] right) {
        int shared = Math.min(left.length, right.length);
        for (int i = 0; i < shared; i++) {
            int diff = Byte.toUnsignedInt(left[i]) - Byte.toUnsignedInt(right[i]);
            if (diff != 0) {
                return diff;
            }
        }
        return left.length - right.length;
    }

    /**
     * Parses a UUID, returning {@code null} rather than throwing.
     *
     * @param raw the text to parse; may be {@code null}
     * @return the UUID, or {@code null} when {@code raw} is absent or malformed
     */
    static @Nullable UUID parseUuid(@Nullable String raw) {
        if (raw == null) {
            return null;
        }
        try {
            return UUID.fromString(raw);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
