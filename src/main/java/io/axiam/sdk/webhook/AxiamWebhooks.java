package io.axiam.sdk.webhook;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.webhook.WebhookVerificationException.Reason;

import org.jspecify.annotations.Nullable;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * HMAC-SHA256 webhook-signature verification for inbound AXIAM webhook
 * deliveries (CONTRACT.md &sect;13, T-145).
 *
 * <p>Without this class every integrator hand-rolls the HMAC comparison (or
 * skips it) &mdash; this is the gap &sect;13 closes.
 *
 * <p><strong>{@code body} MUST be the exact raw bytes received off the
 * wire.</strong> Never re-serialize a parsed JSON body before calling
 * {@link #verify}: re-encoding changes key order and whitespace, which
 * produces different bytes than the server signed and breaks the MAC
 * (CONTRACT.md &sect;13.3 rule 1).
 */
public final class AxiamWebhooks {

    /**
     * Default two-sided freshness window applied to the signature header's
     * {@code t=} timestamp (CONTRACT.md &sect;13.2/&sect;13.3 rule 5): a
     * delivery is accepted only when {@code abs(now - t) <= DEFAULT_TOLERANCE},
     * unless a caller-supplied {@code tolerance} overrides it.
     */
    public static final Duration DEFAULT_TOLERANCE = Duration.ofSeconds(300);

    private static final String ALGO = "HmacSHA256";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AxiamWebhooks() {
    }

    /**
     * Verifies {@code signatureHeader} against {@code body}, keyed by
     * {@code secret}, using the default {@link #DEFAULT_TOLERANCE} freshness
     * window and the system UTC clock.
     *
     * @param secret          the webhook's plaintext secret
     * @param signatureHeader the raw {@code X-Axiam-Signature} header value
     * @param body            the exact raw request body bytes received off
     *                        the wire
     * @return the verified {@link WebhookEvent}
     * @throws WebhookVerificationException if verification fails for any
     *                                       reason (see {@link Reason})
     */
    public static WebhookEvent verify(Sensitive secret, String signatureHeader, byte[] body) {
        return verify(secret, signatureHeader, body, DEFAULT_TOLERANCE, Clock.systemUTC());
    }

    /**
     * Verifies {@code signatureHeader} against {@code body}, keyed by
     * {@code secret}, using {@code tolerance} as the freshness window and
     * the system UTC clock.
     *
     * @param secret          the webhook's plaintext secret
     * @param signatureHeader the raw {@code X-Axiam-Signature} header value
     * @param body            the exact raw request body bytes received off
     *                        the wire
     * @param tolerance       the two-sided freshness window applied to the
     *                        signature header's {@code t=} timestamp
     * @return the verified {@link WebhookEvent}
     * @throws WebhookVerificationException if verification fails for any
     *                                       reason (see {@link Reason})
     */
    public static WebhookEvent verify(Sensitive secret, String signatureHeader, byte[] body, Duration tolerance) {
        return verify(secret, signatureHeader, body, tolerance, Clock.systemUTC());
    }

    /**
     * Verifies {@code signatureHeader} against {@code body}, keyed by
     * {@code secret}, per CONTRACT.md &sect;13. {@code clock} is an
     * injection seam for tests that need a fixed or synthetic "now" without
     * sleeping past the tolerance window.
     *
     * <p>The verification algorithm, in order:
     * <ol>
     *   <li>Parse {@code signatureHeader} into its {@code t} and {@code v1}
     *       pair(s). Malformed structure (empty header, no {@code t}, more
     *       than one {@code t}) &rarr; {@link Reason#MALFORMED_HEADER}. No
     *       {@code v1} pair at all &rarr; {@link Reason#MISSING_V1}.</li>
     *   <li>Parse {@code t} as a base-10 integer. Non-numeric &rarr;
     *       {@link Reason#INVALID_TIMESTAMP}.</li>
     *   <li>Recompute {@code HMAC-SHA256(secret, "<t>.<body>")} using the
     *       exact {@code t} bytes from the header (never a re-formatted
     *       integer) and the raw body bytes.</li>
     *   <li>Constant-time compare ({@link MessageDigest#isEqual}, over
     *       decoded bytes &mdash; never a hex string {@code equals}) against
     *       every supplied {@code v1}. A {@code v1} value that fails hex
     *       decoding is treated as a non-match for that candidate (fail
     *       closed; never a fallback comparison) rather than aborting
     *       immediately, so a header carrying multiple {@code v1} values
     *       (secret rotation) still succeeds if any one decodes and
     *       matches. If none match &rarr; {@link Reason#SIGNATURE_MISMATCH}.</li>
     *   <li>Freshness: reject when {@code abs(now - t) > tolerance} &mdash;
     *       a future-dated {@code t} is rejected exactly like a stale one
     *       (CONTRACT.md &sect;13.3 rule 5) &rarr;
     *       {@link Reason#TIMESTAMP_TOO_OLD}/{@link Reason#TIMESTAMP_TOO_NEW}.</li>
     *   <li>On success, return the parsed {@link WebhookEvent}.</li>
     * </ol>
     *
     * <p>Only the {@code t=} value actually covered by the MAC is trusted
     * (CONTRACT.md &sect;13.3 rule 2) &mdash; this method does not read the
     * separate, redundant {@code X-Axiam-Timestamp} header at all; a caller
     * who also has that header and wants to enforce equality should compare
     * it to the returned {@link WebhookEvent#timestamp()} themselves.
     *
     * @param secret          the webhook's plaintext secret
     * @param signatureHeader the raw {@code X-Axiam-Signature} header value,
     *                        of the form
     *                        {@code "t=<unix_seconds>,v1=<hex_lowercase>[,v1=<hex_lowercase>...]"}.
     *                        Unknown keys are ignored for forward
     *                        compatibility, but a header with no {@code v1}
     *                        pair is always a failure (CONTRACT.md
     *                        &sect;13.3 rule 3) &mdash; this method never
     *                        treats "nothing to check" as success
     * @param body            the exact raw request body bytes received off
     *                        the wire
     * @param tolerance       the two-sided freshness window applied to the
     *                        signature header's {@code t=} timestamp
     * @param clock           the clock used to evaluate freshness (a test
     *                        injection seam; use {@link Clock#systemUTC()}
     *                        in production)
     * @return the verified {@link WebhookEvent}
     * @throws WebhookVerificationException if verification fails for any
     *                                       reason (see {@link Reason}).
     *                                       Its message never contains the
     *                                       expected/received signature or
     *                                       the secret.
     */
    public static WebhookEvent verify(Sensitive secret, String signatureHeader, byte[] body, Duration tolerance, Clock clock) {
        Objects.requireNonNull(secret, "secret");
        Objects.requireNonNull(signatureHeader, "signatureHeader");
        Objects.requireNonNull(body, "body");
        Objects.requireNonNull(tolerance, "tolerance");
        Objects.requireNonNull(clock, "clock");

        ParsedHeader parsed = parseHeader(signatureHeader);

        long t;
        try {
            t = Long.parseLong(parsed.timestamp());
        } catch (NumberFormatException e) {
            throw new WebhookVerificationException(Reason.INVALID_TIMESTAMP);
        }

        byte[] computed = computeHmac(secret, parsed.timestamp(), body);

        boolean matched = false;
        for (String v1 : parsed.signatures()) {
            byte[] decoded;
            try {
                decoded = HexFormat.of().parseHex(v1);
            } catch (IllegalArgumentException e) {
                // Fail closed for this candidate: never fall back to a raw
                // hex-string comparison. Keep checking any remaining
                // candidates (secret-rotation headers carry more than one).
                continue;
            }
            if (MessageDigest.isEqual(decoded, computed)) {
                matched = true;
                break;
            }
        }
        if (!matched) {
            throw new WebhookVerificationException(Reason.SIGNATURE_MISMATCH);
        }

        long now = clock.instant().getEpochSecond();
        long toleranceSeconds = tolerance.getSeconds();
        long age = now - t;
        if (age > toleranceSeconds) {
            throw new WebhookVerificationException(Reason.TIMESTAMP_TOO_OLD);
        }
        if (age < -toleranceSeconds) {
            throw new WebhookVerificationException(Reason.TIMESTAMP_TOO_NEW);
        }

        return new WebhookEvent(bestEffortEventType(body), t, body);
    }

    /**
     * Computes {@code HMAC-SHA256(secret, "<timestamp>.<body>")}, matching
     * the server's signing algorithm exactly (CONTRACT.md &sect;13.1).
     * {@code timestamp} is written as its exact header bytes (never a
     * re-formatted {@code long}) so the signed bytes match the server's
     * byte-for-byte.
     */
    private static byte[] computeHmac(Sensitive secret, String timestamp, byte[] body) {
        try {
            Mac mac = Mac.getInstance(ALGO);
            mac.init(new SecretKeySpec(secret.expose().getBytes(StandardCharsets.UTF_8), ALGO));
            mac.update(timestamp.getBytes(StandardCharsets.UTF_8));
            mac.update((byte) '.');
            return mac.doFinal(body);
        } catch (GeneralSecurityException e) {
            // HmacSHA256 is a mandatory algorithm on every standard JVM and
            // SecretKeySpec never rejects a non-empty UTF-8 key for it, so
            // this is unreachable in practice; wrap rather than declare a
            // checked exception on the public API for it.
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }

    /**
     * Splits {@code header} into comma-separated {@code key=value} pairs and
     * extracts exactly one {@code t} and every {@code v1} (CONTRACT.md
     * &sect;13.3 rule 3). Unknown keys and malformed (non
     * {@code "key=value"}) pairs are ignored for forward compatibility.
     *
     * @throws WebhookVerificationException {@link Reason#MALFORMED_HEADER}
     *                                       for an empty header, a missing
     *                                       {@code t}, or more than one
     *                                       {@code t}; {@link Reason#MISSING_V1}
     *                                       for a header with a valid
     *                                       {@code t} but no {@code v1} at
     *                                       all
     */
    private static ParsedHeader parseHeader(String header) {
        String timestamp = null;
        boolean haveTimestamp = false;
        List<String> signatures = new ArrayList<>();

        for (String part : header.split(",", -1)) {
            String trimmed = part.strip();
            int eq = trimmed.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String key = trimmed.substring(0, eq);
            String value = trimmed.substring(eq + 1);
            if ("t".equals(key)) {
                if (haveTimestamp) {
                    // More than one t is ambiguous — fail closed rather
                    // than picking one arbitrarily.
                    throw new WebhookVerificationException(Reason.MALFORMED_HEADER);
                }
                timestamp = value;
                haveTimestamp = true;
            } else if ("v1".equals(key)) {
                signatures.add(value);
            }
            // Unknown keys are ignored (forward compatibility).
        }

        if (!haveTimestamp) {
            throw new WebhookVerificationException(Reason.MALFORMED_HEADER);
        }
        if (signatures.isEmpty()) {
            throw new WebhookVerificationException(Reason.MISSING_V1);
        }
        return new ParsedHeader(timestamp, List.copyOf(signatures));
    }

    /**
     * Decodes {@code body}'s top-level {@code "event"} string field for
     * caller convenience. Any failure (non-JSON body, non-object body,
     * missing or non-string {@code "event"} field) yields {@code null}
     * rather than an exception: by the time this runs, {@link #verify} has
     * already accepted {@code body}'s raw bytes against the MAC, so a body
     * that fails this best-effort decode is still a verified delivery.
     */
    private static @Nullable String bestEffortEventType(byte[] body) {
        try {
            JsonNode root = MAPPER.readTree(body);
            JsonNode eventNode = root.get("event");
            return eventNode != null && eventNode.isTextual() ? eventNode.asText() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private record ParsedHeader(String timestamp, List<String> signatures) {
    }
}
