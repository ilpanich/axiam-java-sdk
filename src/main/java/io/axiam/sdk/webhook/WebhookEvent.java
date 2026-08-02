package io.axiam.sdk.webhook;

import org.jspecify.annotations.Nullable;

/**
 * A webhook delivery whose {@code X-Axiam-Signature} has already been
 * verified by {@link AxiamWebhooks#verify}.
 *
 * <p>Note on equality: {@code equals()}/{@code hashCode()} on {@code byte[]}
 * fields are reference-based (standard Java record behavior) — this record
 * is not intended for content-based comparison of {@link #body()}; compare
 * {@code java.util.Arrays.equals(a.body(), b.body())} directly if needed.
 *
 * @param type      the top-level {@code "event"} field decoded from
 *                  {@link #body()}, best-effort: {@code null} if the body is
 *                  not a JSON object or has no string {@code "event"} field.
 *                  This is a convenience only — verification has already
 *                  succeeded against the raw bytes by the time {@code type}
 *                  is populated, so a decode miss here never fails
 *                  verification.
 * @param timestamp the verified {@code t=} value from the signature header
 *                  (unix seconds). {@code X-Axiam-Timestamp} carries the
 *                  same value redundantly (CONTRACT.md &sect;13.3 rule 2);
 *                  {@link AxiamWebhooks#verify} does not read that header at
 *                  all, so if a caller also received it and wants to enforce
 *                  equality, compare it against {@code timestamp} themselves.
 * @param body      the exact raw bytes that were verified, unmodified
 */
public record WebhookEvent(@Nullable String type, long timestamp, byte[] body) {
}
