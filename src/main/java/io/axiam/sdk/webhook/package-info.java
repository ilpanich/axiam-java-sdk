/**
 * Webhook-signature verification for the AXIAM Java SDK (CONTRACT.md
 * &sect;13, T-145).
 *
 * <p>{@link io.axiam.sdk.webhook.AxiamWebhooks#verify} is the entry point:
 * it HMAC-SHA256-verifies an inbound {@code X-Axiam-Signature} header against
 * the exact raw request body bytes, with a two-sided freshness window over
 * the signed {@code t=} timestamp, and throws
 * {@link io.axiam.sdk.webhook.WebhookVerificationException} (never a bare/
 * generic exception, and never one whose message leaks the expected or
 * received signature) on any failure.
 */
@NullMarked
package io.axiam.sdk.webhook;

import org.jspecify.annotations.NullMarked;
