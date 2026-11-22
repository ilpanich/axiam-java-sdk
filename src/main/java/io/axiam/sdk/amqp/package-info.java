/**
 * AMQP support for the AXIAM Java SDK — HMAC-verified message consumption
 * (CONTRACT.md &sect;8).
 *
 * <p>{@link io.axiam.sdk.amqp.Hmac} performs the canonicalization + verify
 * step every inbound {@code AuthzRequest}/{@code AuditEventMessage} delivery
 * must pass before a handler ever sees it. {@link io.axiam.sdk.amqp.ErrDrop}
 * is the poison-message sentinel a handler throws to request a
 * nack-without-requeue. {@link io.axiam.sdk.amqp.AuthzRequester} publishes
 * {@code AuthzRequest} messages with a private reply queue and accepts only the
 * server's signed answer to the request it sent.
 */
@NullMarked
package io.axiam.sdk.amqp;

import org.jspecify.annotations.NullMarked;
