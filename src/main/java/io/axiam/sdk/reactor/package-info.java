/**
 * Reactor runtime — AMQP extension actors (CONTRACT.md &sect;22).
 *
 * <p>A <strong>reactor</strong> is an external process that subscribes to named
 * hook events on the AXIAM AMQP bus and answers back — allow, deny, or a
 * field-allow-listed mutation — inside a timeout the server declared. Unlike
 * Zitadel Actions or Keycloak SPIs, no third-party code is ever loaded into the
 * authorization server: the reactor lives in your process and can only influence
 * the server through the narrow, signed reply schema in
 * {@link io.axiam.sdk.reactor.ReactorProtocol}.
 *
 * <p>{@link io.axiam.sdk.reactor.ReactorServer#reactorServe} is the entry point.
 * It consumes the <em>server-declared</em> queue, verifies every event under
 * &sect;8 v2 (key version, HMAC, freshness, nonce) <em>before</em> your handler
 * sees it, and signs the reply with the same tenant subkey.
 *
 * <p><strong>Both directions are signed, and the canonical bytes carry
 * {@code "hmac_signature": null}</strong> — present and null, not omitted, which
 * is the one place a reactor body differs from the two &sect;8 message types.
 * {@link io.axiam.sdk.reactor.ReactorProtocol} is the only place that rule is
 * implemented, and it is proven byte-for-byte against the server-generated
 * &sect;22.13 vectors.
 *
 * <p><strong>What is deliberately absent:</strong> {@code authz.check},
 * {@code authz.check_batch} and {@code token.introspect}. &sect;22.7 is a
 * MUST NOT — a reactor round trip is milliseconds and the check path's budget is
 * microseconds. {@link io.axiam.sdk.reactor.ReactorEvents#REGISTRY} does not
 * contain them and no interceptor equivalent is offered anywhere in this SDK.
 * An application that needs external input on an authorization decision writes a
 * deny grant, which the engine evaluates in the hot path at hot-path cost.
 */
package io.axiam.sdk.reactor;
