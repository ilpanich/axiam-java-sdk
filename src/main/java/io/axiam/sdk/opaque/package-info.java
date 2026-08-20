/**
 * OPAQUE (RFC 9807) support — CONTRACT.md &sect;23.
 *
 * <p>OPAQUE is an <em>augmented PAKE</em>, like the SRP-6a it replaces: the
 * client proves knowledge of the password without the password, or anything
 * from which it can be cheaply recovered, ever crossing the wire. What it adds
 * over SRP is <strong>pre-computation resistance</strong> — the record the
 * server stores is sealed under a tenant-wide oblivious PRF seed, so a stolen
 * record database is not offline-crackable on its own.
 *
 * <p><strong>Nothing in this package implements the protocol.</strong> &sect;23.1
 * forbids an SDK from doing so: OPAQUE needs an oblivious PRF,
 * {@code hash_to_curve}, {@code expand_message_xmd}, an envelope construction
 * and a three-message AKE, and eleven independent implementations of that is
 * eleven chances to be subtly and silently wrong in a way that still
 * interoperates until it does not. What is here is a JNA binding to
 * {@code libaxiam_opaque_ffi}, the same implementation the AXIAM server links,
 * plus the ownership bookkeeping a binding has to get right.
 *
 * <p>Both JNA and the shared library are optional and independently absent-able;
 * {@link io.axiam.sdk.opaque.Opaque#available()} reports rather than throwing.
 * The login flow that uses this package is {@code AxiamClient.loginOpaque}.
 *
 * <p>What this closes, and what it does not: OPAQUE defends against a
 * TLS-terminating proxy, an accidental request-body log, a heap dump, and a
 * stolen record database. It does <strong>not</strong> defend against a
 * compromised AXIAM server.
 */
package io.axiam.sdk.opaque;
