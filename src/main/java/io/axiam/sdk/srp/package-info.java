/**
 * Secure Remote Password (SRP-6a) support — CONTRACT.md &sect;23.
 *
 * <p>SRP is an <em>augmented PAKE</em>: the client proves knowledge of the
 * password without the password, or anything from which the password can be
 * cheaply recovered, ever crossing the wire. The server stores a verifier
 * {@code v = g^x mod N} instead of a password hash.
 *
 * <p>Everything in this package is pure arithmetic and performs no I/O. The
 * login flow that uses it is {@code AxiamClient.loginSrp}.
 *
 * <p>What this closes, and what it does not: SRP defends against a
 * TLS-terminating proxy, an accidental request-body log, and a heap dump —
 * places a plaintext password exists today and would not under SRP. It does
 * <strong>not</strong> defend against a compromised AXIAM server.
 */
package io.axiam.sdk.srp;
