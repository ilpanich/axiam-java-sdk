/**
 * WebAuthn and passkeys — CONTRACT.md &sect;24.
 *
 * <p>A passkey ceremony is <strong>two exchanges stacked</strong>: one with an
 * <em>authenticator</em>, which needs a platform API, and one with
 * <em>AXIAM</em>, which is four ordinary JSON round trips. The JVM has no
 * authenticator, so this package is the second half.
 *
 * <p>That is not a consolation prize. A Java service completing a ceremony that
 * ran on an Android or iOS handset is the relying party exactly as a browser
 * is, and &sect;24.6b rule 2 forbids the alternative outright: an SDK MUST NOT
 * emulate an authenticator in software, because a "credential" held in process
 * memory is not a second factor.
 *
 * <p>The rule everything obeys is &sect;24.0: the server chooses every option
 * and verifies every response, so this carries both through untouched. It does
 * not default a field, normalize one, or re-encode a buffer — the challenge is
 * held as a raw {@code JsonNode} precisely so there is nothing to normalize
 * through.
 */
@NullMarked
package io.axiam.sdk.webauthn;

import org.jspecify.annotations.NullMarked;
