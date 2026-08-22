package io.axiam.sdk.account;

import io.axiam.sdk.Sensitive;

/**
 * A TOTP enrolment offer (CONTRACT.md &sect;25.1).
 *
 * <p><strong>The factor is not active yet.</strong> It becomes active when
 * {@code mfaConfirm} accepts a code derived from this secret — which is why
 * &sect;25.2 rule 4 forbids a composed one-call helper here: the human step in
 * the middle, scanning the URI and reading a code, is not something a helper
 * can wait for, and one that returned after {@code mfaEnroll} would report MFA
 * as enabled when it is not.
 *
 * @param secretBase32 the shared TOTP secret. Anyone holding it can generate
 *                     valid codes indefinitely.
 * @param totpUri      {@code otpauth://totp/…?secret=<secretBase32>} — so it
 *                     <em>contains</em> the secret beside it. Both are
 *                     {@link Sensitive} for that reason, and this is the one
 *                     that actually reaches a log, because it is the one a
 *                     caller hands to a QR renderer (&sect;25.3).
 */
public record MfaEnrollment(Sensitive secretBase32, Sensitive totpUri) {
}
