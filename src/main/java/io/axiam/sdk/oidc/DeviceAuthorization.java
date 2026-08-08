package io.axiam.sdk.oidc;

import io.axiam.sdk.Sensitive;

import org.jspecify.annotations.Nullable;

/**
 * The {@code DeviceAuthorizationResponse} — what the device shows its user,
 * plus the {@code device_code} it polls with (CONTRACT.md &sect;14.1).
 *
 * <p>{@link #deviceCode()} is {@link Sensitive} (&sect;14.5): a bearer
 * credential for the lifetime of the grant. {@link #userCode()} deliberately
 * is <strong>not</strong> — it exists to be read aloud and typed by a human,
 * and wrapping it would defeat the one thing it is for. Neither may be
 * logged; displaying the user code is the caller's job.
 *
 * @param deviceCode              the device's polling credential (&sect;14.5 secret)
 * @param userCode                the short code the human types into the verification page
 * @param verificationUri         where the human goes to enter {@code userCode}
 * @param verificationUriComplete the verification URI with the user code already embedded, when the server sent one — prefer it when the device can render a QR code; {@code null} otherwise, and never synthesised by concatenation (&sect;14.3), because its format is the server's to choose
 * @param expiresIn               seconds until the grant expires; polling stops here (&sect;14.2 rule 4)
 * @param interval                seconds between polls, from the response, defaulted to 5 when the server omitted it (&sect;14.2 rule 2)
 */
public record DeviceAuthorization(
        Sensitive deviceCode,
        String userCode,
        String verificationUri,
        @Nullable String verificationUriComplete,
        int expiresIn,
        int interval) {
}
