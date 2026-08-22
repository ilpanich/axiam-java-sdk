package io.axiam.sdk.webauthn;

import java.util.Locale;
import java.util.Map;

/**
 * A ceremony failure a caller can say something useful about (CONTRACT.md
 * &sect;24.6b rule 5).
 *
 * <p>Five outcomes, and the first two are the ones that matter.
 */
public enum WebauthnFailure {

    /**
     * Covers <strong>both</strong> an explicit refusal and a silent timeout.
     *
     * <p>The WebAuthn spec deliberately refuses to distinguish them, because
     * telling a website which one happened leaks whether an authenticator was
     * present. It must not be recovered by timing the call.
     */
    CANCELLED("The request was cancelled or timed out. You can try again."),

    /**
     * The authenticator already holds a credential for this account and refused
     * to silently mint a second — the exclusion list working, not a failure.
     * The only classification whose remedy is "use a different device".
     */
    ALREADY_REGISTERED(
            "This device is already registered on your account. Try a different device, "
                    + "or remove the existing one first."),

    /** An explicitly aborted ceremony. */
    TIMEOUT("The request timed out before it completed. Please try again."),

    /** This device or browser cannot run the ceremony. */
    UNSUPPORTED(
            "This browser or device cannot be used for passkeys. Try a different browser, "
                    + "or use another sign-in method."),

    /** Everything else. */
    UNKNOWN("Something went wrong. Please try again.");

    private static final Map<String, WebauthnFailure> BY_NAME = Map.of(
            "notallowederror", CANCELLED,
            "canceled", CANCELLED,
            "cancelled", CANCELLED,
            "invalidstateerror", ALREADY_REGISTERED,
            "aborterror", TIMEOUT,
            "timeout", TIMEOUT,
            "notsupportederror", UNSUPPORTED,
            "securityerror", UNSUPPORTED);

    private final String message;

    WebauthnFailure(String message) {
        this.message = message;
    }

    /**
     * Copy for this failure, safe to show a user.
     *
     * <p>The {@link #CANCELLED} string deliberately does not accuse anyone of
     * cancelling: the same classification covers a silent timeout, and the spec
     * will not say which happened.
     *
     * @return user-facing copy
     */
    public String message() {
        return message;
    }

    /**
     * Map a platform ceremony error name to its canonical classification.
     *
     * <p>Every platform reports a ceremony failure as one opaque type whose
     * only machine-readable part is a name, so a handset can relay just that
     * name and a Java service can turn it into the same five outcomes a browser
     * would see. Anything unrecognized is {@link #UNKNOWN} rather than a throw
     * — a classifier that can fail is one more thing for an error handler to
     * handle.
     *
     * @param name the platform's error name, however it arrived
     * @return the canonical classification
     */
    public static WebauthnFailure classify(String name) {
        if (name == null) {
            return UNKNOWN;
        }
        return BY_NAME.getOrDefault(name.strip().toLowerCase(Locale.ROOT), UNKNOWN);
    }
}
