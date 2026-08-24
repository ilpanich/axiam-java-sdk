package io.axiam.sdk.opaque;

import com.fasterxml.jackson.databind.JsonNode;
import org.jspecify.annotations.Nullable;

/**
 * The tenant's {@code opaque_mode}, as {@code login/start} reports it
 * (CONTRACT.md &sect;23.4 rule 7, &sect;23.5).
 *
 * <p>The {@code mode} field is <strong>optional on the wire</strong>: it
 * arrives as the string {@code "optional"} or {@code "required"} — never
 * {@code "disabled"}, which answers {@code 404} instead — and is absent
 * altogether from a server older than the field. Absence and an unrecognised
 * value both read as {@link #REQUIRED}: this decides whether a failed OPAQUE
 * exchange may be retried with a plaintext password, so the safe reading is
 * the one that does not.
 *
 * <p><strong>This is not downgrade protection</strong> and &sect;23.4 rule 7
 * forbids presenting it as such. A hostile server that wanted the plaintext
 * could answer {@code 404} and get the fallback whatever it puts here. What
 * closes that is server-side: {@code required} refuses {@code /auth/login} for
 * every principal in the tenant, before any credential is examined.
 */
public enum OpaqueMode {

    /**
     * {@code optional} — both login paths work, and records accumulate as
     * passwords are set.
     *
     * <p>The mid-migration state, and the reason rule 7 has a fallback at all:
     * every account has no registration record the moment an operator enables
     * OPAQUE, and acquires one only when its password is next set. A failed
     * exchange here is the ordinary case rather than an error, so the SDK
     * retries over {@code POST /auth/login} before reporting any failure.
     */
    OPTIONAL,

    /**
     * {@code required} — {@code /auth/login} answers {@code 403
     * opaque_required} for every principal in the tenant.
     *
     * <p>A failed exchange is final. Retrying over the password endpoint would
     * be refused anyway, so it would put a plaintext password on the wire for
     * nothing. Also the reading for a response with no {@code mode} field, and
     * for one naming a mode this SDK does not recognise.
     */
    REQUIRED;

    /** The wire spelling of {@link #OPTIONAL}. */
    public static final String WIRE_OPTIONAL = "optional";

    /** The wire spelling of {@link #REQUIRED}. */
    public static final String WIRE_REQUIRED = "required";

    /**
     * Reads the optional {@code mode} field of a {@code login/start} response.
     *
     * @param wire the parsed response body
     * @return the mode the tenant named, or {@link #REQUIRED} when the field is
     *         absent, null, non-textual or unrecognised
     */
    public static OpaqueMode fromWire(JsonNode wire) {
        JsonNode node = wire.get("mode");
        if (node == null || !node.isTextual()) {
            return REQUIRED;
        }
        return fromWire(node.asText());
    }

    /**
     * Reads one {@code mode} string, tolerating its absence.
     *
     * @param mode the value the server sent, or {@code null} when it sent none
     * @return the mode it names, or {@link #REQUIRED} for {@code null} and for
     *         any value this SDK does not recognise
     */
    public static OpaqueMode fromWire(@Nullable String mode) {
        return WIRE_OPTIONAL.equals(mode) ? OPTIONAL : REQUIRED;
    }

    /**
     * Whether a failed {@code KE2} may be retried over {@code POST
     * /auth/login} (&sect;23.4 rule 7).
     *
     * @return {@code true} only for {@link #OPTIONAL}
     */
    public boolean allowsPasswordLoginFallback() {
        return this == OPTIONAL;
    }
}
