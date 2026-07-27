package io.axiam.sdk;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.util.Objects;

/**
 * Hardened wrapper for any token-carrying string value (access token,
 * refresh token, MFA challenge token, AMQP signing key) so it can never
 * accidentally leak via {@code toString()}, Jackson serialization, or Java's
 * reflective object serialization (CONTRACT.md &sect;7, D-17).
 *
 * <p>Mirrors {@code sdks/go}'s {@code Sensitive} (String/Format/GoString/
 * MarshalJSON quartet) and {@code sdks/typescript}'s private-{@code #value}
 * class. The raw value is reachable only via the single explicit
 * {@link #expose()} accessor (CONTRACT.md &sect;7 rule 3) — there is no other
 * public getter, no implicit conversion, and no public field.
 *
 * <p>{@code Sensitive} intentionally does NOT implement
 * {@link java.io.Serializable}: Java's default serialization would
 * otherwise expose {@code value} via reflective field access even with
 * {@code toString()} redacted. Omitting {@code Serializable} means any
 * attempt to Java-serialize an object graph containing a {@code Sensitive}
 * field throws {@code NotSerializableException} at the first attempt — a
 * fail-closed (not fail-open) posture.
 */
@JsonSerialize(using = Sensitive.Redactor.class)
public final class Sensitive {

    private static final String REDACTED = "[SENSITIVE]";

    private final String value;

    private Sensitive(String value) {
        this.value = Objects.requireNonNull(value, "value");
    }

    /**
     * Wraps {@code value} so it can never accidentally leak via {@code toString()},
     * Jackson serialization, or Java reflective serialization.
     *
     * @param value the raw token-carrying string to wrap; must not be {@code null}
     * @return a new {@code Sensitive} wrapping {@code value}
     */
    public static Sensitive of(String value) {
        return new Sensitive(value);
    }

    @Override
    public String toString() {
        return REDACTED;
    }

    // Deliberately no equals()/hashCode() override exposing `value` via a
    // timing side channel; if equality is ever needed, use a constant-time
    // MessageDigest.isEqual comparison, never String.equals.

    /**
     * Returns the wrapped raw value — the SDK's single explicit accessor for
     * a {@code Sensitive} (CONTRACT.md &sect;7 rule 3).
     *
     * <p>Public because CONTRACT.md &sect;12 hands
     * {@code accessToken}/{@code refreshToken}/{@code idToken} to the
     * <strong>calling application</strong> inside the {@code /oauth2/token}
     * response body, not via a {@code Set-Cookie} the SDK captures on the
     * caller's behalf — there is no cookie jar to read them back out of.
     * Without a public accessor a &sect;12 caller could hold an
     * {@code OidcTokenSet} and never be able to persist, forward, or later
     * revoke the tokens it contains, which would make &sect;12 unusable.
     * Widening this accessor from package-private is additive and breaks no
     * existing caller.
     *
     * <p><strong>Call this only at the point of actually using the value</strong>
     * (attaching it to an {@code Authorization} header, writing it to your own
     * encrypted session store, handing it to a revoke call) and never pass the
     * result to a {@code log}/{@code trace}/serialization sink — {@code
     * toString()} and Jackson serialization on {@code Sensitive} itself still
     * always redact, but that protection does not follow the raw
     * {@code String} once this method returns it.
     *
     * @return the wrapped raw value
     */
    public String expose() {
        return value;
    }

    static final class Redactor extends StdSerializer<Sensitive> {

        Redactor() {
            super(Sensitive.class);
        }

        @Override
        public void serialize(Sensitive value, JsonGenerator gen, SerializerProvider provider) throws IOException {
            gen.writeString(REDACTED);
        }
    }
}
