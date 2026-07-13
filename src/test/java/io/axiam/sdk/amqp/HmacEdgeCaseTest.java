package io.axiam.sdk.amqp;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Non-fixture edge cases for {@link Hmac#verify(byte[], byte[])}'s strict-mode
 * ("reject, never throw") contract (&sect;8.3): a body that is valid JSON but
 * not an object, a body that is not JSON at all, and an empty body must all
 * verify as {@code false} rather than raising.
 */
class HmacEdgeCaseTest {

    private static final byte[] KEY = "any-32-byte-signing-key-material!".getBytes(StandardCharsets.UTF_8);

    @Test
    void jsonArrayBodyIsRejectedNotThrown() {
        // Valid JSON, but the root is an array (not an ObjectNode) — must
        // short-circuit to false without attempting to strip hmac_signature.
        byte[] body = "[1, 2, 3]".getBytes(StandardCharsets.UTF_8);
        assertFalse(Hmac.verify(KEY, body));
    }

    @Test
    void jsonScalarBodyIsRejected() {
        assertFalse(Hmac.verify(KEY, "42".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void nonJsonBodyIsRejected() {
        assertFalse(Hmac.verify(KEY, "this is not json".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void emptyBodyIsRejected() {
        assertFalse(Hmac.verify(KEY, new byte[0]));
    }
}
