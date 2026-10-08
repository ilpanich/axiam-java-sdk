package io.axiam.sdk.testutil;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * The redaction assertion the contract's tests use: a rendering contains
 * neither a secret nor any 8-character substring of it.
 *
 * <p>A failure reports only the offset of the fragment within the secret and
 * a label &mdash; never the fragment, the secret or the rendering, which would
 * put the very value the test protects into the build log.
 */
public final class Redaction {

    private Redaction() {
    }

    /**
     * Fails if {@code haystack} contains any 8-character window of {@code secret}.
     *
     * @param label    what the rendering is, for the failure message
     * @param haystack the rendering under test
     * @param secret   the value that must not appear
     */
    public static void assertNoFragment(String label, String haystack, String secret) {
        for (int i = 0; i + 8 <= secret.length(); i++) {
            if (haystack.contains(secret.substring(i, i + 8))) {
                fail(label + ": an 8-character fragment of the secret (offset " + i + ") was rendered");
            }
        }
    }
}
