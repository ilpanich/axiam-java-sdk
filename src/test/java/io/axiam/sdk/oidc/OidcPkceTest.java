package io.axiam.sdk.oidc;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;12.1 PKCE/CSPRNG primitives: the RFC 7636 Appendix B test
 * vector every SDK must carry, S256-only, and &ge;128-bit entropy/uniqueness
 * for generated {@code state}/{@code nonce}/{@code code_verifier} values.
 */
class OidcPkceTest {

    /** RFC 7636 Appendix B: the canonical verifier -&gt; challenge test vector. */
    @Test
    void rfc7636AppendixBVector() {
        String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        assertEquals(expectedChallenge, OidcPkce.computeCodeChallenge(verifier));
    }

    @Test
    void codeChallengeMethodIsS256Only() {
        assertEquals("S256", OidcPkce.CODE_CHALLENGE_METHOD_S256);
    }

    @Test
    void generatedCodeVerifierHasAtLeast128BitsOfEntropyAndUsesUnreservedCharset() {
        String verifier = OidcPkce.generateCodeVerifier();

        // 32 CSPRNG bytes base64url-encoded (unpadded) -> 43 characters, well
        // above the RFC 7636 §4.1 minimum of 43 and >= 128 bits of entropy.
        assertEquals(43, verifier.length());
        assertTrue(verifier.matches("^[A-Za-z0-9\\-._~]+$"),
                "code_verifier must be drawn only from the RFC 7636 §4.1 unreserved set");
        assertFalse(verifier.contains("="), "code_verifier must not be padded");
    }

    @Test
    void randomUrlSafeTokenDefaultIs32BytesUnpaddedBase64Url() {
        String token = OidcPkce.randomUrlSafeToken();

        assertFalse(token.contains("="), "state/nonce must be unpadded base64url (RFC 4648 §5)");
        assertFalse(token.contains("+"), "base64url must not use '+' ");
        assertFalse(token.contains("/"), "base64url must not use '/'");
        // 32 bytes -> 43 base64url chars (256 bits, well above the 128-bit floor).
        assertEquals(43, token.length());
    }

    @Test
    void randomUrlSafeTokenHonorsExplicitByteCountAndStaysAboveTheFloor() {
        // §12.1 rule 1's floor is 16 bytes (128 bits).
        String token = OidcPkce.randomUrlSafeToken(16);
        assertEquals(22, token.length()); // 16 bytes -> 22 unpadded base64url chars (128 bits)
    }

    @Test
    void generatedTokensAreUniqueAcrossManyCalls() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            assertTrue(seen.add(OidcPkce.randomUrlSafeToken()), "state/nonce values must not collide");
            assertTrue(seen.add(OidcPkce.generateCodeVerifier()), "code_verifier values must not collide");
        }
    }

    @Test
    void computeCodeChallengeIsDeterministicForTheSameVerifier() {
        String verifier = OidcPkce.generateCodeVerifier();
        assertEquals(OidcPkce.computeCodeChallenge(verifier), OidcPkce.computeCodeChallenge(verifier));
    }
}
