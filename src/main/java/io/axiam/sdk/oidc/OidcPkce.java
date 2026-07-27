package io.axiam.sdk.oidc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * PKCE + CSPRNG primitives for the OIDC relying-party flow (CONTRACT.md
 * &sect;12.1 "{@code oidcBegin} inputs and construction", RFC 7636).
 *
 * <p>The JDK's {@link SecureRandom}, {@link MessageDigest}, and
 * {@link Base64} cover everything needed — CSPRNG, SHA-256, and base64url —
 * so this class adds NO new runtime dependency.
 *
 * <p><strong>S256 only.</strong> {@code plain} is not implemented, not
 * reachable, and not configurable: there is no code path in this SDK that can
 * emit {@code code_challenge_method=plain}.
 */
public final class OidcPkce {

    /** The only PKCE code-challenge method this SDK emits (RFC 7636 &sect;4.2, CONTRACT.md &sect;12.1 rule 3). {@code plain} is intentionally absent. */
    public static final String CODE_CHALLENGE_METHOD_S256 = "S256";

    /**
     * Entropy, in bytes, of a generated {@code state}/{@code nonce}/
     * {@code code_verifier}. CONTRACT.md &sect;12.1 rule 1 requires at least
     * 16 bytes (128 bits) and RECOMMENDS 32; rule 2 RECOMMENDS 32 bytes for
     * the verifier, which base64url-encodes to exactly 43 characters — the
     * minimum RFC 7636 &sect;4.1 length.
     */
    public static final int CSPRNG_BYTES = 32;

    private static final SecureRandom RNG = new SecureRandom();

    private OidcPkce() {
    }

    /**
     * Generates a URL-safe random token: {@link #CSPRNG_BYTES} CSPRNG bytes,
     * base64url-encoded without padding (RFC 4648 &sect;5).
     *
     * <p>Used for both {@code state} and {@code nonce}, which CONTRACT.md
     * &sect;12.3 rule 2 classes as <strong>non-secret</strong>.
     *
     * @return a fresh, unpadded base64url-encoded random token
     */
    public static String randomUrlSafeToken() {
        return randomUrlSafeToken(CSPRNG_BYTES);
    }

    /**
     * Generates a URL-safe random token from {@code numBytes} of CSPRNG
     * output, base64url-encoded without padding.
     *
     * @param numBytes the number of random bytes to draw
     * @return a fresh, unpadded base64url-encoded random token
     */
    public static String randomUrlSafeToken(int numBytes) {
        byte[] buffer = new byte[numBytes];
        RNG.nextBytes(buffer);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer);
    }

    /**
     * Generates a fresh PKCE {@code code_verifier} (RFC 7636 &sect;4.1): 32
     * CSPRNG bytes base64url-encoded without padding, i.e. 43 characters from
     * the unreserved set {@code [A-Za-z0-9-._~]}.
     *
     * <p>Returned as a raw string — the caller (the &sect;12 operations on
     * {@code AxiamClient}) wraps it in {@code Sensitive} immediately, since
     * CONTRACT.md &sect;12.5 makes the verifier secret for its whole
     * lifetime.
     *
     * @return a fresh PKCE code verifier
     */
    public static String generateCodeVerifier() {
        return randomUrlSafeToken(CSPRNG_BYTES);
    }

    /**
     * Derives the PKCE {@code code_challenge} from a verifier:
     * {@code BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))}, unpadded
     * (RFC 7636 &sect;4.2, CONTRACT.md &sect;12.1 rule 3).
     *
     * <p>The challenge is a one-way digest and is <strong>not</strong> secret
     * — it travels in the authorization URL — so it is returned as a plain
     * string.
     *
     * @param codeVerifier the PKCE verifier to hash
     * @return the base64url-encoded (unpadded) SHA-256 digest of {@code codeVerifier}
     */
    public static String computeCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed available on every conforming JDK
            // (Java Cryptography Architecture Standard Algorithm Name spec).
            throw new IllegalStateException("SHA-256 MessageDigest unavailable", e);
        }
    }
}
