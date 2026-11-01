package io.axiam.sdk.oidc;

import io.axiam.sdk.Sensitive;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * The nonce pair a native sign-in needs (CONTRACT.md &sect;37.4): the {@link #raw()} value the
 * app later sends to AXIAM, and the {@link #hashed()} value it gives the provider's own SDK.
 *
 * <p>The provider's SDK is handed {@code hashed}, so the ID token it returns carries the hash
 * in its {@code nonce} claim; AXIAM is handed {@code raw}, hashes it and compares. Handing the
 * provider the raw value, or a hash in another encoding, comes back as the same generic
 * {@code invalid_grant} as every other refusal (&sect;37.2 rule 10) &mdash; which is the mistake
 * {@link #generate()} exists to rule out.
 *
 * <p>{@code raw} is a credential (&sect;37.6): it is the preimage of the value inside the
 * provider's token. It is a {@link Sensitive}, so {@code toString()} and Jackson serialization
 * redact it, and this record's own {@code toString()} therefore prints
 * {@code ProviderNonce[raw=[SENSITIVE], hashed=...]}. Hold it for the length of the attempt
 * only; nothing in this SDK stores it. {@code hashed} is not secret &mdash; it travels to the
 * provider and into the token.
 *
 * @param raw    the raw nonce: at least 32 CSPRNG bytes, base64url without padding, wrapped
 * @param hashed {@code SHA-256} of the bytes of {@code raw} as sent, as 64 lower-case hexadecimal characters
 */
public record ProviderNonce(Sensitive raw, String hashed) {

    /** Random bytes behind {@code raw}: 32, the RECOMMENDED size of &sect;12.1 rule 1 (the server's floor is 16). */
    public static final int RAW_BYTES = 32;

    /**
     * Builds the pair (CONTRACT.md &sect;37.4): a fresh {@code raw} on every call, nothing stored.
     * Pure local computation; no network I/O.
     *
     * @return a fresh nonce pair
     */
    public static ProviderNonce generate() {
        String raw = OidcPkce.randomUrlSafeToken(RAW_BYTES);
        return new ProviderNonce(Sensitive.of(raw), hash(raw));
    }

    /**
     * {@code SHA-256} of the UTF-8 (equivalently, ASCII) bytes of {@code raw}, as lower-case
     * hexadecimal &mdash; the value the provider's SDK is given (&sect;37.4 rule 2).
     *
     * @param raw the raw nonce
     * @return 64 lower-case hexadecimal characters
     */
    public static String hash(String raw) {
        Objects.requireNonNull(raw, "raw");
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed available on every conforming JDK.
            throw new IllegalStateException("SHA-256 MessageDigest unavailable", e);
        }
    }
}
