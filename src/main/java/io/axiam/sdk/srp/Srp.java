package io.axiam.sdk.srp;

import io.axiam.sdk.errors.NetworkError;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * SRP-6a protocol arithmetic (CONTRACT.md &sect;23).
 *
 * <p>Everything here is pure: no I/O, no client state, no network. The two
 * HTTP calls and the policy around them live in
 * {@code AxiamClient.loginSrp}.
 *
 * <p>{@code H} is <strong>SHA-256</strong> throughout. RFC 5054 specifies
 * SHA-1; AXIAM does not use SHA-1 anywhere and does not start here.
 */
public final class Srp {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    private Srp() {
    }

    /**
     * {@code PAD(v)} — {@code v} as exactly {@code byteLength} big-endian
     * bytes (&sect;23.3 rule 1).
     *
     * <p>Skipping this is the classic SRP interop bug: two implementations
     * agree until a value happens to have a leading zero byte, and then
     * roughly one login in 256 fails in a way that reads as a flaky network.
     *
     * @param value      the value to render
     * @param byteLength the group's modulus width in bytes
     * @return exactly {@code byteLength} bytes
     */
    public static byte[] pad(BigInteger value, int byteLength) {
        byte[] out = new byte[byteLength];
        byte[] raw = value.toByteArray();
        // BigInteger#toByteArray carries a sign byte, and a value wider than
        // the modulus is a caller error rather than something to truncate.
        int from = Math.max(0, raw.length - byteLength);
        int length = raw.length - from;
        System.arraycopy(raw, from, out, byteLength - length, length);
        return out;
    }

    /**
     * SHA-256 over the concatenation of {@code parts}.
     *
     * @param parts the byte strings to hash, in order
     * @return the 32-byte digest
     */
    public static byte[] hash(byte[]... parts) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts) {
                digest.update(part);
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandatory in every conformant JRE.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * {@link #hash} read back as a non-negative big-endian integer.
     *
     * @param parts the byte strings to hash, in order
     * @return the digest as an integer
     */
    public static BigInteger hashToInt(byte[]... parts) {
        return new BigInteger(1, hash(parts));
    }

    /**
     * {@code k = H(N | PAD(g))} — depends only on the group.
     *
     * @param group the group
     * @return the SRP-6a multiplier
     */
    public static BigInteger multiplier(SrpGroup group) {
        return hashToInt(
                pad(group.modulus(), group.byteLength()),
                pad(group.generator(), group.byteLength()));
    }

    /**
     * {@code x = KDF(identity ":" password, salt)}, as raw bytes
     * (&sect;23.3 rule 3).
     *
     * <p>RFC 5054's bare-hash {@code x} would make a leaked verifier
     * <em>cheaper</em> to attack offline than the Argon2id hashes AXIAM stores
     * today, which would make adopting SRP a net regression at rest — so the
     * KDF is memory-hard, and the server dictates which one per exchange.
     *
     * <p>The identity is the one the server named in the challenge, never what
     * the human typed (&sect;23.3 rule 2).
     *
     * @param identity the server's canonical identity for the account
     * @param password the plaintext password
     * @param salt     the account's SRP salt
     * @param params   the KDF and cost the server dictated
     * @return 32 bytes of key material; the caller reduces mod {@code N}
     * @throws NetworkError if {@code params.kdf()} is not one this SDK implements
     */
    public static byte[] deriveX(String identity, char[] password, byte[] salt, SrpKdfParams params) {
        char[] secret = joinIdentityAndPassword(identity, password);
        try {
            return switch (params.kdf() == null ? "" : params.kdf()) {
                case SrpKdfParams.ARGON2ID -> argon2id(secret, salt, params);
                case SrpKdfParams.PBKDF2_SHA256 -> pbkdf2(secret, salt, params);
                // Never substitute the other KDF: it derives a different x and
                // surfaces as "invalid password", the single most misleading
                // failure this code could produce.
                default -> throw new NetworkError("SRP: this SDK does not implement KDF '" + params.kdf()
                        + "'; it implements argon2id and pbkdf2_sha256");
            };
        } finally {
            Arrays.fill(secret, '\0');
        }
    }

    private static char[] joinIdentityAndPassword(String identity, char[] password) {
        char[] prefix = (identity + ":").toCharArray();
        char[] joined = new char[prefix.length + password.length];
        System.arraycopy(prefix, 0, joined, 0, prefix.length);
        System.arraycopy(password, 0, joined, prefix.length, password.length);
        return joined;
    }

    private static byte[] argon2id(char[] secret, byte[] salt, SrpKdfParams params) {
        // Argon2 takes bytes, and the UTF-8 encoding of the identity is what
        // §23.3 rule 2 pins — which is why the non-ASCII vector exists.
        byte[] utf8 = toUtf8(secret);
        try {
            Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withIterations(Math.max(1, params.iterations()))
                    .withMemoryAsKB(Math.max(8, params.memoryKib()))
                    .withParallelism(Math.max(1, params.parallelism()))
                    .withSalt(salt)
                    .build();
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(parameters);
            byte[] out = new byte[32];
            generator.generateBytes(utf8, out);
            return out;
        } finally {
            Arrays.fill(utf8, (byte) 0);
        }
    }

    private static byte[] pbkdf2(char[] secret, byte[] salt, SrpKdfParams params) {
        // PBEKeySpec's char[] path encodes as UTF-8 on every JDK since 8, which
        // is what the contract pins — the identity's encoding must match the
        // Argon2id path byte for byte or the two KDFs would disagree about the
        // same account.
        PBEKeySpec spec = new PBEKeySpec(secret, salt, Math.max(1, params.iterations()), 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new NetworkError("SRP: PBKDF2-HMAC-SHA256 is unavailable in this JRE: " + e.getMessage(), e);
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] toUtf8(char[] chars) {
        java.nio.ByteBuffer buffer = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(chars));
        byte[] out = new byte[buffer.remaining()];
        buffer.get(out);
        // The encoder's backing array may still hold a copy.
        if (buffer.hasArray()) {
            Arrays.fill(buffer.array(), (byte) 0);
        }
        return out;
    }

    /**
     * {@code v = g^x mod N} — the verifier the server stores instead of a
     * password hash.
     *
     * @param group the group the verifier lives in
     * @param x     the KDF output from {@link #deriveX}
     * @return the verifier, lowercase hex, padded to the group width
     */
    public static String computeVerifier(SrpGroup group, byte[] x) {
        BigInteger reduced = new BigInteger(1, x).mod(group.modulus());
        return HEX.formatHex(pad(group.generator().modPow(reduced, group.modulus()), group.byteLength()));
    }

    /**
     * 32 fresh bytes from the platform CSPRNG, for an enrolment salt
     * (&sect;23.3 rule 11).
     *
     * <p>A reused salt would make every verifier in a tenant equally
     * attackable with one precomputation.
     *
     * @return 32 random bytes
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[32];
        RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * A fresh client ephemeral {@code a}, at least 256 bits, from the platform
     * CSPRNG (&sect;23.3 rule 7).
     *
     * <p>Reusing {@code a} across logins leaks the relationship between two
     * session secrets, which is why {@link SrpClientSession} offers no way to
     * supply one.
     *
     * @return the ephemeral secret
     */
    static BigInteger generateEphemeral() {
        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        // Set the top bit so a is unambiguously >= 2^255.
        raw[0] |= (byte) 0x80;
        return new BigInteger(1, raw);
    }

    /**
     * Constant-time comparison of the server's {@code M2} against the expected
     * one (&sect;23.3 rule 6).
     *
     * @param expected the {@code M2} this client derived
     * @param actual   the {@code server_proof} the server returned, possibly {@code null}
     * @return {@code true} only if they match
     */
    public static boolean verifyServerProof(String expected, String actual) {
        if (actual == null || actual.length() != expected.length()) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.toLowerCase(java.util.Locale.ROOT).getBytes(StandardCharsets.US_ASCII),
                actual.toLowerCase(java.util.Locale.ROOT).getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Lowercase hex, the encoding every SRP field uses on the wire.
     *
     * @param bytes the bytes to render
     * @return the hex string
     */
    public static String toHex(byte[] bytes) {
        return HEX.formatHex(bytes);
    }

    /**
     * Parses a lowercase-hex wire field.
     *
     * @param hex   the field's value
     * @param field the field's name, for the error message
     * @return the decoded bytes
     * @throws NetworkError if {@code hex} is not valid hex
     */
    public static byte[] fromHex(String hex, String field) {
        try {
            return HEX.parseHex(hex);
        } catch (IllegalArgumentException e) {
            throw new NetworkError("SRP: the server's " + field + " is not valid hex", e);
        }
    }
}
