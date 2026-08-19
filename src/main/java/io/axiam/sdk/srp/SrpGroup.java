package io.axiam.sdk.srp;

import io.axiam.sdk.errors.NetworkError;

import java.math.BigInteger;

/**
 * The RFC 5054 Appendix A groups AXIAM speaks (CONTRACT.md &sect;23.4).
 *
 * <p>These moduli are embedded as constants and a modulus is <strong>never</strong>
 * accepted from the server: a server-supplied {@code N} is a server-supplied
 * trapdoor. {@code SrpVectorsTest} asserts each one's width, primality and
 * safe-primality, because a transcription slip here is a silent, total break
 * that a client/server round-trip cannot catch — both sides would share the
 * same wrong constant.
 */
public enum SrpGroup {

    /** RFC 5054 Appendix A, 2048-bit group, {@code g = 2}. */
    RFC5054_2048("rfc5054_2048", SrpModuli.N_2048, 2),

    /** RFC 5054 Appendix A, 3072-bit group, {@code g = 5}. */
    RFC5054_3072("rfc5054_3072", SrpModuli.N_3072, 5),

    /**
     * RFC 5054 Appendix A, 4096-bit group, {@code g = 5}.
     *
     * <p>AXIAM's default: it matches the RSA-4096 floor the project already
     * sets for certificates.
     */
    RFC5054_4096("rfc5054_4096", SrpModuli.N_4096, 5);

    private final String wireName;
    private final BigInteger modulus;
    private final BigInteger generator;
    private final int byteLength;

    SrpGroup(String wireName, String modulusHex, int generator) {
        this.wireName = wireName;
        this.modulus = new BigInteger(modulusHex, 16);
        this.generator = BigInteger.valueOf(generator);
        this.byteLength = modulusHex.length() / 2;
    }

    /**
     * The name this group carries on the wire, e.g. {@code "rfc5054_4096"}.
     *
     * @return the wire name
     */
    public String wireName() {
        return wireName;
    }

    /**
     * The group modulus {@code N}.
     *
     * @return {@code N}
     */
    public BigInteger modulus() {
        return modulus;
    }

    /**
     * The generator {@code g}.
     *
     * @return {@code g}
     */
    public BigInteger generator() {
        return generator;
    }

    /**
     * The modulus width in bytes — the width every hashed value is padded to
     * (&sect;23.3 rule 1).
     *
     * @return the modulus width in bytes
     */
    public int byteLength() {
        return byteLength;
    }

    /**
     * Resolves a wire group name, refusing anything this SDK does not
     * recognise rather than guessing (&sect;23.4).
     *
     * <p>The exception is {@link NetworkError} and not
     * {@link io.axiam.sdk.errors.AuthError}: this is a client capability gap,
     * and &sect;2 reserves {@code AuthError} for wrong credentials. Reporting
     * it as one would send a user off to reset a password that works.
     *
     * @param wireName the {@code group} field of a challenge response
     * @return the matching group
     * @throws NetworkError if this SDK does not implement {@code wireName}
     */
    public static SrpGroup fromWire(String wireName) {
        for (SrpGroup group : values()) {
            if (group.wireName.equals(wireName)) {
                return group;
            }
        }
        throw new NetworkError("SRP: this SDK does not implement group '" + wireName
                + "'; it embeds only rfc5054_2048, rfc5054_3072 and rfc5054_4096");
    }
}
