package io.axiam.sdk.srp;

import io.axiam.sdk.errors.NetworkError;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * One SRP exchange's client half: the ephemeral secret {@code a} held between
 * the challenge request and the proof that answers it (CONTRACT.md &sect;23.2).
 *
 * <p>A session is single-use. {@code a} is drawn fresh per exchange and there
 * is no way to supply one, because reusing it across logins leaks the
 * relationship between two session secrets (&sect;23.3 rule 7).
 */
public final class SrpClientSession {

    private final SrpGroup group;
    private final BigInteger ephemeral;
    private final String clientPublic;

    private SrpClientSession(SrpGroup group, BigInteger ephemeral) {
        this.group = group;
        this.ephemeral = ephemeral;
        this.clientPublic = Srp.toHex(
                Srp.pad(group.generator().modPow(ephemeral, group.modulus()), group.byteLength()));
    }

    /**
     * Starts an exchange in {@code group}: draws a fresh {@code a} and
     * computes {@code A = g^a mod N}.
     *
     * @param group the group to compute in
     * @return the new session
     */
    public static SrpClientSession begin(SrpGroup group) {
        return new SrpClientSession(group, Srp.generateEphemeral());
    }

    /**
     * Starts an exchange with {@code a} pinned to a supplied value.
     *
     * <p>For the &sect;23.7 cross-language vectors <strong>only</strong>: they
     * fix {@code a} so every intermediate is reproducible. Never call this from
     * application code — a predictable {@code a} defeats the protocol.
     *
     * @param group     the group to compute in
     * @param ephemeral the pinned {@code a}
     * @return the new session
     */
    public static SrpClientSession withFixedEphemeral(SrpGroup group, BigInteger ephemeral) {
        return new SrpClientSession(group, ephemeral);
    }

    /**
     * The group this exchange runs in.
     *
     * @return the group
     */
    public SrpGroup group() {
        return group;
    }

    /**
     * {@code A = g^a mod N}, lowercase hex — sent with the challenge request.
     *
     * @return the client's public value
     */
    public String clientPublic() {
        return clientPublic;
    }

    /**
     * Completes the exchange: {@code S}, {@code K}, {@code M1} and the
     * {@code M2} the server must return.
     *
     * @param identity        the identity from the challenge response, never
     *                        what the user typed (&sect;23.3 rule 2)
     * @param saltHex         the {@code salt} field of the challenge response
     * @param serverPublicHex the {@code b_pub} field of the challenge response
     * @param x               the KDF output from {@link Srp#deriveX}
     * @return the proof pair
     * @throws NetworkError if {@code B mod N == 0}, if {@code u} would be zero,
     *                      or if a hex field is malformed
     */
    public SrpProofs finish(String identity, String saltHex, String serverPublicHex, byte[] x) {
        byte[] salt = Srp.fromHex(saltHex, "salt");
        BigInteger modulus = group.modulus();
        BigInteger serverPublic = new BigInteger(1, Srp.fromHex(serverPublicHex, "b_pub"));

        // §23.3 rule 5. B ≡ 0 is the classic SRP break: S becomes predictable
        // and the exchange would authenticate against a server that never knew
        // the verifier. That is a broken or hostile server, not a wrong password.
        if (serverPublic.mod(modulus).signum() == 0) {
            throw new NetworkError("SRP: the server sent an invalid public value (B mod N == 0)");
        }

        byte[] paddedA = Srp.fromHex(clientPublic, "client_public");
        byte[] paddedB = Srp.pad(serverPublic, group.byteLength());

        // u = H(PAD(A) | PAD(B))
        BigInteger u = Srp.hashToInt(paddedA, paddedB);
        if (u.signum() == 0) {
            throw new NetworkError("SRP: the server's parameters produce u == 0");
        }

        BigInteger xInt = new BigInteger(1, x).mod(modulus);
        BigInteger k = Srp.multiplier(group);

        // S = (B - k*g^x)^(a + u*x) mod N
        BigInteger kgx = k.multiply(group.generator().modPow(xInt, modulus)).mod(modulus);
        BigInteger base = serverPublic.mod(modulus).subtract(kgx).mod(modulus);
        BigInteger sharedSecret = base.modPow(ephemeral.add(u.multiply(xInt)), modulus);

        byte[] paddedS = Srp.pad(sharedSecret, group.byteLength());
        byte[] sessionKey = Srp.hash(paddedS);
        try {
            // M1 = H(H(N) XOR H(PAD(g)) | H(I) | s | PAD(A) | PAD(B) | K)
            byte[] hn = Srp.hash(Srp.pad(modulus, group.byteLength()));
            byte[] hg = Srp.hash(Srp.pad(group.generator(), group.byteLength()));
            byte[] hxor = new byte[hn.length];
            for (int i = 0; i < hn.length; i++) {
                hxor[i] = (byte) (hn[i] ^ hg[i]);
            }
            byte[] hi = Srp.hash(identity.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] m1 = Srp.hash(hxor, hi, salt, paddedA, paddedB, sessionKey);

            // M2 = H(PAD(A) | M1 | K)
            byte[] m2 = Srp.hash(paddedA, m1, sessionKey);
            return new SrpProofs(Srp.toHex(m1), Srp.toHex(m2));
        } finally {
            // §23.3 rule 8: clear what can be cleared.
            Arrays.fill(paddedS, (byte) 0);
            Arrays.fill(sessionKey, (byte) 0);
        }
    }
}
