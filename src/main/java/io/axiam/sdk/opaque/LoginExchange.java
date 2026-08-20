package io.axiam.sdk.opaque;

import com.sun.jna.Pointer;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.NetworkError;

import java.util.Arrays;

/** One in-flight login (CONTRACT.md &sect;23). */
public final class LoginExchange extends OpaqueExchange {

    LoginExchange(OpaqueNative lib, Pointer handle, String ke1) {
        super(lib, handle, ke1, false);
    }

    /**
     * The hex {@code KE1} to send to {@code login/start}.
     *
     * @return the first protocol message
     */
    public String ke1() {
        return firstMessage();
    }

    /**
     * Opens the envelope, producing {@code KE3}.
     *
     * <p>A failure here is the <strong>whole</strong> of the client's
     * authentication check, and covers both halves of the mutual
     * authentication: the envelope only opens under the right password, and
     * {@code KE2}'s MAC only verifies if the server actually holds the record.
     * Nothing may be sent afterwards (&sect;23.4 rule 7).
     *
     * <p>That case is an {@link AuthError}, unlike every other {@code null}
     * return in this package. The distinction is the point: a wrong password,
     * an account that does not exist and a server that does not hold the
     * record are indistinguishable by design and are all authentication
     * failures, whereas a key-stretching function this build cannot perform is
     * a configuration problem, and reporting it as "invalid password" would
     * send an operator looking in the wrong place.
     *
     * @param password the account password; every copy this SDK makes is
     *                 cleared, but not the caller's
     * @param ke2      the server's hex {@code KE2}
     * @param ksf      the key-stretching function the server named
     * @return the hex {@code KE3} to send to {@code login/finish}
     * @throws AuthError    when the envelope does not open or {@code KE2} does
     *                      not verify
     * @throws NetworkError if the exchange is already spent, or the
     *                      key-stretching function is one this SDK cannot ask for
     */
    public String finish(char[] password, String ke2, KsfParams ksf) {
        Pointer state = consume();
        byte[] encoded = Opaque.nulTerminatedUtf8(password);
        Pointer ksfHandle = ksf.build(lib);
        try {
            Pointer ke3 = lib.axiam_opaque_login_finish(
                    state, encoded, Opaque.nulTerminatedAscii(ke2), ksfHandle, null, null);
            if (ke3 == null) {
                throw new AuthError("invalid credentials: "
                        + Opaque.lastError(lib, "the OPAQUE envelope did not open"));
            }
            return Opaque.take(lib, ke3);
        } finally {
            lib.axiam_opaque_ksf_free(ksfHandle);
            Arrays.fill(encoded, (byte) 0);
        }
    }
}
