package io.axiam.sdk.opaque;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import io.axiam.sdk.errors.NetworkError;

import java.util.Arrays;

/** One in-flight enrolment (CONTRACT.md &sect;23). */
public final class RegistrationExchange extends OpaqueExchange {

    RegistrationExchange(OpaqueNative lib, Pointer handle, String request) {
        super(lib, handle, request, true);
    }

    /**
     * The hex {@code RegistrationRequest} to send to {@code register/start}.
     *
     * @return the first protocol message
     */
    public String request() {
        return firstMessage();
    }

    /**
     * Seals the envelope under the server's oblivious PRF.
     *
     * @param password the plaintext being enrolled; every copy this SDK makes
     *                 is cleared, but not the caller's
     * @param registrationResponse the server's hex {@code RegistrationResponse}
     * @param ksf      the key-stretching function the server named
     * @return the hex {@code RegistrationRecord} to attach to the request that
     *         sets the password
     * @throws NetworkError if the exchange is already spent, the key-stretching
     *                      function is one this SDK cannot ask for, or the
     *                      library refuses the response
     */
    public String finish(char[] password, String registrationResponse, KsfParams ksf) {
        // The key-stretching handle is built BEFORE the state is spent, and the
        // order is load-bearing. build() refuses an unrecognised function or an
        // out-of-band cost, and if the state had already been taken out of its
        // one-shot slot by then it could never be freed -- a leaked Rust
        // allocation per refused attempt, which is once per login against a
        // misconfigured tenant. Built first, a refusal leaves the exchange
        // intact: close() still releases it, and a caller who fixes the
        // parameters can retry.
        Pointer ksfHandle = ksf.build(lib);
        byte[] encoded = Opaque.nulTerminatedUtf8(password);
        try {
            Pointer state = consume();
            Pointer record = lib.axiam_opaque_registration_finish(
                    state, encoded, Opaque.nulTerminatedAscii(registrationResponse),
                    ksfHandle, null);
            if (record == null) {
                throw new NetworkError("OPAQUE: "
                        + Opaque.lastError(lib, "the envelope could not be sealed"));
            }
            return Opaque.take(lib, record);
        } finally {
            lib.axiam_opaque_ksf_free(ksfHandle);
            Arrays.fill(encoded, (byte) 0);
        }
    }
}
