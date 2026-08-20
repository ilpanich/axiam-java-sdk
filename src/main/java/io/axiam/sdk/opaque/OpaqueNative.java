package io.axiam.sdk.opaque;

import com.sun.jna.Library;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

/**
 * The {@code libaxiam_opaque_ffi} C ABI, exactly as
 * {@code include/axiam/opaque.h} declares it.
 *
 * <p>An interface rather than a set of {@code static native} methods for two
 * reasons. It is what JNA binds, and — less obviously but more usefully — it
 * is what a test can implement in plain Java. The contract this ABI carries is
 * about <em>ownership</em>: who frees a returned string, when a state handle is
 * spent, what a {@code NULL} means. Those are the rules a binding gets wrong,
 * and they can be exercised exhaustively against a stand-in without the real
 * shared library present.
 *
 * <p>Strings cross as {@code byte[]}, NUL-terminated and UTF-8, never as
 * {@code String}. JNA's {@code String} mapping encodes with the platform
 * charset unless {@code jna.encoding} is set, and a password that round-trips
 * differently on a machine with a different default locale would produce a
 * randomized password no AXIAM server agrees with — surfacing as a wrong
 * password on that machine only. The conformance vectors require UTF-8.
 */
interface OpaqueNative extends Library {

    /** Releases a string this library returned. Rust allocated it; Rust frees it. */
    void axiam_opaque_string_free(Pointer ptr);

    /**
     * Describes the last failure on this thread.
     *
     * @return a borrowed, library-owned string — <strong>not</strong> to be freed
     */
    Pointer axiam_opaque_last_error();

    /**
     * Whether this build can perform OPAQUE.
     *
     * @return nonzero when it can
     */
    int axiam_opaque_available();

    /**
     * Builds an Argon2id key-stretching handle.
     *
     * @param memoryKib   memory cost in KiB
     * @param iterations  time cost
     * @param parallelism lane count
     * @return the handle, or {@code null} when the parameters are refused
     */
    Pointer axiam_opaque_ksf_argon2id(int memoryKib, int iterations, int parallelism);

    /**
     * Builds a scrypt key-stretching handle.
     *
     * @param logN the base-2 logarithm of the CPU/memory cost
     * @param r    the block size
     * @param p    the parallelisation parameter
     * @return the handle, or {@code null} when the parameters are refused
     */
    Pointer axiam_opaque_ksf_scrypt(byte logN, int r, int p);

    /**
     * Releases a key-stretching handle.
     *
     * @param ptr the handle
     */
    void axiam_opaque_ksf_free(Pointer ptr);

    /**
     * Begins an enrolment, writing the hex {@code RegistrationRequest} to
     * {@code outRequest}.
     *
     * @param password   the NUL-terminated UTF-8 password
     * @param outRequest receives the hex request, which the caller frees
     * @return the state handle, or {@code null} on failure
     */
    Pointer axiam_opaque_registration_start(byte[] password, PointerByReference outRequest);

    /**
     * Completes an enrolment, <strong>consuming</strong> {@code state} whether
     * it succeeds or fails.
     *
     * @param state                the handle from {@code registration_start}
     * @param password             the NUL-terminated UTF-8 password
     * @param registrationResponse the server's hex {@code RegistrationResponse}
     * @param ksf                  the key-stretching handle
     * @param outExportKey         may be {@code null}
     * @return the hex {@code RegistrationRecord}, or {@code null} on failure
     */
    Pointer axiam_opaque_registration_finish(Pointer state, byte[] password,
                                             byte[] registrationResponse, Pointer ksf,
                                             PointerByReference outExportKey);

    /**
     * Releases enrolment state that was never finished.
     *
     * @param ptr the handle
     */
    void axiam_opaque_registration_free(Pointer ptr);

    /**
     * Begins a login, writing the hex {@code KE1} to {@code outKe1}.
     *
     * @param password the NUL-terminated UTF-8 password
     * @param outKe1   receives the hex {@code KE1}, which the caller frees
     * @return the state handle, or {@code null} on failure
     */
    Pointer axiam_opaque_login_start(byte[] password, PointerByReference outKe1);

    /**
     * Completes a login, <strong>consuming</strong> {@code state}.
     *
     * <p>A {@code null} return is the whole of the client's authentication
     * check, and it covers both halves of the mutual authentication: the
     * envelope only opens under the right password, and {@code KE2}'s MAC only
     * verifies if the server actually holds the record. Per CONTRACT.md
     * &sect;23.4 rule 7 nothing may be sent to {@code login/finish} after it.
     *
     * @param state          the handle from {@code login_start}
     * @param password       the NUL-terminated UTF-8 password
     * @param ke2            the server's hex {@code KE2}
     * @param ksf            the key-stretching handle
     * @param outSessionKey  may be {@code null}
     * @param outExportKey   may be {@code null}
     * @return the hex {@code KE3}, or {@code null} on failure
     */
    Pointer axiam_opaque_login_finish(Pointer state, byte[] password, byte[] ke2, Pointer ksf,
                                      PointerByReference outSessionKey,
                                      PointerByReference outExportKey);

    /**
     * Releases login state that was never finished.
     *
     * @param ptr the handle
     */
    void axiam_opaque_login_free(Pointer ptr);
}
