package io.axiam.sdk.opaque;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import io.axiam.sdk.errors.NetworkError;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Entry points into {@code libaxiam_opaque_ffi} (CONTRACT.md &sect;23).
 *
 * <p>There is no cryptography in this class, or anywhere in this package. That
 * is deliberate and is what &sect;23.1 requires: OPAQUE needs an oblivious PRF,
 * {@code hash_to_curve}, {@code expand_message_xmd}, an envelope construction
 * and a three-message AKE, and eleven independent implementations of that is
 * eleven chances to be subtly and silently wrong. The SRP-6a this replaces was
 * arithmetic every language can express, which is why {@code io.axiam.sdk.srp}
 * existed.
 */
public final class Opaque {

    private Opaque() {
    }

    /**
     * Whether this installation can perform OPAQUE (&sect;23.2).
     *
     * <p>Reports rather than throwing, and is genuinely able to answer
     * {@code false}: both JNA and the shared library are optional. Ask before
     * a login rather than discovering the gap mid-exchange.
     *
     * @return {@code true} when both the binding and the library are present
     *         and the library says it can
     */
    public static boolean available() {
        OpaqueNative lib = OpaqueLibrary.load();
        return lib != null && lib.axiam_opaque_available() != 0;
    }

    /**
     * Blinds {@code password} to open an enrolment.
     *
     * @param password the plaintext being enrolled; every copy this SDK makes
     *                 is cleared, but not the caller's
     * @return an exchange whose {@code request()} goes to {@code register/start}
     * @throws NetworkError if the library is unavailable or refuses
     */
    public static RegistrationExchange startRegistration(char[] password) {
        OpaqueNative lib = OpaqueLibrary.require();
        byte[] encoded = nulTerminatedUtf8(password);
        PointerByReference out = new PointerByReference();
        try {
            Pointer handle = lib.axiam_opaque_registration_start(encoded, out);
            if (handle == null) {
                throw new NetworkError("OPAQUE: "
                        + lastError(lib, "registration could not be started"));
            }
            return new RegistrationExchange(lib, handle, take(lib, out.getValue()));
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * Blinds {@code password} to open a login.
     *
     * @param password the account password; every copy this SDK makes is
     *                 cleared, but not the caller's
     * @return an exchange whose {@code ke1()} goes to {@code login/start}
     * @throws NetworkError if the library is unavailable or refuses
     */
    public static LoginExchange startLogin(char[] password) {
        OpaqueNative lib = OpaqueLibrary.require();
        byte[] encoded = nulTerminatedUtf8(password);
        PointerByReference out = new PointerByReference();
        try {
            Pointer handle = lib.axiam_opaque_login_start(encoded, out);
            if (handle == null) {
                throw new NetworkError("OPAQUE: " + lastError(lib, "login could not be started"));
            }
            return new LoginExchange(lib, handle, take(lib, out.getValue()));
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * Takes ownership of a returned string, freeing the Rust allocation.
     *
     * <p>Called on every path that receives one, including the error paths: a
     * binding that frees only on success leaks once per failed login, which is
     * the login rate an installation under attack sees.
     */
    static String take(OpaqueNative lib, Pointer ptr) {
        if (ptr == null) {
            throw new NetworkError("OPAQUE: " + lastError(lib, "the library returned no value"));
        }
        try {
            return ptr.getString(0, "UTF-8");
        } finally {
            lib.axiam_opaque_string_free(ptr);
        }
    }

    /**
     * The library's description of the last failure, or {@code fallback}.
     *
     * <p>The returned pointer is borrowed — library-owned, not freed here. A
     * failure with nothing behind it is a library bug, but a caller still
     * deserves a sentence rather than an empty one.
     */
    static String lastError(OpaqueNative lib, String fallback) {
        Pointer raw = lib.axiam_opaque_last_error();
        if (raw == null) {
            return fallback;
        }
        String message = raw.getString(0, "UTF-8");
        return message.isEmpty() ? fallback : message;
    }

    /**
     * Encodes a password as NUL-terminated UTF-8, without an intermediate
     * {@code String}.
     *
     * <p>UTF-8 explicitly rather than through JNA's {@code String} mapping,
     * which uses the platform charset unless {@code jna.encoding} says
     * otherwise: a password that encoded differently under a different default
     * locale would derive a randomized password no AXIAM server agrees with,
     * and would surface as a wrong password on that machine only.
     *
     * <p>No {@code String} because a {@code String} cannot be cleared. The
     * caller clears the returned array.
     */
    static byte[] nulTerminatedUtf8(char[] password) {
        CharBuffer chars = CharBuffer.wrap(password);
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(chars);
        byte[] out = new byte[encoded.remaining() + 1];
        encoded.get(out, 0, out.length - 1);
        if (encoded.hasArray()) {
            Arrays.fill(encoded.array(), (byte) 0);
        }
        return out;
    }

    /**
     * Encodes a hex protocol message as a NUL-terminated byte array.
     *
     * <p>Separate from {@link #nulTerminatedUtf8} because these are not
     * secrets and need no clearing — and because passing them through the same
     * helper would suggest they do.
     */
    static byte[] nulTerminatedAscii(String hex) {
        byte[] raw = hex.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[raw.length + 1];
        System.arraycopy(raw, 0, out, 0, raw.length);
        return out;
    }
}
