package io.axiam.sdk.opaque;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.jna.Pointer;
import io.axiam.sdk.errors.NetworkError;
import org.jspecify.annotations.Nullable;

/**
 * The key-stretching function and cost a {@code &#42;/start} response names
 * (CONTRACT.md &sect;23.4).
 *
 * <p>Fields are boxed and nullable on purpose: they arrive flat, and a field
 * that does not apply to the named function is <strong>absent, not zero</strong>.
 * Reading a missing {@code memory_kib} as {@code 0} would stretch at the wrong
 * cost and fail against a record that is perfectly good (&sect;23.4 rule 5).
 *
 * <p>These are never cached across exchanges and never defaulted locally. A
 * credential enrolled under one cost keeps working after a tenant raises its
 * policy, so a client that guessed would derive a different randomized
 * password and report "invalid password" for one that is entirely correct
 * (&sect;23.4 rule 2).
 *
 * @param ksf         the wire name of the function: {@code argon2id} or {@code scrypt}
 * @param memoryKib   Argon2id's memory cost in KiB
 * @param iterations  Argon2id's time cost
 * @param parallelism Argon2id's lane count
 * @param logN        scrypt's base-2 CPU/memory cost
 * @param r           scrypt's block size
 * @param p           scrypt's parallelisation parameter
 */
public record KsfParams(
        String ksf,
        @Nullable Integer memoryKib,
        @Nullable Integer iterations,
        @Nullable Integer parallelism,
        @Nullable Integer logN,
        @Nullable Integer r,
        @Nullable Integer p) {

    /** The wire name of the memory-hard function AXIAM asks for by default. */
    public static final String ARGON2ID = "argon2id";

    /** The wire name of the alternative AXIAM accepts. */
    public static final String SCRYPT = "scrypt";

    /**
     * Reads the flat key-stretching fields of a {@code &#42;/start} response,
     * preserving absence.
     *
     * @param wire the parsed response body
     * @return the parameters that exchange must use
     */
    public static KsfParams fromWire(JsonNode wire) {
        return new KsfParams(
                wire.path("ksf").asText(""),
                optional(wire, "memory_kib"),
                optional(wire, "iterations"),
                optional(wire, "parallelism"),
                optional(wire, "log_n"),
                optional(wire, "r"),
                optional(wire, "p"));
    }

    private static @Nullable Integer optional(JsonNode wire, String field) {
        JsonNode node = wire.get(field);
        if (node == null || node.isNull()) {
            return null;
        }
        return node.asInt();
    }

    /**
     * Builds the library's key-stretching handle from what the <em>server</em>
     * named.
     *
     * <p>An unrecognised function is refused, never substituted: substituting
     * produces a well-formed randomized password no AXIAM server agrees with,
     * which surfaces to the user as a wrong password (&sect;23.4 rule 3).
     *
     * @param lib the loaded library
     * @return a handle the caller must release with {@code ksf_free}
     * @throws NetworkError if a cost is missing, out of range, or the function
     *                      is one this SDK cannot ask for
     */
    Pointer build(OpaqueNative lib) {
        Pointer handle;
        if (ARGON2ID.equals(ksf)) {
            handle = lib.axiam_opaque_ksf_argon2id(
                    require("memory_kib", memoryKib, 8192, 1_048_576),
                    require("iterations", iterations, 1, 10),
                    require("parallelism", parallelism, 1, 16));
        } else if (SCRYPT.equals(ksf)) {
            handle = lib.axiam_opaque_ksf_scrypt(
                    (byte) require("log_n", logN, 14, 20),
                    require("r", r, 1, 16),
                    require("p", p, 1, 16));
        } else {
            throw new NetworkError("OPAQUE: this SDK cannot perform the key-stretching function "
                    + "the server named (`" + ksf + "`)");
        }
        if (handle == null) {
            throw new NetworkError("OPAQUE: " + Opaque.lastError(lib, "invalid KSF parameters"));
        }
        return handle;
    }

    /**
     * One cost the named function needs: present, and inside the band this SDK
     * will act on.
     *
     * <p>A server is trusted to name its own policy, not to name a cost that
     * would wedge every device an account owns. The library range-checks too;
     * doing it here as well means the refusal names the field.
     */
    private int require(String field, @Nullable Integer value, int low, int high) {
        if (value == null) {
            throw new NetworkError("OPAQUE: the server named ksf `" + ksf
                    + "` without `" + field + "`");
        }
        if (value < low || value > high) {
            throw new NetworkError("OPAQUE: the server named " + field + "=" + value
                    + " for `" + ksf + "`, outside the accepted " + low + ".." + high);
        }
        return value;
    }
}
