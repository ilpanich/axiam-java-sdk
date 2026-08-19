package io.axiam.sdk.srp;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * The KDF and cost the server dictates for one SRP exchange (CONTRACT.md
 * &sect;23.5).
 *
 * <p>&sect;23.3 rule 4: these arrive per exchange and are honoured as given.
 * They are deliberately <strong>not</strong> cached across logins — a verifier
 * enrolled under different costs is still valid and has to keep working.
 *
 * @param kdf         {@code "argon2id"} or {@code "pbkdf2_sha256"}
 * @param iterations  Argon2id's time cost, or PBKDF2's iteration count
 * @param memoryKib   Argon2id's memory cost in KiB; ignored for PBKDF2
 * @param parallelism Argon2id's lane count; ignored for PBKDF2
 */
public record SrpKdfParams(String kdf, int iterations, int memoryKib, int parallelism) {

    /** The wire name of the memory-hard KDF AXIAM asks for by default. */
    public static final String ARGON2ID = "argon2id";

    /** The wire name of the fallback for runtimes with no vetted Argon2. */
    public static final String PBKDF2_SHA256 = "pbkdf2_sha256";

    /**
     * Reads the KDF fields of a challenge response.
     *
     * <p>{@code memory_kib} and {@code parallelism} are present only for
     * {@code argon2id}, so their absence is normal rather than an error.
     *
     * @param challenge the parsed challenge response body
     * @return the parameters that exchange must use
     */
    public static SrpKdfParams fromChallenge(JsonNode challenge) {
        return new SrpKdfParams(
                challenge.path("kdf").asText(""),
                challenge.path("iterations").asInt(0),
                challenge.path("memory_kib").asInt(0),
                challenge.path("parallelism").asInt(0));
    }

    /**
     * This instance with any zero cost replaced by AXIAM's default for the
     * chosen KDF.
     *
     * <p>Used on the enrolment path, where the caller may know only which KDF
     * the tenant runs. It is never applied to a challenge response: a server
     * that omits a cost it is required to send is a server this SDK should
     * not be guessing on behalf of.
     *
     * @return the same parameters with defaults filled in
     */
    public SrpKdfParams withDefaults() {
        String resolvedKdf = kdf == null || kdf.isEmpty() ? ARGON2ID : kdf;
        if (PBKDF2_SHA256.equals(resolvedKdf)) {
            return new SrpKdfParams(resolvedKdf, iterations > 0 ? iterations : 600_000, 0, 0);
        }
        return new SrpKdfParams(
                resolvedKdf,
                iterations > 0 ? iterations : 2,
                memoryKib > 0 ? memoryKib : 19456,
                parallelism > 0 ? parallelism : 1);
    }
}
