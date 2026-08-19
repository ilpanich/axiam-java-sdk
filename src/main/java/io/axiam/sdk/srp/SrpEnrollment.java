package io.axiam.sdk.srp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * The {@code srp} object CONTRACT.md &sect;23.5 defines: a verifier and the
 * parameters it was computed under.
 *
 * <p>The server cannot compute this — it never sees the plaintext — so any
 * request that <strong>sets</strong> a password has to carry it:
 * {@code POST /api/v1/users}, {@code /auth/password/change},
 * {@code /auth/reset/confirm} and {@code /admin/bootstrap} (&sect;23.3 rule 11).
 *
 * <p>Neither {@code salt} nor {@code verifier} may be logged (&sect;23.3
 * rule 12), which is why this record deliberately does not override
 * {@code toString()} into something friendlier: the default record rendering
 * already names them, and a "helpful" one-line summary is exactly how such a
 * value reaches a log.
 *
 * @param group       the wire group name the verifier lives in
 * @param kdf         the KDF used to derive {@code x}
 * @param memoryKib   Argon2id's memory cost, or {@code 0} for PBKDF2
 * @param iterations  the KDF's iteration/time cost
 * @param parallelism Argon2id's lane count, or {@code 0} for PBKDF2
 * @param salt        the 32-byte enrolment salt, lowercase hex
 * @param verifier    {@code v = g^x mod N}, lowercase hex
 */
public record SrpEnrollment(
        String group,
        String kdf,
        int memoryKib,
        int iterations,
        int parallelism,
        String salt,
        String verifier) {

    /**
     * Renders this enrolment as the JSON object the password-setting
     * endpoints accept.
     *
     * @param mapper the mapper to allocate the node from
     * @return a node ready to attach as the request's {@code srp} member
     */
    public ObjectNode toJson(ObjectMapper mapper) {
        ObjectNode node = mapper.createObjectNode();
        node.put("group", group);
        node.put("kdf", kdf);
        if (memoryKib > 0) {
            node.put("memory_kib", memoryKib);
        }
        node.put("iterations", iterations);
        if (parallelism > 0) {
            node.put("parallelism", parallelism);
        }
        node.put("salt", salt);
        node.put("verifier", verifier);
        return node;
    }
}
