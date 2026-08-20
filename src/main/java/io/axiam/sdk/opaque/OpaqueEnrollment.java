package io.axiam.sdk.opaque;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * The {@code opaque} object CONTRACT.md &sect;23 defines: a registration record
 * and the server-issued session handle that identifies the exchange it came
 * from.
 *
 * <p>The server cannot build this — it never sees the plaintext — so any
 * request that <strong>sets</strong> a password has to carry it:
 * {@code POST /api/v1/users}, {@code /auth/password/change},
 * {@code /auth/reset/confirm} and {@code /admin/bootstrap}.
 *
 * <p>Note what is <em>not</em> here. The SRP enrolment this replaces carried a
 * salt, a group and a full set of KDF costs, and required the account's
 * canonical username — passing an email produced a verifier no login could
 * ever satisfy. A record binds to a credential identifier the server chooses,
 * and the key-stretching parameters are the server's, so there is nothing here
 * a caller can get wrong and no rename that can invalidate a credential.
 *
 * @param opaqueSession      the handle {@code register/start} issued
 * @param registrationRecord the hex {@code RegistrationRecord}
 */
public record OpaqueEnrollment(String opaqueSession, String registrationRecord) {

    /**
     * Renders this enrolment as the JSON object the password-setting endpoints
     * accept.
     *
     * @param mapper the mapper to allocate the node from
     * @return a node ready to attach as the request's {@code opaque} member
     */
    public ObjectNode toJson(ObjectMapper mapper) {
        ObjectNode node = mapper.createObjectNode();
        node.put("opaque_session", opaqueSession);
        node.put("registration_record", registrationRecord);
        return node;
    }
}
