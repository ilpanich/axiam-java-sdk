package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.errors.ConflictError;
import io.axiam.sdk.management.models.Certificate;
import io.axiam.sdk.management.models.CertificateType;
import io.axiam.sdk.management.models.CreateCertificateRequest;
import io.axiam.sdk.management.models.GeneratedCertificate;
import io.axiam.sdk.management.models.KeyAlgorithm;
import io.axiam.sdk.management.models.SignCertificateCsrRequest;
import io.axiam.sdk.management.models.SsfDeliveryMethod;
import io.axiam.sdk.management.models.SsfStream;
import io.axiam.sdk.management.models.SsfStreamInput;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md contract 1.61: {@code Certificate.user_id} and its request members
 * (&sect;27.11 rule 5), {@code SsfStreamInput.expected_updated_at} and the three
 * meanings of {@code events_requested} on an update (&sect;32.2, &sect;32.3 rule 4,
 * &sect;32.8 test 1) &mdash; each over the wire against the mocked server.
 *
 * <p>{@code CibaPendingList} (&sect;33.3 rule 16) is not modelled by this SDK: no
 * registry operation returns it and the SDK generates models only for the types the
 * operations carry (the route is a console surface, &sect;33.9).
 */
class Contract161ModelsTest extends ManagementTestBase {

    private static final String STREAMS = "/api/v1/tenants/" + TENANT_ID + "/ssf/streams";
    private static final String EVENT = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

    private static ObjectNode certBody(UUID userId, boolean withMember) {
        ObjectNode b = JSON.createObjectNode();
        b.put("cert_type", "User");
        b.put("created_at", "2026-10-13T00:00:00Z");
        b.put("fingerprint", "example");
        b.put("id", UUID.randomUUID().toString());
        b.put("issuer_ca_id", EXAMPLE_ID.toString());
        b.put("key_algorithm", "Rsa4096");
        b.putObject("metadata");
        b.put("not_after", "2027-10-13T00:00:00Z");
        b.put("not_before", "2026-10-13T00:00:00Z");
        b.put("public_cert_pem", "example");
        b.put("status", "Active");
        b.put("subject", "example");
        b.put("tenant_id", TENANT_ID.toString());
        if (withMember) {
            if (userId == null) {
                b.putNull("user_id");
            } else {
                b.put("user_id", userId.toString());
            }
        }
        return b;
    }

    private static CreateCertificateRequest generateRequest(UUID userId) {
        return new CreateCertificateRequest(CertificateType.USER, EXAMPLE_ID, KeyAlgorithm.RSA4096, null,
                "example", null, userId, 365);
    }

    private static SignCertificateCsrRequest csrRequest(UUID userId) {
        return new SignCertificateCsrRequest(CertificateType.USER, "example", EXAMPLE_ID, null, null, userId, 365);
    }

    // ── §27.11 rule 5: the required test ─────────────────────────────────

    @Test
    void generateAndSignCsrSendUserIdExactlyAsGivenAndNoKeyWithoutOne() throws Exception {
        UUID user = UUID.randomUUID();
        ObjectNode generated = certBody(user, true);
        generated.put("private_key_pem", "example");
        Route generate = mount("POST", "/api/v1/certificates", 201, generated.toString());
        Route sign = mount("POST", "/api/v1/certificates/sign-csr", 201, certBody(user, true).toString());

        client.management().certificates().generate(generateRequest(user));
        assertEquals(user.toString(), generate.last().json().path("user_id").asText());
        client.management().certificates().generate(generateRequest(null));
        assertFalse(generate.last().json().has("user_id"), "no account named: no key, and never null");

        client.management().certificates().signCsr(csrRequest(user));
        assertEquals(user.toString(), sign.last().json().path("user_id").asText());
        client.management().certificates().signCsr(csrRequest(null));
        assertFalse(sign.last().json().has("user_id"), "no account named: no key, and never null");
    }

    @Test
    void aCertificateBodyWithAUuidANullAndNoMemberAllDecode() throws Exception {
        UUID user = UUID.randomUUID();
        UUID a = UUID.randomUUID();
        UUID b = UUID.randomUUID();
        UUID c = UUID.randomUUID();
        mount("GET", "/api/v1/certificates/" + a, 200, certBody(user, true).toString());
        mount("GET", "/api/v1/certificates/" + b, 200, certBody(null, true).toString());
        mount("GET", "/api/v1/certificates/" + c, 200, certBody(null, false).toString());

        assertEquals(user, client.management().certificates().get(a).userId());
        assertNull(client.management().certificates().get(b).userId(), "null: no account named");
        assertNull(client.management().certificates().get(c).userId(), "absent (a pre-1.0.1 server): no account named");

        // Inside GeneratedCertificate and as a list item: the same member, the same rule.
        GeneratedCertificate withKey = JSON.treeToValue(
                certBody(user, true).put("private_key_pem", "example"), GeneratedCertificate.class);
        assertEquals(user, withKey.userId());
        assertNull(JSON.treeToValue(certBody(null, false).put("private_key_pem", "example"),
                GeneratedCertificate.class).userId());
        Certificate listed = JSON.treeToValue(certBody(null, true), Certificate.class);
        assertNull(listed.userId());
        // Never synthesised from the metadata or the subject.
        ObjectNode legacy = certBody(null, false);
        legacy.putObject("metadata").put("user_id", user.toString());
        assertNull(JSON.treeToValue(legacy, Certificate.class).userId());
    }

    // ── §32.8 test 1: expected_updated_at and events_requested ───────────

    private static ObjectNode streamBody(String updatedAt, List<String> requested) {
        ObjectNode b = JSON.createObjectNode();
        b.put("id", UUID.randomUUID().toString());
        b.put("tenant_id", TENANT_ID.toString());
        b.put("receiver_client_id", "rp-1");
        b.put("audience", "https://rp.example");
        b.put("delivery_method", "push");
        b.put("endpoint_url", "https://rp.example/ssf");
        b.put("authorization_header_set", false);
        b.putArray("events_allowed").add(EVENT);
        if (requested != null) {
            requested.forEach(b.putArray("events_requested")::add);
            if (requested.isEmpty()) {
                b.putArray("events_requested");
            }
        }
        b.putArray("events_delivered");
        b.put("subject_format", "iss_sub");
        b.put("status", "enabled");
        b.put("status_actor", "admin");
        b.put("created_at", "2026-10-04T00:00:00Z");
        b.put("updated_at", updatedAt);
        b.put("transmitter_active", true);
        return b;
    }

    private static SsfStreamInput input(List<String> requested, String expectedUpdatedAt) {
        return new SsfStreamInput("https://rp.example", null, null, SsfDeliveryMethod.PUSH, null,
                "https://rp.example/ssf", List.of(EVENT), requested, expectedUpdatedAt, "rp-1", null, null, null);
    }

    @Test
    void expectedUpdatedAtIsSentExactlyAsGivenAndAbsentWhenUnset() throws Exception {
        UUID id = UUID.randomUUID();
        Route put = mount("PUT", STREAMS + "/" + id, 200, streamBody("2026-10-04T00:00:00Z", List.of(EVENT)).toString());
        // A non-UTC offset and a trailing-zero fraction an OffsetDateTime would re-render.
        String read = "2026-10-05T02:00:00.120000+02:00";
        client.ssf().updateStream(id, input(null, read));
        assertEquals(read, put.last().json().path("expected_updated_at").asText());
        assertTrue(put.last().json().path("expected_updated_at").isTextual());
        client.ssf().updateStream(id, input(null, null));
        assertFalse(put.last().json().has("expected_updated_at"), "absent when unset, never null");

        // events_requested: [] is sent as [], an unset one is absent.
        client.ssf().updateStream(id, input(List.of(), null));
        JsonNode empty = put.last().json().path("events_requested");
        assertTrue(empty.isArray() && empty.isEmpty(), "[] is sent as []");
        client.ssf().updateStream(id, input(null, null));
        assertFalse(put.last().json().has("events_requested"), "unset is absent");
    }

    @Test
    void aConflictOnUpdateIsSurfacedAndNotRetried() throws Exception {
        UUID id = UUID.randomUUID();
        Route conflict = mount("PUT", STREAMS + "/" + id, 409,
                "{\"error\":\"conflict\",\"message\":\"the stream changed since it was read\"}");
        ConflictError e = assertThrows(ConflictError.class,
                () -> client.ssf().updateStream(id, input(List.of(EVENT), "2026-10-04T00:00:00Z")));
        assertTrue(e.getMessage().contains("changed since it was read"), e.getMessage());
        assertEquals(1, conflict.calls(), "a 409 is the caller's to resolve: one request");
        assertEquals("2026-10-04T00:00:00Z", conflict.last().json().path("expected_updated_at").asText());
    }

    @Test
    void theReadModifyWriteHelperSendsBackWhatItRead() throws Exception {
        UUID id = UUID.randomUUID();
        Route put = mount("PUT", STREAMS + "/" + id, 200, streamBody("2026-10-04T00:00:00Z", List.of()).toString());

        // The receiver narrowed the stream to "none": [] goes back as [], never omitted.
        SsfStream none = JSON.treeToValue(streamBody("2026-10-05T02:00:00.5+02:00", List.of()), SsfStream.class);
        assertEquals(List.of(), none.eventsRequested());
        client.ssf().updateStream(id, ReplacementBodies.from(none));
        JsonNode sent = put.last().json();
        assertTrue(sent.path("events_requested").isArray() && sent.path("events_requested").isEmpty(),
                "[] goes back as []");
        assertTrue(sent.has("expected_updated_at"), "the version it read goes back");
        assertEquals(none.updatedAt().toInstant(),
                java.time.OffsetDateTime.parse(sent.path("expected_updated_at").asText()).toInstant(),
                "the same instant as the updated_at it read");

        // A list the receiver chose goes back as given.
        SsfStream some = JSON.treeToValue(streamBody("2026-10-04T00:00:00Z", List.of(EVENT)), SsfStream.class);
        client.ssf().updateStream(id, ReplacementBodies.from(some));
        assertEquals(EVENT, put.last().json().path("events_requested").get(0).asText());
        assertEquals("2026-10-04T00:00:00Z", put.last().json().path("expected_updated_at").asText());
    }
}
