package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.management.models.Certificate;
import io.axiam.sdk.management.models.CertificateType;
import io.axiam.sdk.management.models.CreateCertificateRequest;
import io.axiam.sdk.management.models.KeyAlgorithm;
import io.axiam.sdk.management.models.ScimTargetInput;
import io.axiam.sdk.management.models.SignCertificateCsrRequest;
import io.axiam.sdk.management.models.SsfDeliveryMethod;
import io.axiam.sdk.management.models.SsfStream;
import io.axiam.sdk.management.models.SsfStreamInput;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract 1.62, CONTRACT.md &sect;34.6 items (e), (f), (g), (h) and (i): the change-taking
 * form for a stream (&sect;32.2, &sect;32.8 test 7), an assigned {@code null} is "none"
 * (&sect;27.11 rule 5), {@code expected_updated_at} is the response's own string, the three
 * meanings of {@code events_requested} at the {@code update_stream} call site, and the request
 * {@code user_id} is an untyped string.
 */
class Contract162ModelsTest extends ManagementTestBase {

    private static final String STREAMS = "/api/v1/tenants/" + TENANT_ID + "/ssf/streams";
    private static final String A = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    private static final String B = "https://schemas.openid.net/secevent/caep/event-type/credential-change";
    private static final String C = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
    /** A fixture with a {@code +00:00} offset and nine fraction digits: an OffsetDateTime renders neither. */
    private static final String UPDATED_AT = "2026-10-05T02:00:00.123456789+00:00";

    private static ObjectNode streamBody(List<String> allowed, List<String> requested, String updatedAt) {
        ObjectNode b = JSON.createObjectNode();
        b.put("id", UUID.randomUUID().toString());
        b.put("tenant_id", TENANT_ID.toString());
        b.put("receiver_client_id", "rp-1");
        b.put("audience", "https://rp.example");
        b.put("delivery_method", "push");
        b.put("endpoint_url", "https://rp.example/ssf");
        b.put("authorization_header_set", true);
        allowed.forEach(b.putArray("events_allowed")::add);
        requested.forEach(b.putArray("events_requested")::add);
        if (requested.isEmpty()) {
            b.putArray("events_requested");
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

    private SsfStream read(List<String> allowed, List<String> requested, String updatedAt) throws Exception {
        return JSON.treeToValue(streamBody(allowed, requested, updatedAt), SsfStream.class);
    }

    // -- (g) the response's own string ----------------------------------------------------------

    @Test
    void anSsfStreamKeepsTheServersOwnStringNextToTheParsedInstant() throws Exception {
        SsfStream stream = read(List.of(A), List.of(A), UPDATED_AT);
        assertEquals(UPDATED_AT, stream.updatedAtRaw(), "byte for byte");
        assertEquals(OffsetDateTime.parse(UPDATED_AT), stream.updatedAt());
        // An OffsetDateTime does NOT hold that spelling: this is why the raw string is kept.
        assertTrue(!stream.updatedAt().toString().equals(UPDATED_AT));
        // The wire name is still `updated_at`, once.
        JsonNode rendered = JSON.valueToTree(stream);
        assertEquals(UPDATED_AT, rendered.path("updated_at").asText());
        assertFalse(rendered.has("updatedAtRaw"));
    }

    @Test
    void theResponseOwnStringComesBackFromAWholeUpdateRoundTrip() throws Exception {
        UUID id = UUID.randomUUID();
        Route put = mount("PUT", STREAMS + "/" + id, 200, streamBody(List.of(A), List.of(A), UPDATED_AT).toString());
        Route get = mount("GET", STREAMS + "/" + id, 200, streamBody(List.of(A), List.of(A), UPDATED_AT).toString());

        SsfStream stream = client.ssf().getStream(id);
        client.ssf().updateStream(id, ReplacementBodies.from(stream));

        assertEquals(UPDATED_AT, put.last().json().path("expected_updated_at").asText(),
                "the plain converter sends the response's own string");
        assertEquals(1, get.calls());
    }

    // -- (e) the change-taking form -------------------------------------------------------------

    @Test
    void loweringTheCeilingCutsEventsRequestedToWhatIsLeftInIt() throws Exception {
        SsfStream stream = read(List.of(A, B, C), List.of(C, A), UPDATED_AT);

        SsfStreamInput body = ReplacementBodies.ssfStream(stream,
                SsfStreamChanges.builder().eventsAllowed(List.of(A)).build());

        assertEquals(List.of(A), body.eventsAllowed());
        assertEquals(List.of(A), body.eventsRequested(), "only what is in the new ceiling");
        assertEquals(UPDATED_AT, body.expectedUpdatedAt(), "as read");

        // The entries that stay keep the order they were read in.
        SsfStreamInput two = ReplacementBodies.ssfStream(stream,
                SsfStreamChanges.builder().eventsAllowed(List.of(A, C)).build());
        assertEquals(List.of(C, A), two.eventsRequested());
    }

    @Test
    void aChangeThatLeavesEventsAloneSendsThemAsReadAnEmptyListAsEmptyAndTheOwnString() throws Exception {
        UUID id = UUID.randomUUID();
        Route put = mount("PUT", STREAMS + "/" + id, 200, streamBody(List.of(A), List.of(), UPDATED_AT).toString());

        // The receiver narrowed the stream to "none".
        SsfStream none = read(List.of(A, B, C), List.of(), UPDATED_AT);
        client.ssf().updateStream(id, ReplacementBodies.ssfStream(none,
                SsfStreamChanges.builder().description("renamed").build()));

        JsonNode sent = put.last().json();
        assertTrue(sent.path("events_requested").isArray() && sent.path("events_requested").isEmpty(),
                "[] stays []");
        assertEquals(UPDATED_AT, sent.path("expected_updated_at").asText(), "byte for byte, +00:00 and nine digits");
        assertEquals("renamed", sent.path("description").asText());
        assertEquals(List.of(A, B, C), strings(sent.path("events_allowed")));
        assertEquals("rp-1", sent.path("receiver_client_id").asText(), "everything else as read");
        assertFalse(sent.has("authorization_header"), "absent keeps the stored header");

        SsfStream some = read(List.of(A, B, C), List.of(B, A), UPDATED_AT);
        client.ssf().updateStream(id, ReplacementBodies.ssfStream(some));
        assertEquals(List.of(B, A), strings(put.last().json().path("events_requested")));
    }

    @Test
    void anEventsRequestedTheChangesNameIsSentAsGivenAndNullOmitsIt() throws Exception {
        SsfStream stream = read(List.of(A, B), List.of(A), UPDATED_AT);

        // The ceiling is lowered AND events_requested is named: the server judges it.
        SsfStreamInput named = ReplacementBodies.ssfStream(stream, SsfStreamChanges.builder()
                .eventsAllowed(List.of(A)).eventsRequested(List.of(B)).build());
        assertEquals(List.of(B), named.eventsRequested(), "as given, not cut");

        SsfStreamInput reset = ReplacementBodies.ssfStream(stream,
                SsfStreamChanges.builder().eventsRequested(null).build());
        assertNull(reset.eventsRequested(), "an assigned null omits the key, which resets (the caller said so)");
    }

    @Test
    void anAssignedNullForExpectedUpdatedAtLeavesTheKeyOut() throws Exception {
        UUID id = UUID.randomUUID();
        Route put = mount("PUT", STREAMS + "/" + id, 200, streamBody(List.of(A), List.of(A), UPDATED_AT).toString());
        SsfStream stream = read(List.of(A), List.of(A), UPDATED_AT);

        client.ssf().updateStream(id, ReplacementBodies.ssfStream(stream,
                SsfStreamChanges.builder().expectedUpdatedAt(null).build()));

        assertFalse(put.last().json().has("expected_updated_at"), "the key is omitted, and null is never sent");
        assertFalse(put.last().body().contains("null"), put.last().body());

        SsfStreamInput other = ReplacementBodies.ssfStream(stream,
                SsfStreamChanges.builder().expectedUpdatedAt("2026-10-06T00:00:00Z").build());
        assertEquals("2026-10-06T00:00:00Z", other.expectedUpdatedAt(), "another value is sent as given");
    }

    @Test
    void everyOtherChangeMemberReplacesTheReadAndTheRestKeepsIt() throws Exception {
        SsfStream stream = read(List.of(A, B), List.of(A), UPDATED_AT);
        SsfStreamInput body = ReplacementBodies.ssfStream(stream, SsfStreamChanges.builder()
                .audience("https://other.example").authorizationHeader(Sensitive.of("Bearer new"))
                .clearAuthorizationHeader(false).deliveryMethod(SsfDeliveryMethod.POLL)
                .description("d").endpointUrl(null).receiverClientId("rp-2")
                .status(io.axiam.sdk.management.models.SsfStreamStatus.PAUSED).statusReason("why")
                .subjectFormat(io.axiam.sdk.management.models.SsfSubjectFormat.EMAIL).build());
        assertEquals("https://other.example", body.audience());
        assertEquals("Bearer new", body.authorizationHeader().expose());
        assertEquals(false, body.clearAuthorizationHeader());
        assertEquals(SsfDeliveryMethod.POLL, body.deliveryMethod());
        assertEquals("d", body.description());
        assertNull(body.endpointUrl(), "none");
        assertEquals("rp-2", body.receiverClientId());
        assertEquals(io.axiam.sdk.management.models.SsfStreamStatus.PAUSED, body.status());
        assertEquals("why", body.statusReason());
        assertEquals(io.axiam.sdk.management.models.SsfSubjectFormat.EMAIL, body.subjectFormat());
        assertEquals(List.of(A), body.eventsRequested(), "untouched when the ceiling is untouched");
        assertEquals(SsfStreamChanges.empty().getClass(), SsfStreamChanges.builder().build().getClass());
        assertThrows(NullPointerException.class, () -> SsfStreamChanges.builder().audience(null));
    }

    private static List<String> strings(JsonNode array) {
        List<String> out = new java.util.ArrayList<>();
        array.forEach(n -> out.add(n.asText()));
        return out;
    }

    // -- (h) and the documentation duties -------------------------------------------------------

    /** §32.8 test 7, last sentence: a documentation check, not a mock. */
    @Test
    void theUpdateStreamDocumentationStatesTheThreeMeanings() throws Exception {
        String source = Files.readString(Path.of("src/main/java/io/axiam/sdk/management/SsfApi.java"));
        int at = source.indexOf("public io.axiam.sdk.management.models.SsfStream updateStream(");
        String doc = source.substring(source.lastIndexOf("/**", at), at).replaceAll("\\s*\\n\\s*\\*\\s?", " ");
        assertTrue(doc.contains("absent resets"), doc);
        assertTrue(doc.contains("{@code []} is stored as the receiver's \"none\""), doc);
        assertTrue(doc.contains("a list is stored as given"), doc);
        assertTrue(doc.contains("refused {@code 400} if any entry is outside {@code events_allowed}"), doc);
        assertTrue(doc.contains("omitted optional member takes its default"), doc);
        assertTrue(doc.contains("except {@code authorization_header}"), doc);
        assertTrue(doc.contains("raw API client"), doc);
        assertTrue(doc.contains("ReplacementBodies.ssfStream(stream, changes)"), doc);
    }

    @Test
    void thePlainConverterDocumentationNamesTheCallersDuty() throws Exception {
        String source = Files.readString(Path.of("src/main/java/io/axiam/sdk/management/ReplacementBodies.java"));
        int at = source.indexOf("public static SsfStreamInput from(SsfStream stream)");
        String doc = source.substring(source.lastIndexOf("/**", at), at).replaceAll("\\s*\\n\\s*\\*\\s?", " ");
        assertTrue(doc.contains("The caller's duty"), doc);
        assertTrue(doc.contains("cut {@code events_requested} to the new ceiling yourself"), doc);
        assertTrue(doc.contains("three meanings of {@code events_requested}"), doc);
        assertTrue(doc.contains("{@code 409}"), doc);
    }

    // -- (f) and (i): user_id --------------------------------------------------------------------

    @Test
    void theRequestUserIdIsAnUntypedStringSoAMalformedValueReachesTheServerAnd400IsSurfaced() throws Exception {
        assertEquals(String.class, componentType(CreateCertificateRequest.class, "userId"));
        assertEquals(String.class, componentType(SignCertificateCsrRequest.class, "userId"));
        assertEquals(UUID.class, componentType(Certificate.class, "userId"), "the response member stays typed");

        Route generate = mount("POST", "/api/v1/certificates", 400,
                "{\"error\":\"validation_error\",\"message\":\"user_id is not a user of this tenant\"}");
        Route sign = mount("POST", "/api/v1/certificates/sign-csr", 400,
                "{\"error\":\"validation_error\",\"message\":\"user_id is not a user of this tenant\"}");

        ValidationError e = assertThrows(ValidationError.class, () -> client.management().certificates().generate(
                new CreateCertificateRequest(CertificateType.USER, EXAMPLE_ID, KeyAlgorithm.RSA4096, null,
                        "example", null, "not-a-uuid", 365)));
        assertTrue(e.getMessage().contains("user_id is not a user of this tenant"), e.getMessage());
        assertEquals("not-a-uuid", generate.last().json().path("user_id").asText(), "sent exactly as given");

        assertThrows(ValidationError.class, () -> client.management().certificates().signCsr(
                new SignCertificateCsrRequest(CertificateType.USER, "example", EXAMPLE_ID, null, null,
                        " 12345 ", 365)));
        assertEquals(" 12345 ", sign.last().json().path("user_id").asText(), "not trimmed, not judged");
    }

    @Test
    void anAssignedNullIsNoneForUserIdAndExpectedUpdatedAtNullIsNeverSent() throws Exception {
        Route generate = mount("POST", "/api/v1/certificates", 400, "{\"error\":\"validation_error\",\"message\":\"m\"}");
        Route sign = mount("POST", "/api/v1/certificates/sign-csr", 400, "{\"error\":\"validation_error\",\"message\":\"m\"}");
        assertThrows(ValidationError.class, () -> client.management().certificates().generate(
                new CreateCertificateRequest(CertificateType.USER, EXAMPLE_ID, KeyAlgorithm.RSA4096, null,
                        "example", null, null, 365)));
        assertThrows(ValidationError.class, () -> client.management().certificates().signCsr(
                new SignCertificateCsrRequest(CertificateType.USER, "example", EXAMPLE_ID, null, null, null, 365)));
        assertFalse(generate.last().json().has("user_id"));
        assertFalse(sign.last().json().has("user_id"));
        assertFalse(generate.last().body().contains("null") && generate.last().body().contains("user_id"));

        // expected_updated_at, on ssf.update_stream and scim_targets.update.
        SsfStreamInput ssf = new SsfStreamInput("a", null, null, SsfDeliveryMethod.POLL, null, null,
                List.of(A), null, null, "rp", null, null, null);
        assertFalse(JSON.valueToTree(ssf).has("expected_updated_at"));
        assertFalse(JSON.writeValueAsString(ssf).contains("null"), JSON.writeValueAsString(ssf));
        ScimTargetInput scim = JSON.readValue("{\"base_url\":\"https://x\",\"name\":\"n\","
                + "\"auth\":{\"type\":\"bearer\"},\"scope\":{\"type\":\"all_users\"},"
                + "\"deprovision\":\"disable\",\"enabled\":true,\"push_groups\":false,"
                + "\"user_name_from\":\"username\",\"expected_updated_at\":null}", ScimTargetInput.class);
        assertNull(scim.expectedUpdatedAt());
        assertFalse(JSON.valueToTree(scim).has("expected_updated_at"), "null is never sent");
    }

    private static Class<?> componentType(Class<? extends Record> type, String name) {
        for (java.lang.reflect.RecordComponent c : type.getRecordComponents()) {
            if (c.getName().equals(name)) {
                return c.getType();
            }
        }
        throw new AssertionError(type + " has no component " + name);
    }
}
