package io.axiam.sdk.management;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.axiam.sdk.Sensitive;
import io.axiam.sdk.errors.AuthError;
import io.axiam.sdk.errors.ConflictError;
import io.axiam.sdk.errors.NetworkError;
import io.axiam.sdk.errors.NotFoundError;
import io.axiam.sdk.errors.ValidationError;
import io.axiam.sdk.management.models.SsfDeliveryMethod;
import io.axiam.sdk.management.models.SsfStatusActor;
import io.axiam.sdk.management.models.SsfStream;
import io.axiam.sdk.management.models.SsfStreamInput;
import io.axiam.sdk.management.models.SsfStreamStatus;
import io.axiam.sdk.management.models.SsfSubjectFormat;
import io.axiam.sdk.ssf.SsfEventTypes;
import io.axiam.sdk.testutil.Redaction;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@code ssf} management namespace &mdash; CONTRACT.md &sect;32.8's six
 * management tests. (The receiver helper's eight are in
 * {@code io.axiam.sdk.ssf.SsfReceiverTest}.)
 */
class SsfManagementTest extends ManagementTestBase {

    private static final String STREAMS = "/api/v1/tenants/" + TENANT_ID + "/ssf/streams";
    private static final String REVOKED = SsfEventTypes.SESSION_REVOKED;

    private static String headerValue() {
        return "Bearer " + UUID.randomUUID().toString().replace("-", "");
    }

    private static ObjectNode streamBody() {
        ObjectNode b = JSON.createObjectNode();
        b.put("id", UUID.randomUUID().toString());
        b.put("tenant_id", TENANT_ID.toString());
        b.put("receiver_client_id", "rp-1");
        b.put("audience", "https://rp.example");
        b.putNull("description");
        b.put("delivery_method", "push");
        b.put("endpoint_url", "https://rp.example/ssf");
        b.put("authorization_header_set", true);
        b.putArray("events_allowed").add(REVOKED);
        b.putArray("events_requested").add(REVOKED);
        b.putArray("events_delivered").add(REVOKED);
        b.put("subject_format", "iss_sub");
        b.put("status", "enabled");
        b.putNull("status_reason");
        b.put("status_actor", "admin");
        b.putNull("last_verification_at");
        b.put("created_at", "2026-10-04T00:00:00Z");
        b.put("updated_at", "2026-10-04T00:00:00Z");
        b.put("transmitter_active", true);
        return b;
    }

    private static SsfStreamInput input(String header) {
        return new SsfStreamInput("https://rp.example", header == null ? null : Sensitive.of(header), null,
                SsfDeliveryMethod.PUSH, "the RP", "https://rp.example/ssf", List.of(REVOKED),
                null, "rp-1", null, null, null);
    }

    // ── 1. Replacement ───────────────────────────────────────────────────

    @Test
    void updateStreamPutsEveryMemberItModels() throws Exception {
        UUID id = UUID.randomUUID();
        Route put = mount("PUT", STREAMS + "/" + id, 200, streamBody().toString());
        SsfStreamInput body = new SsfStreamInput("https://rp.example", null, false, SsfDeliveryMethod.PUSH,
                "the RP", "https://rp.example/ssf", List.of(REVOKED),
                List.of(REVOKED), "rp-1", SsfStreamStatus.ENABLED, "ok",
                SsfSubjectFormat.ISS_SUB);
        SsfStream stream = client.ssf().updateStream(id, body);
        assertTrue(stream.transmitterActive());
        JsonNode sent = put.last().json();
        for (String member : List.of("receiver_client_id", "audience", "delivery_method", "events_allowed",
                "description", "endpoint_url", "events_requested", "subject_format", "status", "status_reason",
                "clear_authorization_header")) {
            assertTrue(sent.has(member), "a modelled member was not sent");
        }
        assertEquals(REVOKED, sent.path("events_allowed").get(0).asText());
        assertFalse(sent.has("authorization_header"), "absent keeps the stored header");
        // The four required members cannot be null: the constructor refuses them.
        assertEquals(12, SsfStreamInput.class.getRecordComponents().length);
        assertCannotBeBuiltWithout(input(null), "receiver_client_id", "audience", "delivery_method",
                "events_allowed");
    }

    // ── 2. The header is Sensitive ───────────────────────────────────────

    @Test
    void thePushHeaderIsSentAndNeverRenderedOrDecoded() throws Exception {
        String h = headerValue();
        SsfStreamInput body = input(h);
        Redaction.assertNoFragment("input rendering", body + " " + JSON.writeValueAsString(body), h);
        ObjectNode answer = streamBody();
        answer.put("authorization_header", h);
        Route post = mount("POST", STREAMS, 201, answer.toString());
        SsfStream created = client.ssf().createStream(body);
        assertTrue(h.equals(post.last().json().path("authorization_header").asText()), "the header is sent");
        Redaction.assertNoFragment("decoded stream", created + " " + JSON.writeValueAsString(created), h);
        assertFalse(Arrays.stream(SsfStream.class.getRecordComponents())
                .anyMatch(c -> c.getName().equals("authorizationHeader")), "no accessor for the header");
        assertTrue(created.authorizationHeaderSet());
    }

    // ── 3. Open decoding ─────────────────────────────────────────────────

    @Test
    void unknownValuesAndBothTransmitterStatesDecode() throws Exception {
        ObjectNode odd = streamBody();
        odd.put("status", "quarantined");
        odd.put("delivery_method", "websocket");
        odd.put("subject_format", "opaque");
        odd.put("status_actor", "policy");
        odd.putArray("events_allowed").add("https://example.test/event-type/new");
        SsfStream s = JSON.treeToValue(odd, SsfStream.class);
        assertEquals(SsfStreamStatus.UNKNOWN, s.status());
        assertEquals(SsfDeliveryMethod.UNKNOWN, s.deliveryMethod());
        assertEquals(SsfSubjectFormat.UNKNOWN, s.subjectFormat());
        assertEquals(SsfStatusActor.UNKNOWN, s.statusActor());
        // §32.2: event types are strings, so an unseen URI keeps its value (R-22).
        assertEquals("https://example.test/event-type/new", s.eventsAllowed().get(0));
        // §34.2 P12.2: an unknown status carried back into a write is refused locally.
        UUID id = UUID.randomUUID();
        Route put = mount("PUT", STREAMS + "/" + id, 200, streamBody().toString());
        ValidationError refused = assertThrows(ValidationError.class,
                () -> client.ssf().updateStream(id, ReplacementBodies.from(s)));
        assertTrue(refused.getMessage().contains("delivery_method"), refused.getMessage());
        assertEquals(0, put.calls(), "refused before sending");

        ObjectNode inactive = streamBody();
        inactive.put("transmitter_active", false);
        inactive.put("transmitter_inactive_reason", "per-tenant issuers are off in a multi-tenant deployment");
        SsfStream gated = JSON.treeToValue(inactive, SsfStream.class);
        assertFalse(gated.transmitterActive());
        assertNotNull(gated.transmitterInactiveReason());
        assertNull(JSON.treeToValue(streamBody(), SsfStream.class).transmitterInactiveReason());
    }

    // ── 4. Pagination ────────────────────────────────────────────────────

    @Test
    void listStreamsPagesAndTheWalkCarriesSearch() {
        Route list = mountTwoPages(STREAMS, () -> streamBody().toString());
        Page<SsfStream> page = client.ssf().listStreams(PageRequest.matching(1, "rp.example"));
        assertEquals(2, page.total());
        assertEquals(2, client.ssf().listStreamsAll(PageRequest.matching(1, "rp.example")).size());
        for (Recorded r : list.requests()) {
            assertEquals("rp.example", r.query().get("search"), "the pager carries search on every page");
        }
    }

    // ── 5. No retry ──────────────────────────────────────────────────────

    @Test
    void noneOfTheThreeWritesIsRetriedOn503() {
        UUID id = UUID.randomUUID();
        List<Route> routes = List.of(
                mount("POST", STREAMS, 503, ""),
                mount("PUT", STREAMS + "/" + id, 503, ""),
                mount("DELETE", STREAMS + "/" + id, 503, ""));
        SsfApi s = client.ssf();
        for (Executable write : List.<Executable>of(
                () -> s.createStream(input(headerValue())),
                () -> s.updateStream(id, input(null)),
                () -> s.deleteStream(id))) {
            NetworkError e = assertThrows(NetworkError.class, write);
            assertFalse(e instanceof ValidationError);
        }
        for (Route r : routes) {
            assertEquals(1, r.calls(), "exactly one request per write");
        }
    }

    @Test
    void noneOfTheThreeWritesIsResentAfterADroppedConnection() throws Exception {
        UUID id = UUID.randomUUID();
        SsfApi s = client.ssf();
        assertSentOnceOverADroppedConnection("POST", STREAMS, () -> s.createStream(input(headerValue())));
        assertSentOnceOverADroppedConnection("PUT", STREAMS + "/" + id, () -> s.updateStream(id, input(null)));
        assertSentOnceOverADroppedConnection("DELETE", STREAMS + "/" + id, () -> s.deleteStream(id));
    }

    // ── 6. Errors ────────────────────────────────────────────────────────

    @Test
    void statusesMapPerSection2() {
        UUID id = UUID.randomUUID();
        mount("PUT", STREAMS + "/" + id, 400,
                "{\"error\":\"validation_error\",\"message\":\"endpoint_url: must be https\"}");
        mount("POST", STREAMS, 409, "{\"error\":\"conflict\",\"message\":\"audience\"}");
        mount("GET", STREAMS + "/" + id, 404, "{\"error\":\"not_found\",\"message\":\"no\"}");
        mount("DELETE", STREAMS + "/" + id, 401, "{\"error\":\"unauthorized\",\"message\":\"human only\"}");
        mount("POST", "/api/v1/auth/refresh", 401, "{\"error\":\"unauthorized\"}");
        SsfApi s = client.ssf();
        ValidationError v = assertThrows(ValidationError.class, () -> s.updateStream(id, input(null)));
        assertTrue(v.getMessage().contains("https"));
        assertThrows(ConflictError.class, () -> s.createStream(input(null)));
        assertThrows(NotFoundError.class, () -> s.getStream(id));
        assertInstanceOf(AuthError.class, assertThrows(RuntimeException.class, () -> s.deleteStream(id)));
    }

    @Test
    void aReadConvertsIntoTheReplacementBodyWithoutTheHeader() throws Exception {
        SsfStream s = JSON.treeToValue(streamBody(), SsfStream.class);
        SsfStreamInput body = ReplacementBodies.from(s);
        assertNull(body.authorizationHeader());
        assertNull(body.clearAuthorizationHeader());
        assertEquals(s.eventsRequested(), body.eventsRequested());
        assertEquals(s.endpointUrl(), body.endpointUrl());
    }
}
