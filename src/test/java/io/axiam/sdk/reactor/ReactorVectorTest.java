package io.axiam.sdk.reactor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CONTRACT.md &sect;22.13 conformance, against the server-generated vectors in
 * {@code reactor_v2_reference_vectors.json}.
 *
 * <p>These are the tests the contract asks for by name, in its own order: sign
 * direction, verify direction, replay, and the topology strings. The
 * expectations are the fixture's — nothing here is hand-rolled, which is the
 * point of shipping vectors rather than a prose description of the
 * canonicalization.
 */
class ReactorVectorTest {

    private static final Instant VERIFIED_AT = Instant.parse("2026-07-10T12:00:00Z");

    // ---- sign direction (reactor → server) ---------------------------------

    @Test
    void everyCommittedReplyReproducesItsCanonicalBytesAndItsMac() throws Exception {
        JsonNode root = ReactorVectors.load();
        byte[] key = ReactorVectors.subkey(root);
        UUID tenant = ReactorVectors.tenantId(root);
        UUID correlation = ReactorVectors.correlationId(root);

        for (String name : new String[]{"allow", "deny", "mutate", "require_mfa"}) {
            JsonNode vector = root.get("reactor_to_server").get(name);
            JsonNode message = vector.get("message");
            String event = message.get("event").asText();
            UUID nonce = UUID.fromString(message.get("nonce").asText());
            Instant issuedAt = Instant.parse(message.get("issued_at").asText());
            ReactorDecision decision = decisionOf(message);

            byte[] canonical = ReactorProtocol.canonicalReplyBytes(
                    correlation, tenant, event, decision, nonce, issuedAt);
            assertArrayEquals(
                    vector.get("canonical_signed_json").asText().getBytes(StandardCharsets.UTF_8),
                    canonical,
                    name + ": the reply this SDK builds must reproduce canonical_signed_json "
                            + "byte-for-byte, `\"hmac_signature\": null` placeholder included");

            byte[] signed = ReactorProtocol.signedReply(
                    key, correlation, tenant, event, decision, nonce, issuedAt);
            JsonNode reparsed = ReactorVectors.MAPPER.readTree(signed);
            assertEquals(vector.get("hmac_signature_hex").asText(),
                    reparsed.get("hmac_signature").asText(),
                    name + ": recomputed MAC must equal the server's");
            assertTrue(ReactorProtocol.verifyEvent(key, signed),
                    name + ": a reply this SDK signed must verify under the same subkey");
        }
    }

    /**
     * &sect;22.2: the three conditionally-omitted fields are load-bearing. A reply
     * that serializes {@code "require_mfa": false} rather than omitting it
     * produces different canonical bytes and therefore a different MAC.
     */
    @Test
    void theOmissionRulesAreReproducedNotJustTheValues() throws Exception {
        JsonNode root = ReactorVectors.load();
        UUID tenant = ReactorVectors.tenantId(root);
        UUID correlation = ReactorVectors.correlationId(root);
        UUID nonce = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

        String allow = new String(ReactorProtocol.canonicalReplyBytes(correlation, tenant,
                ReactorEvents.LOGIN_POST_AUTH, ReactorDecision.allow(), nonce, VERIFIED_AT),
                StandardCharsets.UTF_8);
        assertFalse(allow.contains("require_mfa"),
                "require_mfa MUST NOT be serialized when false");
        assertFalse(allow.contains("reason"), "reason MUST be omitted when absent");
        assertFalse(allow.contains("patch"), "patch MUST be omitted when absent");
        assertTrue(allow.endsWith("\"hmac_signature\":null}"),
                "the signed bytes carry hmac_signature present and null, not omitted");

        String denyNoReason = new String(ReactorProtocol.canonicalReplyBytes(correlation, tenant,
                ReactorEvents.GRANT_PRE_ASSIGN, ReactorDecision.deny(null), nonce, VERIFIED_AT),
                StandardCharsets.UTF_8);
        assertFalse(denyNoReason.contains("reason"),
                "a deny with no reason omits the field rather than sending null");

        String stepUp = new String(ReactorProtocol.canonicalReplyBytes(correlation, tenant,
                ReactorEvents.LOGIN_POST_AUTH, ReactorDecision.allowRequiringStepUp(), nonce,
                VERIFIED_AT), StandardCharsets.UTF_8);
        assertTrue(stepUp.contains("\"require_mfa\":true"),
                "require_mfa IS serialized when true");
    }

    /**
     * &sect;22.2: two replies differing in nothing but the nonce carry different
     * MACs — the nonce is inside the signed bytes, which is the only uniqueness a
     * reply body has beyond its timestamp.
     */
    @Test
    void theNonceIsInsideTheSignedBytes() throws Exception {
        JsonNode root = ReactorVectors.load();
        JsonNode binding = root.get("nonce_binding");
        byte[] key = ReactorVectors.subkey(root);
        UUID tenant = ReactorVectors.tenantId(root);
        UUID correlation = ReactorVectors.correlationId(root);

        String macA = macOf(ReactorProtocol.signedReply(key, correlation, tenant,
                ReactorEvents.LOGIN_POST_AUTH, ReactorDecision.allow(),
                UUID.fromString(binding.get("nonce_a").asText()), VERIFIED_AT));
        String macB = macOf(ReactorProtocol.signedReply(key, correlation, tenant,
                ReactorEvents.LOGIN_POST_AUTH, ReactorDecision.allow(),
                UUID.fromString(binding.get("nonce_b").asText()), VERIFIED_AT));

        assertEquals(binding.get("hmac_a_hex").asText(), macA);
        assertEquals(binding.get("hmac_b_hex").asText(), macB);
        assertNotEquals(macA, macB, "a nonce swap must change the MAC");
    }

    // ---- verify direction (server → reactor) -------------------------------

    @Test
    void everyCommittedEventVerifiesUnderTheDerivedSubkeyAndNoOther() throws Exception {
        JsonNode root = ReactorVectors.load();
        byte[] key = ReactorVectors.subkey(root);
        byte[] wrongKey = new byte[key.length];

        for (String name : new String[]{"token_pre_issue", "login_post_auth"}) {
            byte[] body = ReactorVectors.wireBody(root.get("server_to_reactor").get(name));
            assertTrue(ReactorProtocol.verifyEvent(key, body),
                    name + ": must verify under the derived subkey");
            assertFalse(ReactorProtocol.verifyEvent(wrongKey, body),
                    name + ": must NOT verify under any other key");
        }
    }

    @Test
    void tamperingWithAnySignedFieldInvalidatesTheEvent() throws Exception {
        JsonNode root = ReactorVectors.load();
        byte[] key = ReactorVectors.subkey(root);
        JsonNode vector = root.get("server_to_reactor").get("token_pre_issue");

        ObjectNode payloadTampered = tamperable(vector);
        ((ObjectNode) payloadTampered.get("payload")).put("sub", "root");
        assertFalse(ReactorProtocol.verifyEvent(key, ReactorVectors.MAPPER.writeValueAsBytes(payloadTampered)),
                "rewriting the payload must invalidate the event");

        ObjectNode timeoutStretched = tamperable(vector);
        timeoutStretched.put("timeout_ms", 60_000);
        assertFalse(ReactorProtocol.verifyEvent(key, ReactorVectors.MAPPER.writeValueAsBytes(timeoutStretched)),
                "widening the window an actor thinks it has is tampering too");

        ObjectNode crossTenant = tamperable(vector);
        crossTenant.put("tenant_id", "33333333-3333-3333-3333-333333333333");
        assertFalse(ReactorProtocol.verifyEvent(key, ReactorVectors.MAPPER.writeValueAsBytes(crossTenant)),
                "re-aiming an event at another tenant must invalidate it");

        ObjectNode nonceSwapped = tamperable(vector);
        nonceSwapped.put("nonce", "dddddddd-dddd-dddd-dddd-dddddddddddd");
        assertFalse(ReactorProtocol.verifyEvent(key, ReactorVectors.MAPPER.writeValueAsBytes(nonceSwapped)),
                "the nonce is inside the signed bytes");
    }

    @Test
    void aStaleOrFutureTimestampIsOutsideTheWindowInBothDirections() {
        Instant now = VERIFIED_AT;
        assertTrue(ReactorProtocol.isFresh(now, now, ReactorProtocol.DEFAULT_FRESHNESS_SKEW));
        assertTrue(ReactorProtocol.isFresh(now.minusSeconds(300), now,
                ReactorProtocol.DEFAULT_FRESHNESS_SKEW), "exactly ±300 s is inside the window");
        assertFalse(ReactorProtocol.isFresh(now.minusSeconds(301), now,
                ReactorProtocol.DEFAULT_FRESHNESS_SKEW), "stale");
        assertFalse(ReactorProtocol.isFresh(now.plusSeconds(301), now,
                ReactorProtocol.DEFAULT_FRESHNESS_SKEW),
                "a future timestamp is not extra fresh — it is a captured message held for later");
    }

    /**
     * The fixture's {@code stale} and {@code stale_future} reply vectors, checked
     * against their own {@code verified_at}: both carry a perfectly valid
     * signature and are still outside the window.
     */
    @Test
    void theCommittedStaleVectorsAreRefusedOnFreshnessNotOnSignature() throws Exception {
        JsonNode root = ReactorVectors.load();
        byte[] key = ReactorVectors.subkey(root);
        Instant now = Instant.parse(root.get("verified_at").asText());

        for (String name : new String[]{"stale", "stale_future"}) {
            JsonNode vector = root.get("rejected_replies").get(name);
            byte[] body = ReactorVectors.wireBody(vector);
            assertTrue(ReactorProtocol.verifyEvent(key, body),
                    name + ": the signature itself is valid — the refusal is a freshness one");
            Instant issuedAt = Instant.parse(vector.get("message").get("issued_at").asText());
            assertFalse(ReactorProtocol.isFresh(issuedAt, now, ReactorProtocol.DEFAULT_FRESHNESS_SKEW),
                    name + ": must be refused as stale");
        }
    }

    /**
     * &sect;22.13 replay: the accepted reply verbatim — valid signature, inside
     * the window — is refused when presented against a different
     * {@code correlation_id}, and this SDK cannot re-aim it, because the
     * correlation lives inside the signed bytes.
     */
    @Test
    void aCapturedReplyCannotBeReAimedAtAnotherCorrelation() throws Exception {
        JsonNode root = ReactorVectors.load();
        JsonNode vector = root.get("rejected_replies").get("correlation_replay");
        byte[] key = ReactorVectors.subkey(root);
        UUID tenant = ReactorVectors.tenantId(root);

        UUID captured = UUID.fromString(vector.get("message").get("correlation_id").asText());
        UUID presentedAgainst = UUID.fromString(vector.get("verify_against_correlation_id").asText());
        assertNotEquals(captured, presentedAgainst,
                "the fixture presents the captured reply against a different dispatch");
        assertEquals("wrong_correlation", vector.get("expected_rejection").asText());

        assertTrue(ReactorProtocol.verifyEvent(key, ReactorVectors.wireBody(vector)),
                "the captured reply's signature is perfectly valid; the correlation is what refuses it");

        String reAimed = macOf(ReactorProtocol.signedReply(key, presentedAgainst, tenant,
                ReactorEvents.LOGIN_POST_AUTH, ReactorDecision.allow(),
                UUID.fromString(vector.get("message").get("nonce").asText()), VERIFIED_AT));
        assertNotEquals(vector.get("hmac_signature_hex").asText(), reAimed,
                "changing the correlation changes the MAC — a captured reply cannot be re-aimed");
    }

    // ---- topology (§22.1) --------------------------------------------------

    @Test
    void topologyStringsMatchTheServersOwn() throws Exception {
        JsonNode root = ReactorVectors.load();
        JsonNode topology = root.get("topology");
        UUID tenant = ReactorVectors.tenantId(root);
        UUID reactorId = UUID.fromString(root.get("reactor_id").asText());

        assertEquals(topology.get("exchange").asText(), ReactorProtocol.EXCHANGE);
        assertEquals("topic", topology.get("exchange_type").asText());
        assertEquals(topology.get("queue").asText(), ReactorProtocol.queueName(tenant, reactorId));
        assertEquals(topology.get("routing_key_token_pre_issue").asText(),
                ReactorProtocol.routingKey(tenant, ReactorEvents.TOKEN_PRE_ISSUE));
        assertEquals(topology.get("routing_key_login_post_auth").asText(),
                ReactorProtocol.routingKey(tenant, ReactorEvents.LOGIN_POST_AUTH));
    }

    @Test
    void theFixturesFieldOrderIsTheOrderThisSdkWrites() throws Exception {
        JsonNode root = ReactorVectors.load();
        assertEquals(
                java.util.List.of("tenant_id", "event", "correlation_id", "payload", "timeout_ms",
                        "key_version", "nonce", "issued_at", "hmac_signature"),
                names(root.get("field_order").get("reactor_event")));
        assertEquals(
                java.util.List.of("correlation_id", "tenant_id", "event", "decision", "reason",
                        "patch", "require_mfa", "key_version", "nonce", "issued_at", "hmac_signature"),
                names(root.get("field_order").get("reactor_reply")));

        // The mutate vector exercises the longest reply: decision + patch, with
        // reason and require_mfa omitted. Its key order is the contract's, minus
        // the omissions.
        ObjectNode mutate = ReactorVectors.canonicalNode(root.get("reactor_to_server").get("mutate"));
        assertEquals(java.util.List.of("correlation_id", "tenant_id", "event", "decision", "patch",
                        "key_version", "nonce", "issued_at", "hmac_signature"),
                names(mutate));
    }

    // ---- helpers -----------------------------------------------------------

    /**
     * The fixture annotates its last {@code field_order} entry in prose
     * ("hmac_signature (SERIALIZED AS null while signing, not omitted)"), so the
     * field name is the token before the parenthesis.
     */
    private static java.util.List<String> names(JsonNode node) {
        java.util.List<String> out = new java.util.ArrayList<>();
        if (node.isArray()) {
            node.forEach(n -> out.add(n.asText().split(" ", 2)[0]));
        } else {
            node.fieldNames().forEachRemaining(out::add);
        }
        return out;
    }

    private static ObjectNode tamperable(JsonNode vector) throws Exception {
        ObjectNode node = ReactorVectors.canonicalNode(vector);
        node.put("hmac_signature", vector.get("hmac_signature_hex").asText());
        return node;
    }

    private static String macOf(byte[] signedBody) throws Exception {
        return ReactorVectors.MAPPER.readTree(signedBody).get("hmac_signature").asText();
    }

    private static ReactorDecision decisionOf(JsonNode message) {
        String decision = message.get("decision").asText();
        return switch (decision) {
            case "allow" -> message.path("require_mfa").asBoolean(false)
                    ? ReactorDecision.allowRequiringStepUp()
                    : ReactorDecision.allow();
            case "deny" -> ReactorDecision.deny(
                    message.has("reason") ? message.get("reason").asText() : null);
            case "mutate" -> {
                Map<String, String> patch = new LinkedHashMap<>();
                message.get("patch").fields().forEachRemaining(
                        e -> patch.put(e.getKey(), e.getValue().asText()));
                yield ReactorDecision.mutate(patch);
            }
            default -> throw new IllegalStateException("unknown decision " + decision);
        };
    }
}
